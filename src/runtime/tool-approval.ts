import type {
	ExtensionAPI,
	ExtensionContext,
	SessionMessageEntry,
	ToolCallEvent,
	ToolCallEventResult,
} from '@earendil-works/pi-coding-agent';
import { checkPermissionRule } from '../analysis/permission-rules';
import {
	analyzeShellCommand,
	isShellCommandScopedToCwd,
} from '../analysis/shell-guard';
import { isPathInsideRoot } from '../path-scope';
import type { BlockedCommand, Config } from '../types';

type ToolCallResult = ToolCallEventResult | undefined;

interface ApprovalRuntime {
	config: Config;
	approvedCalls: Set<string>;
	blockedCommands: BlockedCommand[];
	api: ExtensionAPI;
	sessionState: {
		deniedBatchId?: string;
		approvedBatchId?: string;
	};
}

const MAX_BLOCKED_COMMANDS = 1000;
const APPROVAL_TIMEOUT_MS = 120000;

function rememberApproved(runtime: ApprovalRuntime, toolCallId: string): void {
	runtime.approvedCalls.add(toolCallId);
}

function rememberBlocked(
	runtime: ApprovalRuntime,
	tool: string,
	reason: string,
): void {
	runtime.blockedCommands.push({
		tool,
		reason,
		timestamp: Date.now(),
	});
	if (runtime.blockedCommands.length > MAX_BLOCKED_COMMANDS) {
		runtime.blockedCommands.shift();
	}
}

function sendDenySteer(runtime: ApprovalRuntime, command: string): void {
	runtime.api.sendMessage(
		{
			customType: 'blocked-command',
			content: `⛔ Shell command blocked: ${command}\n\nNote: this command was blocked by deny rules.\n\nWhy did you choose this command? Is it really the best approach?\n\nIf yes — explain to the user how to run it manually in their shell.\nOtherwise — suggest an alternative.`,
			display: false,
		},
		{
			deliverAs: 'steer',
			triggerTurn: false,
		},
	);
}

async function confirm(
	ctx: ExtensionContext,
	title: string,
	summary: string,
): Promise<boolean> {
	return ctx.ui.confirm(title, summary, {
		timeout: APPROVAL_TIMEOUT_MS,
		signal: ctx.signal,
	});
}

async function askApproval(
	ctx: ExtensionContext,
	title: string,
	summary: string,
	isBatch: boolean,
): Promise<'allow' | 'deny' | 'allow-all' | 'deny-all'> {
	if (!isBatch) {
		const approved = await confirm(ctx, title, summary);
		return approved ? 'allow' : 'deny';
	}

	const choices = ['Allow', 'Deny', 'Allow All', 'Deny All'];
	const choice = await ctx.ui.select(title, choices, {
		timeout: APPROVAL_TIMEOUT_MS,
		signal: ctx.signal,
	});

	if (choice === 'Allow') return 'allow';
	if (choice === 'Allow All') return 'allow-all';
	if (choice === 'Deny All') return 'deny-all';
	return 'deny'; // fallback for Deny, cancelled, or closed dialog
}

interface ToolCallBlock {
	type: 'toolCall';
	id: string;
	name: string;
	arguments?: Record<string, unknown>;
}

interface BatchContext {
	assistantEntry?: SessionMessageEntry;
	allToolCalls: ToolCallBlock[];
	currentIndex: number;
	total: number;
	formattedRemaining: string;
}

function getBatchContext(
	event: ToolCallEvent,
	ctx: ExtensionContext,
): BatchContext {
	const branch = ctx.sessionManager.getBranch();
	const assistantEntry = branch
		.slice()
		.reverse()
		.find(
			(entry): entry is SessionMessageEntry =>
				entry.type === 'message' && entry.message.role === 'assistant',
		);

	if (!assistantEntry) {
		return {
			allToolCalls: [],
			currentIndex: -1,
			total: 0,
			formattedRemaining: '',
		};
	}

	const msg = assistantEntry.message;
	if (msg.role !== 'assistant') {
		return {
			allToolCalls: [],
			currentIndex: -1,
			total: 0,
			formattedRemaining: '',
		};
	}

	const allToolCalls =
		(msg.content as ToolCallBlock[]).filter((c) => c.type === 'toolCall') ?? [];
	const currentIndex = allToolCalls.findIndex(
		(tc) => tc.id === event.toolCallId,
	);

	let formattedRemaining = '';
	if (allToolCalls.length > 1 && currentIndex !== -1) {
		const remaining = allToolCalls.slice(currentIndex + 1);
		if (remaining.length > 0) {
			formattedRemaining =
				'\n\nRemaining in batch:\n' +
				remaining
					.map((tc) => {
						const toolName = tc.name;
						const input = (tc.arguments ?? {}) as Record<string, unknown>;
						let detail = '';
						if (toolName === 'bash') {
							detail = `shell: ${input.command ?? ''}`;
						} else if (isPathToolName(toolName)) {
							detail = `${toolName} ${input.path ?? 'unknown'}`;
						} else {
							detail = `${toolName}: ${JSON.stringify(input)}`;
						}
						return `  - ${detail}`;
					})
					.join('\n');
		}
	}

	return {
		assistantEntry,
		allToolCalls,
		currentIndex,
		total: allToolCalls.length,
		formattedRemaining,
	};
}

function isPathToolName(toolName: string): boolean {
	return (
		toolName === 'read' ||
		toolName === 'write' ||
		toolName === 'edit' ||
		toolName === 'grep' ||
		toolName === 'find' ||
		toolName === 'ls'
	);
}

function isMutatingPathToolName(toolName: string): boolean {
	return toolName === 'write' || toolName === 'edit';
}

function pathToolPath(input: Record<string, unknown>): string | undefined {
	return typeof input.path === 'string' ? input.path : undefined;
}

function isPathToolInsideCwd(
	input: Record<string, unknown>,
	ctx: ExtensionContext,
): boolean {
	return isPathInsideRoot(ctx.cwd, pathToolPath(input), ctx.cwd);
}

async function handleShellToolCall(
	event: ToolCallEvent,
	ctx: ExtensionContext,
	runtime: ApprovalRuntime,
): Promise<ToolCallResult> {
	const input = event.input as Record<string, unknown>;
	const command = (input.command as string) ?? '';
	const batch = getBatchContext(event, ctx);

	const analysis = analyzeShellCommand(command, runtime.config);

	if (analysis === 'dangerous') {
		rememberApproved(runtime, event.toolCallId);
		rememberBlocked(runtime, 'bash', `shell: ${command}`);
		sendDenySteer(runtime, command);
		if (batch.assistantEntry) {
			runtime.sessionState.deniedBatchId = batch.assistantEntry.id;
		}
		return { block: true, reason: 'Command blocked by deny rules' };
	}

	if (
		batch.assistantEntry &&
		runtime.sessionState.deniedBatchId === batch.assistantEntry.id
	) {
		rememberApproved(runtime, event.toolCallId);
		rememberBlocked(runtime, 'bash', `shell: ${command} (batch denied)`);
		return { block: true, reason: 'User denied all tool calls in this batch' };
	}

	if (
		batch.assistantEntry &&
		runtime.sessionState.approvedBatchId === batch.assistantEntry.id
	) {
		rememberApproved(runtime, event.toolCallId);
		return undefined;
	}

	if (
		runtime.config.mode === 'full-access' ||
		runtime.approvedCalls.has(event.toolCallId)
	) {
		return undefined;
	}

	if (runtime.config.mode === 'read-safe' && analysis === 'safe') {
		rememberApproved(runtime, event.toolCallId);
		return undefined;
	}

	if (
		runtime.config.mode === 'folder-trusted' &&
		analysis === 'safe' &&
		isShellCommandScopedToCwd(command, ctx.cwd)
	) {
		rememberApproved(runtime, event.toolCallId);
		return undefined;
	}

	if (runtime.config.mode === 'self-guarded' && analysis === 'safe') {
		rememberApproved(runtime, event.toolCallId);
		return undefined;
	}

	const titleSuffix =
		batch.total > 1 && batch.currentIndex !== -1
			? ` [${batch.currentIndex + 1}/${batch.total}]`
			: '';
	const title = `Approve shell command${titleSuffix}`;
	const summary = `shell: ${command}${batch.formattedRemaining}`;

	const choice = await askApproval(ctx, title, summary, batch.total > 1);

	if (choice === 'allow' || choice === 'allow-all') {
		rememberApproved(runtime, event.toolCallId);
		if (choice === 'allow-all' && batch.assistantEntry) {
			runtime.sessionState.approvedBatchId = batch.assistantEntry.id;
		}
		return undefined;
	}

	// For 'deny' or 'deny-all'
	rememberApproved(runtime, event.toolCallId);
	rememberBlocked(runtime, 'bash', `shell: ${command}`);
	if (choice === 'deny-all' && batch.assistantEntry) {
		runtime.sessionState.deniedBatchId = batch.assistantEntry.id;
	}
	return { block: true, reason: 'User denied approval' };
}

async function handlePathToolCall(
	event: ToolCallEvent,
	ctx: ExtensionContext,
	runtime: ApprovalRuntime,
): Promise<ToolCallResult> {
	const input = event.input as Record<string, unknown>;
	const filePath = pathToolPath(input) ?? '.';
	const batch = getBatchContext(event, ctx);

	const denyResult = checkPermissionRule(
		runtime.config.permissions.deny,
		{ toolName: event.toolName },
		input,
		{ deny: true },
	);
	if (denyResult === 'blocked') {
		rememberApproved(runtime, event.toolCallId);
		if (batch.assistantEntry) {
			runtime.sessionState.deniedBatchId = batch.assistantEntry.id;
		}
		return { block: true, reason: `Blocked by deny rule: ${filePath}` };
	}

	if (
		batch.assistantEntry &&
		runtime.sessionState.deniedBatchId === batch.assistantEntry.id
	) {
		rememberApproved(runtime, event.toolCallId);
		rememberBlocked(
			runtime,
			event.toolName,
			`${event.toolName} ${filePath} (batch denied)`,
		);
		return { block: true, reason: 'User denied all tool calls in this batch' };
	}

	if (
		batch.assistantEntry &&
		runtime.sessionState.approvedBatchId === batch.assistantEntry.id
	) {
		rememberApproved(runtime, event.toolCallId);
		return undefined;
	}

	const askResult = checkPermissionRule(
		runtime.config.permissions.ask,
		{ toolName: event.toolName },
		input,
	);
	const mustAsk = askResult === 'allowed';
	const isMutatingPathTool = isMutatingPathToolName(event.toolName);

	if (
		!mustAsk &&
		!isMutatingPathTool &&
		runtime.config.mode !== 'folder-trusted' &&
		runtime.config.mode !== 'self-guarded'
	) {
		return undefined;
	}

	if (
		(!mustAsk && runtime.config.mode === 'full-access') ||
		runtime.approvedCalls.has(event.toolCallId)
	) {
		return undefined;
	}

	if (!mustAsk && runtime.config.mode !== 'ask-first') {
		const permResult = checkPermissionRule(
			runtime.config.permissions.allow,
			{ toolName: event.toolName },
			input,
		);
		if (permResult === 'allowed') {
			rememberApproved(runtime, event.toolCallId);
			return undefined;
		}
	}

	if (
		!mustAsk &&
		(runtime.config.mode === 'folder-trusted' ||
			runtime.config.mode === 'self-guarded') &&
		isPathToolInsideCwd(input, ctx)
	) {
		rememberApproved(runtime, event.toolCallId);
		return undefined;
	}

	const fileOpSummary = `${event.toolName} ${filePath}`;

	const titleSuffix =
		batch.total > 1 && batch.currentIndex !== -1
			? ` [${batch.currentIndex + 1}/${batch.total}]`
			: '';
	const title = `Approve file operation${titleSuffix}`;
	const summary = `${fileOpSummary}${batch.formattedRemaining}`;

	const choice = await askApproval(ctx, title, summary, batch.total > 1);

	if (choice === 'allow' || choice === 'allow-all') {
		rememberApproved(runtime, event.toolCallId);
		if (choice === 'allow-all' && batch.assistantEntry) {
			runtime.sessionState.approvedBatchId = batch.assistantEntry.id;
		}
		return undefined;
	}

	// For 'deny' or 'deny-all'
	rememberApproved(runtime, event.toolCallId);
	rememberBlocked(runtime, event.toolName, fileOpSummary);
	if (choice === 'deny-all' && batch.assistantEntry) {
		runtime.sessionState.deniedBatchId = batch.assistantEntry.id;
	}
	return { block: true, reason: 'User denied approval' };
}

async function handleGenericToolCall(
	event: ToolCallEvent,
	ctx: ExtensionContext,
	runtime: ApprovalRuntime,
): Promise<ToolCallResult> {
	if (runtime.config.mode !== 'self-guarded') return undefined;
	if (runtime.approvedCalls.has(event.toolCallId)) return undefined;

	const batch = getBatchContext(event, ctx);
	const input = event.input as Record<string, unknown>;
	const denyResult = checkPermissionRule(
		runtime.config.permissions.deny,
		{ toolName: event.toolName },
		input,
		{ deny: true },
	);
	if (denyResult === 'blocked') {
		rememberApproved(runtime, event.toolCallId);
		if (batch.assistantEntry) {
			runtime.sessionState.deniedBatchId = batch.assistantEntry.id;
		}
		return { block: true, reason: `Blocked by deny rule: ${event.toolName}` };
	}

	if (
		batch.assistantEntry &&
		runtime.sessionState.deniedBatchId === batch.assistantEntry.id
	) {
		rememberApproved(runtime, event.toolCallId);
		rememberBlocked(
			runtime,
			event.toolName,
			`${event.toolName} (batch denied)`,
		);
		return { block: true, reason: 'User denied all tool calls in this batch' };
	}

	if (
		batch.assistantEntry &&
		runtime.sessionState.approvedBatchId === batch.assistantEntry.id
	) {
		rememberApproved(runtime, event.toolCallId);
		return undefined;
	}

	const allowResult = checkPermissionRule(
		runtime.config.permissions.allow,
		{ toolName: event.toolName },
		input,
	);
	if (allowResult === 'allowed') {
		rememberApproved(runtime, event.toolCallId);
		return undefined;
	}

	const titleSuffix =
		batch.total > 1 && batch.currentIndex !== -1
			? ` [${batch.currentIndex + 1}/${batch.total}]`
			: '';
	const title = `Approve tool call${titleSuffix}`;
	const summary = `${event.toolName}: ${JSON.stringify(input)}${batch.formattedRemaining}`;
	const choice = await askApproval(ctx, title, summary, batch.total > 1);

	if (choice === 'allow' || choice === 'allow-all') {
		rememberApproved(runtime, event.toolCallId);
		if (choice === 'allow-all' && batch.assistantEntry) {
			runtime.sessionState.approvedBatchId = batch.assistantEntry.id;
		}
		return undefined;
	}

	rememberApproved(runtime, event.toolCallId);
	rememberBlocked(runtime, event.toolName, summary);
	if (choice === 'deny-all' && batch.assistantEntry) {
		runtime.sessionState.deniedBatchId = batch.assistantEntry.id;
	}
	return { block: true, reason: 'User denied approval' };
}

export async function handleToolCall(
	event: ToolCallEvent,
	ctx: ExtensionContext,
	runtime: ApprovalRuntime,
): Promise<ToolCallResult> {
	if (event.toolName === 'bash') {
		return handleShellToolCall(event, ctx, runtime);
	}

	if (isPathToolName(event.toolName)) {
		return handlePathToolCall(event, ctx, runtime);
	}

	return handleGenericToolCall(event, ctx, runtime);
}
