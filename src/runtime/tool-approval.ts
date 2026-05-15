import type {
	ExtensionAPI,
	ExtensionContext,
	ToolCallEvent,
	ToolCallEventResult,
} from '@earendil-works/pi-coding-agent';
import { analyzeBashCommand } from '../analysis/bash';
import { checkPermissionRule } from '../analysis/permission-rules';
import type { BlockedCommand, Config } from '../types';

type ToolCallResult = ToolCallEventResult | undefined;

interface ApprovalRuntime {
	config: Config;
	approvedCalls: Set<string>;
	blockedCommands: BlockedCommand[];
	api: ExtensionAPI;
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
			content: `⛔ Bash command blocked: ${command}\n\nNote: this command was blocked by deny rules.\n\nWhy did you choose this command? Is it really the best approach?\n\nIf yes — explain to the user how to run it manually in their shell.\nOtherwise — suggest an alternative.`,
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

async function handleBashToolCall(
	event: ToolCallEvent,
	ctx: ExtensionContext,
	runtime: ApprovalRuntime,
): Promise<ToolCallResult> {
	const input = event.input as Record<string, unknown>;
	const command = (input.command as string) ?? '';
	const analysis = analyzeBashCommand(command, runtime.config);

	if (analysis === 'dangerous') {
		rememberApproved(runtime, event.toolCallId);
		rememberBlocked(runtime, 'bash', `bash: ${command}`);
		sendDenySteer(runtime, command);
		return { block: true, reason: 'Command blocked by deny rules' };
	}

	if (
		runtime.config.mode === 'yolo' ||
		runtime.approvedCalls.has(event.toolCallId)
	) {
		return undefined;
	}

	if (runtime.config.mode === 'read-only' && analysis === 'safe') {
		rememberApproved(runtime, event.toolCallId);
		return undefined;
	}

	const summary = `bash: ${command}`;
	const approved = await confirm(ctx, 'Approve bash command', summary);
	if (!approved) {
		rememberApproved(runtime, event.toolCallId);
		rememberBlocked(runtime, 'bash', summary);
		return { block: true, reason: 'User denied approval' };
	}
	rememberApproved(runtime, event.toolCallId);
	return undefined;
}

async function handleFileToolCall(
	event: ToolCallEvent,
	ctx: ExtensionContext,
	runtime: ApprovalRuntime,
): Promise<ToolCallResult> {
	const input = event.input as Record<string, unknown>;
	const filePath = (input.path as string) ?? 'unknown';

	const denyResult = checkPermissionRule(
		runtime.config.permissions.deny,
		{ toolName: event.toolName },
		input,
		{ deny: true },
	);
	if (denyResult === 'blocked') {
		rememberApproved(runtime, event.toolCallId);
		return { block: true, reason: `Blocked by deny rule: ${filePath}` };
	}

	if (
		runtime.config.mode === 'yolo' ||
		runtime.approvedCalls.has(event.toolCallId)
	) {
		return undefined;
	}

	if (runtime.config.mode !== 'strict') {
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

	const summary =
		event.toolName === 'write' ? `write ${filePath}` : `edit ${filePath}`;
	const approved = await confirm(ctx, 'Approve file operation', summary);
	if (!approved) {
		rememberApproved(runtime, event.toolCallId);
		rememberBlocked(runtime, event.toolName, summary);
		return { block: true, reason: 'User denied approval' };
	}
	rememberApproved(runtime, event.toolCallId);
	return undefined;
}

export async function handleToolCall(
	event: ToolCallEvent,
	ctx: ExtensionContext,
	runtime: ApprovalRuntime,
): Promise<ToolCallResult> {
	if (event.toolName === 'bash') {
		return handleBashToolCall(event, ctx, runtime);
	}

	if (event.toolName === 'write' || event.toolName === 'edit') {
		return handleFileToolCall(event, ctx, runtime);
	}

	return undefined;
}
