import type {
	ExtensionAPI,
	ExtensionContext,
	ToolCallEvent,
} from '@earendil-works/pi-coding-agent';
import { describe, expect, it, vi } from 'vitest';
import { DEFAULT_CONFIG } from '../config/schema';
import type { BlockedCommand, Config } from '../types';
import { handleToolCall } from './tool-approval';

function createRuntime(config: Config = DEFAULT_CONFIG) {
	return {
		api: {
			sendMessage: vi.fn(),
		} as unknown as ExtensionAPI,
		config,
		approvedCalls: new Set<string>(),
		blockedCommands: [] as BlockedCommand[],
		sessionState: {
			deniedBatchId: undefined,
			approvedBatchId: undefined,
		},
	};
}

function createContext(approved = true) {
	return {
		ui: {
			confirm: vi.fn().mockResolvedValue(approved),
			select: vi.fn(),
		},
		cwd: '/repo/app',
		sessionManager: {
			getBranch: vi.fn().mockReturnValue([]),
		},
		signal: undefined,
	} as unknown as ExtensionContext;
}

function createContextWithSession(
	approved = true,
	branch: unknown[] = [],
	selectedChoice: string | undefined = undefined,
) {
	return {
		ui: {
			confirm: vi.fn().mockResolvedValue(approved),
			select: vi.fn().mockResolvedValue(selectedChoice),
		},
		cwd: '/repo/app',
		sessionManager: {
			getBranch: vi.fn().mockReturnValue(branch),
		},
		signal: undefined,
	} as unknown as ExtensionContext;
}

function bashEvent(command: string): ToolCallEvent {
	return {
		type: 'tool_call',
		toolCallId: 'call-1',
		toolName: 'bash',
		input: { command },
	} as ToolCallEvent;
}

function readEvent(path: string): ToolCallEvent {
	return {
		type: 'tool_call',
		toolCallId: 'call-1',
		toolName: 'read',
		input: { path },
	} as ToolCallEvent;
}

function writeEvent(path: string): ToolCallEvent {
	return {
		type: 'tool_call',
		toolCallId: 'call-1',
		toolName: 'write',
		input: { path },
	} as ToolCallEvent;
}

function customEvent(
	toolName: string,
	input: Record<string, unknown>,
): ToolCallEvent {
	return {
		type: 'tool_call',
		toolCallId: 'call-1',
		toolName,
		input,
	} as ToolCallEvent;
}

describe('handleToolCall', () => {
	it('blocks denied shell commands in full-access mode', async () => {
		const runtime = createRuntime({ ...DEFAULT_CONFIG, mode: 'full-access' });
		const ctx = createContext();

		const result = await handleToolCall(
			bashEvent('git status && rm -rf /'),
			ctx,
			runtime,
		);

		expect(result).toEqual({
			block: true,
			reason: 'Command blocked by deny rules',
		});
		expect(ctx.ui.confirm).not.toHaveBeenCalled();
		expect(runtime.api.sendMessage).toHaveBeenCalledOnce();
		expect(runtime.blockedCommands).toHaveLength(1);
	});

	it('asks for write commands in read-safe mode', async () => {
		const runtime = createRuntime();
		const ctx = createContext(true);

		const result = await handleToolCall(
			writeEvent('/tmp/output.txt'),
			ctx,
			runtime,
		);

		expect(result).toBeUndefined();
		expect(ctx.ui.confirm).toHaveBeenCalledWith(
			'Approve file operation',
			'write /tmp/output.txt',
			expect.any(Object),
		);
		expect(runtime.approvedCalls.has('call-1')).toBe(true);
	});

	it('allows non-denied write commands in full-access mode without asking', async () => {
		const runtime = createRuntime({ ...DEFAULT_CONFIG, mode: 'full-access' });
		const ctx = createContext();

		const result = await handleToolCall(
			writeEvent('/tmp/output.txt'),
			ctx,
			runtime,
		);

		expect(result).toBeUndefined();
		expect(ctx.ui.confirm).not.toHaveBeenCalled();
	});

	it('asks using select and allows each tool call individually', async () => {
		const runtime = createRuntime({ ...DEFAULT_CONFIG, mode: 'ask-first' });
		const branch = [
			{
				type: 'message',
				id: 'msg-assistant-1',
				message: {
					role: 'assistant',
					content: [
						{
							type: 'toolCall',
							id: 'call-1',
							name: 'bash',
							arguments: { command: 'echo 1' },
						},
						{
							type: 'toolCall',
							id: 'call-2',
							name: 'bash',
							arguments: { command: 'echo 2' },
						},
					],
				},
			},
		];

		// Prompt for first tool call, user chooses 'Allow'
		const ctx1 = createContextWithSession(true, branch, 'Allow');
		const result1 = await handleToolCall(
			{
				type: 'tool_call',
				toolCallId: 'call-1',
				toolName: 'bash',
				input: { command: 'echo 1' },
			} as ToolCallEvent,
			ctx1,
			runtime,
		);
		expect(result1).toBeUndefined();
		expect(ctx1.ui.select).toHaveBeenCalledWith(
			'Approve shell command [1/2]',
			['Allow', 'Deny', 'Allow All', 'Deny All'],
			expect.any(Object),
		);
		expect(runtime.sessionState.approvedBatchId).toBeUndefined();

		// Prompt for second tool call, user is prompted normally (no auto-allow yet)
		const ctx2 = createContextWithSession(true, branch, 'Deny');
		const result2 = await handleToolCall(
			{
				type: 'tool_call',
				toolCallId: 'call-2',
				toolName: 'bash',
				input: { command: 'echo 2' },
			} as ToolCallEvent,
			ctx2,
			runtime,
		);
		expect(result2).toEqual({ block: true, reason: 'User denied approval' });
		expect(ctx2.ui.select).toHaveBeenCalledWith(
			'Approve shell command [2/2]',
			['Allow', 'Deny', 'Allow All', 'Deny All'],
			expect.any(Object),
		);
	});

	it('auto-approves subsequent tool calls when Allow All is selected', async () => {
		const runtime = createRuntime({ ...DEFAULT_CONFIG, mode: 'ask-first' });
		const branch = [
			{
				type: 'message',
				id: 'msg-assistant-1',
				message: {
					role: 'assistant',
					content: [
						{
							type: 'toolCall',
							id: 'call-1',
							name: 'bash',
							arguments: { command: 'echo 1' },
						},
						{
							type: 'toolCall',
							id: 'call-2',
							name: 'bash',
							arguments: { command: 'echo 2' },
						},
					],
				},
			},
		];

		// User selects 'Allow All' on first tool call
		const ctx1 = createContextWithSession(true, branch, 'Allow All');
		const result1 = await handleToolCall(
			{
				type: 'tool_call',
				toolCallId: 'call-1',
				toolName: 'bash',
				input: { command: 'echo 1' },
			} as ToolCallEvent,
			ctx1,
			runtime,
		);
		expect(result1).toBeUndefined();
		expect(runtime.sessionState.approvedBatchId).toBe('msg-assistant-1');

		// Second tool call is auto-approved without prompting
		const ctx2 = createContextWithSession(true, branch, 'Allow');
		const result2 = await handleToolCall(
			{
				type: 'tool_call',
				toolCallId: 'call-2',
				toolName: 'bash',
				input: { command: 'echo 2' },
			} as ToolCallEvent,
			ctx2,
			runtime,
		);
		expect(result2).toBeUndefined();
		expect(ctx2.ui.select).not.toHaveBeenCalled();
		expect(ctx2.ui.confirm).not.toHaveBeenCalled();
	});

	it('auto-denies subsequent tool calls when Deny All is selected', async () => {
		const runtime = createRuntime({ ...DEFAULT_CONFIG, mode: 'ask-first' });
		const branch = [
			{
				type: 'message',
				id: 'msg-assistant-1',
				message: {
					role: 'assistant',
					content: [
						{
							type: 'toolCall',
							id: 'call-1',
							name: 'bash',
							arguments: { command: 'echo 1' },
						},
						{
							type: 'toolCall',
							id: 'call-2',
							name: 'bash',
							arguments: { command: 'echo 2' },
						},
					],
				},
			},
		];

		// User selects 'Deny All' on first tool call
		const ctx1 = createContextWithSession(false, branch, 'Deny All');
		const result1 = await handleToolCall(
			{
				type: 'tool_call',
				toolCallId: 'call-1',
				toolName: 'bash',
				input: { command: 'echo 1' },
			} as ToolCallEvent,
			ctx1,
			runtime,
		);
		expect(result1).toEqual({ block: true, reason: 'User denied approval' });
		expect(runtime.sessionState.deniedBatchId).toBe('msg-assistant-1');

		// Second tool call is auto-denied without prompting
		const ctx2 = createContextWithSession(true, branch, 'Allow');
		const result2 = await handleToolCall(
			{
				type: 'tool_call',
				toolCallId: 'call-2',
				toolName: 'bash',
				input: { command: 'echo 2' },
			} as ToolCallEvent,
			ctx2,
			runtime,
		);
		expect(result2).toEqual({
			block: true,
			reason: 'User denied all tool calls in this batch',
		});
		expect(ctx2.ui.select).not.toHaveBeenCalled();
	});

	it('allows path tools inside cwd in folder-trusted mode', async () => {
		const runtime = createRuntime({
			...DEFAULT_CONFIG,
			mode: 'folder-trusted',
		});
		const ctx = createContext();

		await expect(
			handleToolCall(writeEvent('/repo/app/src/file.ts'), ctx, runtime),
		).resolves.toBeUndefined();
		await expect(
			handleToolCall(readEvent('/repo/app/src/file.ts'), ctx, runtime),
		).resolves.toBeUndefined();
		expect(ctx.ui.confirm).not.toHaveBeenCalled();
	});

	it('asks for path tools outside cwd in folder-trusted mode', async () => {
		const runtime = createRuntime({
			...DEFAULT_CONFIG,
			mode: 'folder-trusted',
		});
		const ctx = createContext(true);

		await expect(
			handleToolCall(writeEvent('/repo/other/file.ts'), ctx, runtime),
		).resolves.toBeUndefined();

		expect(ctx.ui.confirm).toHaveBeenCalledWith(
			'Approve file operation',
			'write /repo/other/file.ts',
			expect.any(Object),
		);
	});

	it('allows scoped safe shell commands in folder-trusted mode', async () => {
		const runtime = createRuntime({
			...DEFAULT_CONFIG,
			mode: 'folder-trusted',
		});
		const ctx = createContext();

		await expect(
			handleToolCall(bashEvent('cat src/index.ts'), ctx, runtime),
		).resolves.toBeUndefined();
		expect(ctx.ui.confirm).not.toHaveBeenCalled();
	});

	it('asks for shell paths outside cwd in folder-trusted mode', async () => {
		const runtime = createRuntime({
			...DEFAULT_CONFIG,
			mode: 'folder-trusted',
		});
		const ctx = createContext(true);

		await expect(
			handleToolCall(bashEvent('cat ../secret.txt'), ctx, runtime),
		).resolves.toBeUndefined();
		expect(ctx.ui.confirm).toHaveBeenCalledWith(
			'Approve shell command',
			'shell: cat ../secret.txt',
			expect.any(Object),
		);
	});

	it('asks for launchers in folder-trusted mode', async () => {
		const runtime = createRuntime({
			...DEFAULT_CONFIG,
			mode: 'folder-trusted',
		});
		const ctx = createContext(true);

		await expect(
			handleToolCall(bashEvent('npm test'), ctx, runtime),
		).resolves.toBeUndefined();
		expect(ctx.ui.confirm).toHaveBeenCalledWith(
			'Approve shell command',
			'shell: npm test',
			expect.any(Object),
		);
	});

	it('self-guarded allows safe shell but asks ambiguous shell', async () => {
		const runtime = createRuntime({
			...DEFAULT_CONFIG,
			mode: 'self-guarded',
		});
		const safeCtx = createContext();
		await expect(
			handleToolCall(bashEvent('git status'), safeCtx, runtime),
		).resolves.toBeUndefined();
		expect(safeCtx.ui.confirm).not.toHaveBeenCalled();

		const askCtx = createContext(true);
		await expect(
			handleToolCall(
				{
					...bashEvent('cargo check'),
					toolCallId: 'call-2',
				} as ToolCallEvent,
				askCtx,
				runtime,
			),
		).resolves.toBeUndefined();
		expect(askCtx.ui.confirm).toHaveBeenCalledWith(
			'Approve shell command',
			'shell: cargo check',
			expect.any(Object),
		);
	});

	it('self-guarded asks for custom tools without an allow rule', async () => {
		const runtime = createRuntime({
			...DEFAULT_CONFIG,
			mode: 'self-guarded',
		});
		const ctx = createContext(true);

		await expect(
			handleToolCall(customEvent('deploy', { target: 'prod' }), ctx, runtime),
		).resolves.toBeUndefined();
		expect(ctx.ui.confirm).toHaveBeenCalledWith(
			'Approve tool call',
			'deploy: {"target":"prod"}',
			expect.any(Object),
		);
	});

	it('keeps hard deny stronger than batch Allow All', async () => {
		const runtime = createRuntime({ ...DEFAULT_CONFIG, mode: 'ask-first' });
		const branch = [
			{
				type: 'message',
				id: 'msg-assistant-2',
				message: {
					role: 'assistant',
					content: [
						{
							type: 'toolCall',
							id: 'call-1',
							name: 'bash',
							arguments: { command: 'cargo check' },
						},
						{
							type: 'toolCall',
							id: 'call-2',
							name: 'bash',
							arguments: { command: 'rm -rf /' },
						},
					],
				},
			},
		];

		const ctx1 = createContextWithSession(true, branch, 'Allow All');
		await expect(
			handleToolCall(
				{
					type: 'tool_call',
					toolCallId: 'call-1',
					toolName: 'bash',
					input: { command: 'cargo check' },
				} as ToolCallEvent,
				ctx1,
				runtime,
			),
		).resolves.toBeUndefined();

		const ctx2 = createContextWithSession(true, branch, 'Allow');
		await expect(
			handleToolCall(
				{
					type: 'tool_call',
					toolCallId: 'call-2',
					toolName: 'bash',
					input: { command: 'rm -rf /' },
				} as ToolCallEvent,
				ctx2,
				runtime,
			),
		).resolves.toEqual({
			block: true,
			reason: 'Command blocked by deny rules',
		});
		expect(ctx2.ui.confirm).not.toHaveBeenCalled();
	});
});
