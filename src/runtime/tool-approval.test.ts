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

function writeEvent(path: string): ToolCallEvent {
	return {
		type: 'tool_call',
		toolCallId: 'call-1',
		toolName: 'write',
		input: { path },
	} as ToolCallEvent;
}

describe('handleToolCall', () => {
	it('blocks denied bash commands in yolo mode', async () => {
		const runtime = createRuntime({ ...DEFAULT_CONFIG, mode: 'yolo' });
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

	it('asks for write commands in read-only mode', async () => {
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

	it('allows non-denied write commands in yolo mode without asking', async () => {
		const runtime = createRuntime({ ...DEFAULT_CONFIG, mode: 'yolo' });
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
		const runtime = createRuntime({ ...DEFAULT_CONFIG, mode: 'strict' });
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
			'Approve bash command [1/2]',
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
			'Approve bash command [2/2]',
			['Allow', 'Deny', 'Allow All', 'Deny All'],
			expect.any(Object),
		);
	});

	it('auto-approves subsequent tool calls when Allow All is selected', async () => {
		const runtime = createRuntime({ ...DEFAULT_CONFIG, mode: 'strict' });
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
		const runtime = createRuntime({ ...DEFAULT_CONFIG, mode: 'strict' });
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
});
