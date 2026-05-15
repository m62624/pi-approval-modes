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
	};
}

function createContext(approved = true) {
	return {
		ui: {
			confirm: vi.fn().mockResolvedValue(approved),
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
			bashEvent('git status && rm -rf /tmp/test-danger-file'),
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
});
