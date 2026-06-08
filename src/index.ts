import type {
	ExtensionCommandContext,
	ExtensionFactory,
} from '@earendil-works/pi-coding-agent';
import { type KeyId, parseKey } from '@earendil-works/pi-tui';
import { ensureConfigExists, loadConfig, saveConfig } from './config/loader';
import { DEFAULT_CONFIG } from './config/schema';
import { EXTENSION_NAME } from './constants';
import {
	formatModeList,
	isApprovalMode,
	MODES,
	modeDescription,
	modeLabel,
	tryResolveMode,
} from './mode';
import { buildApprovalHelperText } from './runtime/approval-helper';
import { buildSelfGuardedSystemPrompt } from './runtime/self-guarded-prompt';
import { handleToolCall } from './runtime/tool-approval';
import type { ApprovalMode, BlockedCommand, Config } from './types';

const factory: ExtensionFactory = async (api) => {
	ensureConfigExists();
	let config: Config = loadConfig() ?? DEFAULT_CONFIG;
	const approvedCalls = new Set<string>();
	const blockedCommands: BlockedCommand[] = [];
	const sessionState = {
		deniedBatchId: undefined as string | undefined,
		approvedBatchId: undefined as string | undefined,
	};

	api.on('session_start', async (_event, ctx) => {
		config = loadConfig() ?? config;
		approvedCalls.clear();
		sessionState.deniedBatchId = undefined;
		sessionState.approvedBatchId = undefined;
		ctx.ui.setStatus(EXTENSION_NAME, modeLabel(config.mode));
	});

	api.on('session_shutdown', async (event, _ctx) => {
		if (event.reason !== 'reload') {
			api.appendEntry('approval-modes-stats', {
				blockedCount: blockedCommands.length,
				mode: config.mode,
			});
		}
	});

	api.on('before_agent_start', async (event, ctx) => {
		if (config.mode !== 'self-guarded') return undefined;
		return {
			systemPrompt: buildSelfGuardedSystemPrompt({
				basePrompt: event.systemPrompt,
				config,
				cwd: ctx.cwd,
			}),
		};
	});

	api.on('tool_call', async (event, ctx) => {
		return handleToolCall(event, ctx, {
			api,
			config,
			approvedCalls,
			blockedCommands,
			sessionState,
		});
	});

	// Shortcut: cycles mode
	const shortcutId = (parseKey(config.shortcut) ??
		parseKey(DEFAULT_CONFIG.shortcut)) as KeyId;
	api.registerShortcut(shortcutId, {
		description: 'Cycle approval mode',
		handler: async (ctx) => {
			const currentIdx = MODES.indexOf(config.mode);
			config.mode = MODES[(currentIdx + 1) % MODES.length];
			saveConfig({ ...config });
			ctx.ui.setStatus(EXTENSION_NAME, modeLabel(config.mode));
			ctx.ui.notify(`Mode: ${modeLabel(config.mode)}`, 'info');
		},
	});

	const applyMode = (
		mode: ApprovalMode,
		ctx: ExtensionCommandContext,
	): void => {
		config.mode = mode;
		saveConfig({ ...config });
		ctx.ui.setStatus(EXTENSION_NAME, modeLabel(config.mode));
		ctx.ui.notify(`Mode: ${modeLabel(mode)}`, 'info');
	};

	const approvalCommand = {
		description: `Switch approval mode (${formatModeList()})`,
		handler: async (args: string, ctx: ExtensionCommandContext) => {
			const mode = args
				? parseModeArg(args, (message, type) => ctx.ui.notify(message, type))
				: await selectApprovalMode(ctx.ui, config.mode);
			if (!mode) return;
			applyMode(mode, ctx);
		},
	};

	api.registerCommand('approval', approvalCommand);

	// /approval-reset
	api.registerCommand('approval-reset', {
		description: 'Reset the full approval settings file to factory defaults.',
		handler: async (_args, ctx) => {
			const confirmed = await ctx.ui.confirm(
				'Reset approval settings?',
				[
					'This will replace the full approval-modes settings file with factory defaults.',
					'Current mode, shortcut, permissions, and shellGuard rules will be lost.',
				].join('\n'),
				{ timeout: 10000 },
			);
			if (!confirmed) {
				ctx.ui.notify('Approval reset cancelled.', 'info');
				return;
			}
			config = {
				...DEFAULT_CONFIG,
				permissions: { ...DEFAULT_CONFIG.permissions },
				shellGuard: { ...DEFAULT_CONFIG.shellGuard, rules: [] },
			};
			saveConfig(config);
			ctx.ui.setStatus(EXTENSION_NAME, modeLabel(config.mode));
			ctx.ui.notify('Approval settings reset to factory defaults.', 'info');
		},
	});

	// /approval-stats
	api.registerCommand('approval-stats', {
		description: 'Show approval statistics',
		handler: async (_args, ctx) => {
			const total = approvedCalls.size + blockedCommands.length;
			ctx.ui.notify(
				`Approved: ${approvedCalls.size} | Blocked: ${blockedCommands.length} | Total: ${total}`,
				'info',
			);
		},
	});

	// /approval-helper
	api.registerCommand('approval-helper', {
		description: 'Show a compact approval modes and config helper.',
		handler: async (_args, _ctx) => {
			api.sendMessage(
				{
					customType: 'approval-helper',
					content: buildApprovalHelperText(),
					display: true,
				},
				{ triggerTurn: false },
			);
		},
	});

	// /approval-reload
	api.registerCommand('approval-reload', {
		description: 'Reload config from disk',
		handler: async (_args, ctx) => {
			config = loadConfig() ?? config;
			ctx.ui.setStatus(EXTENSION_NAME, modeLabel(config.mode));
			ctx.ui.notify(`Config reloaded: ${modeLabel(config.mode)}`, 'info');
		},
	});
};

function parseModeArg(
	args: string,
	notify: (message: string, type?: 'info' | 'warning' | 'error') => void,
): ApprovalMode | null {
	const mode = tryResolveMode(args);
	if (!mode || !isApprovalMode(mode)) {
		notify(`Unknown mode: ${args}. Use: ${formatModeList()}`, 'error');
		return null;
	}
	return mode;
}

async function selectApprovalMode(
	ui: {
		select(title: string, options: string[]): Promise<string | undefined>;
		notify(message: string, type?: 'info' | 'warning' | 'error'): void;
	},
	currentMode: ApprovalMode,
): Promise<ApprovalMode | null> {
	const labels = MODES.map((mode) =>
		approvalModeOptionLabel(mode, currentMode),
	);
	const choice = await ui.select('Approval mode', labels);
	if (!choice) {
		ui.notify('Approval mode unchanged.', 'info');
		return null;
	}
	const index = labels.indexOf(choice);
	return index >= 0 ? (MODES[index] ?? null) : null;
}

function approvalModeOptionLabel(
	mode: ApprovalMode,
	currentMode: ApprovalMode,
): string {
	const marker = mode === currentMode ? '*' : '-';
	return `${marker} ${modeLabel(mode)} [${mode}]\n  ${modeDescription(mode)}`;
}

export default factory;

// ─── Public API (re-export for external use) ───

export { checkPermissionRule, parseRule } from './analysis/permission-rules';
export {
	analyzeBashCommand,
	analyzeShellCommand,
	isShellCommandScopedToCwd,
} from './analysis/shell-guard';
export {
	formatModeList,
	MODES,
	modeDescription,
	modeLabel,
	resolveMode,
	tryResolveMode,
} from './mode';
export { isPathPattern } from './path-pattern';
export type {
	ApprovalMode,
	BashAnalysis,
	BlockedCommand,
	Config,
	PatternRule,
	Permissions,
	ShellAnalysis,
	ShellGuardPolicyConfig,
	ShellGuardRule,
} from './types';
