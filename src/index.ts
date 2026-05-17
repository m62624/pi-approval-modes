import type { ExtensionFactory } from '@earendil-works/pi-coding-agent';
import { Key, type KeyId, parseKey } from '@earendil-works/pi-tui';
import { ensureConfigExists, loadConfig, saveConfig } from './config/loader';
import { DEFAULT_CONFIG } from './config/schema';
import { EXTENSION_NAME } from './constants';
import { MODES, modeLabel, resolveMode } from './mode';
import { handleToolCall } from './runtime/tool-approval';
import type { BlockedCommand, Config } from './types';

const factory: ExtensionFactory = async (api) => {
	ensureConfigExists();
	let config: Config = loadConfig() ?? DEFAULT_CONFIG;
	const approvedCalls = new Set<string>();
	const blockedCommands: BlockedCommand[] = [];

	api.on('session_start', async (_event, ctx) => {
		config = loadConfig() ?? config;
		approvedCalls.clear();
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

	api.on('tool_call', async (event, ctx) => {
		return handleToolCall(event, ctx, {
			api,
			config,
			approvedCalls,
			blockedCommands,
		});
	});

	// Shortcut: cycles mode
	const shortcutId = (parseKey(config.shortcut) ?? Key.shift('tab')) as KeyId;
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

	// /approval command
	api.registerCommand('approval', {
		description: 'Switch approval mode (yolo|read-only|strict)',
		handler: async (args, ctx) => {
			if (!args) {
				ctx.ui.notify(
					`${modeLabel(config.mode)} — yolo|read-only|strict`,
					'info',
				);
				return;
			}
			const mode = resolveMode(args);
			if (mode !== 'yolo' && mode !== 'read-only' && mode !== 'strict') {
				ctx.ui.notify(
					`Unknown mode: ${args}. Use: yolo, read-only, strict`,
					'error',
				);
				return;
			}
			config.mode = mode;
			saveConfig({ ...config });
			ctx.ui.setStatus(EXTENSION_NAME, modeLabel(config.mode));
			ctx.ui.notify(`Mode: ${modeLabel(mode)}`, 'info');
		},
	});

	// /approval-reset
	api.registerCommand('approval-reset', {
		description: 'Reset to defaults',
		handler: async (_args, ctx) => {
			config = {
				...DEFAULT_CONFIG,
				permissions: { ...DEFAULT_CONFIG.permissions },
			};
			saveConfig(config);
			ctx.ui.setStatus(EXTENSION_NAME, modeLabel(config.mode));
			ctx.ui.notify('Reset to defaults', 'info');
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

	// /approval-shortcut
	api.registerCommand('approval-shortcut', {
		description:
			'Show or change shortcut (e.g. /approval-shortcut ctrl+shift+a)',
		handler: async (args, ctx) => {
			if (!args) {
				ctx.ui.notify(`Current shortcut: ${config.shortcut}`, 'info');
				return;
			}
			config.shortcut = args.trim();
			saveConfig({ ...config });
			ctx.ui.notify(`Shortcut changed to: ${args.trim()}`, 'info');
			ctx.ui.notify('Run /reload to activate the new shortcut', 'warning');
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

export default factory;

// ─── Public API (re-export for external use) ───

export { analyzeBashCommand } from './analysis/bash';
export { checkPermissionRule, parseRule } from './analysis/permission-rules';
export { MODES, modeLabel, resolveMode } from './mode';
export { isPathPattern } from './path-pattern';
export type {
	ApprovalMode,
	BashAnalysis,
	BlockedCommand,
	Config,
	PatternRule,
	Permissions,
} from './types';
