import type { ExtensionFactory } from '@earendil-works/pi-coding-agent';
import { Key, type KeyId, parseKey } from '@earendil-works/pi-tui';
import { analyzeBashCommand } from './analysis/bash';
import { resetPatternCache } from './analysis/patterns';
import { checkPermissionRule } from './analysis/permission-rules';
import { ensureConfigExists, loadConfig, saveConfig } from './config/loader';
import { EXTENSION_NAME } from './constants';
import { MODES, modeLabel, resolveMode } from './mode';
import type { BlockedCommand, Config } from './types';

const factory: ExtensionFactory = async (api) => {
	ensureConfigExists();
	let config: Config = loadConfig() ?? {
		mode: 'read-only',
		shortcut: 'shift+tab',
		permissions: {
			allow: [],
			deny: [],
			ask: [],
		},
	};
	const approvedCalls = new Set<string>();
	const blockedCommands: BlockedCommand[] = [];

	api.on('session_start', async (_event, ctx) => {
		config = loadConfig() ?? config;
		approvedCalls.clear();
		resetPatternCache();
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
		// === BASH TOOL ===
		if (event.toolName === 'bash') {
			const input = event.input as Record<string, unknown>;
			const command = (input.command as string) ?? '';
			const analysis = analyzeBashCommand(command, config);

			if (analysis === 'dangerous') {
				approvedCalls.add(event.toolCallId);
				blockedCommands.push({
					tool: 'bash',
					reason: `bash: ${command}`,
					timestamp: Date.now(),
				});
				if (blockedCommands.length > 1000) blockedCommands.shift();

				api.sendMessage(
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

				return { block: true, reason: 'Command blocked by deny rules' };
			}

			if (config.mode === 'yolo' || approvedCalls.has(event.toolCallId))
				return undefined;

			if (config.mode === 'read-only') {
				if (analysis === 'safe') {
					approvedCalls.add(event.toolCallId);
					return undefined;
				}

				const summary = `bash: ${command}`;
				const approved = await ctx.ui.confirm('Approve bash command', summary, {
					timeout: 120000,
					signal: ctx.signal,
				});
				if (!approved) {
					approvedCalls.add(event.toolCallId);
					blockedCommands.push({
						tool: 'bash',
						reason: summary,
						timestamp: Date.now(),
					});
					if (blockedCommands.length > 1000) blockedCommands.shift();
					return { block: true, reason: 'User denied approval' };
				}
				approvedCalls.add(event.toolCallId);
				return undefined;
			}

			if (config.mode === 'strict') {
				const summary = `bash: ${command}`;
				const approved = await ctx.ui.confirm('Approve bash command', summary, {
					timeout: 120000,
					signal: ctx.signal,
				});
				if (!approved) {
					approvedCalls.add(event.toolCallId);
					blockedCommands.push({
						tool: 'bash',
						reason: summary,
						timestamp: Date.now(),
					});
					if (blockedCommands.length > 1000) blockedCommands.shift();
					return { block: true, reason: 'User denied approval' };
				}
				approvedCalls.add(event.toolCallId);
				return undefined;
			}
		}

		// === WRITE/EDIT TOOLS ===
		if (event.toolName !== 'write' && event.toolName !== 'edit')
			return undefined;

		const input = event.input as Record<string, unknown>;
		const filePath = (input.path as string) ?? 'unknown';

		const denyResult = checkPermissionRule(
			config.permissions.deny,
			{ toolName: event.toolName },
			input,
			{ deny: true },
		);
		if (denyResult === 'blocked') {
			approvedCalls.add(event.toolCallId);
			return { block: true, reason: `Blocked by deny rule: ${filePath}` };
		}

		if (config.mode === 'yolo' || approvedCalls.has(event.toolCallId))
			return undefined;

		if (config.mode !== 'strict') {
			const permResult = checkPermissionRule(
				config.permissions.allow,
				{ toolName: event.toolName },
				input,
			);
			if (permResult === 'allowed') {
				approvedCalls.add(event.toolCallId);
				return undefined;
			}
		}

		const summary =
			event.toolName === 'write' ? `write ${filePath}` : `edit ${filePath}`;
		const approved = await ctx.ui.confirm('Approve file operation', summary, {
			timeout: 120000,
			signal: ctx.signal,
		});
		if (!approved) {
			approvedCalls.add(event.toolCallId);
			blockedCommands.push({
				tool: event.toolName,
				reason: summary,
				timestamp: Date.now(),
			});
			if (blockedCommands.length > 1000) blockedCommands.shift();
			return { block: true, reason: 'User denied approval' };
		}
		approvedCalls.add(event.toolCallId);
		return undefined;
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
			const { DEFAULT_CONFIG } = await import('./config/schema');
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
			resetPatternCache();
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
