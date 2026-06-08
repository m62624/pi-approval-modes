import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { getAgentDir } from '@earendil-works/pi-coding-agent';
import { EXTENSION_NAME } from '../constants';
import { resolveMode as resolveApprovalMode } from '../mode';
import type {
	Config,
	FilePermissions,
	ShellGuardPolicyConfig,
	ShellGuardRule,
	ShellGuardRuleAction,
} from '../types';
import { createConfigPaths } from './paths';
import { DEFAULT_CONFIG } from './schema';

export function configPaths() {
	return createConfigPaths({
		agentDir: getAgentDir(),
		cwd: process.cwd(),
		extensionName: EXTENSION_NAME,
	});
}

function resolveMode(raw: string | undefined): Config['mode'] {
	return resolveApprovalMode(raw);
}

function resolveAction(
	raw: string | undefined,
	fallback: ShellGuardRuleAction,
): ShellGuardRuleAction {
	if (raw === 'allow' || raw === 'ask' || raw === 'deny') return raw;
	return fallback;
}

function mergePermissions(
	loaded: Partial<FilePermissions> = {},
): FilePermissions {
	return {
		allow: Array.isArray(loaded.allow) ? loaded.allow : [],
		deny: Array.isArray(loaded.deny) ? loaded.deny : [],
		ask: Array.isArray(loaded.ask) ? loaded.ask : [],
	};
}

function isShellGuardRule(value: unknown): value is ShellGuardRule {
	if (!value || typeof value !== 'object') return false;
	const candidate = value as Partial<ShellGuardRule>;
	return (
		(candidate.action === 'allow' ||
			candidate.action === 'ask' ||
			candidate.action === 'deny') &&
		!!candidate.match &&
		typeof candidate.match === 'object'
	);
}

function mergeShellGuardPolicy(
	loaded: Partial<ShellGuardPolicyConfig> = {},
): ShellGuardPolicyConfig {
	return {
		rules: Array.isArray(loaded.rules)
			? loaded.rules.filter(isShellGuardRule)
			: [],
		unknown: resolveAction(loaded.unknown, DEFAULT_CONFIG.shellGuard.unknown),
	};
}

function mergeConfig(loaded: Partial<Config> | null): Config {
	if (!loaded) {
		return {
			...DEFAULT_CONFIG,
			permissions: { ...DEFAULT_CONFIG.permissions },
			shellGuard: { ...DEFAULT_CONFIG.shellGuard, rules: [] },
		};
	}

	const shellGuard = loaded.shellGuard ?? loaded.bash;
	return {
		mode: resolveMode(loaded.mode),
		shortcut: loaded.shortcut ?? DEFAULT_CONFIG.shortcut,
		permissions: mergePermissions(loaded.permissions),
		shellGuard: mergeShellGuardPolicy(shellGuard),
	};
}

export function loadConfig(): Config | null {
	const paths = configPaths();
	try {
		if (!existsSync(paths.settings)) return null;
		const raw = readFileSync(paths.settings, 'utf-8');
		const loaded = JSON.parse(raw) as Partial<Config>;
		return mergeConfig(loaded);
	} catch (e) {
		console.error(
			`[approval-modes] Failed to load config: ${e instanceof Error ? e.message : String(e)}`,
		);
		return null;
	}
}

export function ensureDir(): void {
	const paths = configPaths();
	mkdirSync(paths.extensionDir, { recursive: true });
}

export function saveConfig(cfg: Config): void {
	try {
		ensureDir();
		const paths = configPaths();
		writeFileSync(paths.settings, JSON.stringify(cfg, null, 2));
	} catch (e) {
		console.error(
			`[approval-modes] Failed to save config: ${e instanceof Error ? e.message : String(e)}`,
		);
	}
}

export function ensureConfigExists(): void {
	const paths = configPaths();
	if (!existsSync(paths.settings)) {
		ensureDir();
		writeFileSync(paths.settings, JSON.stringify(DEFAULT_CONFIG, null, 2));
	}
}
