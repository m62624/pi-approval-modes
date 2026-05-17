import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { getAgentDir } from '@earendil-works/pi-coding-agent';
import { EXTENSION_NAME } from '../constants';
import type {
	BashPolicyConfig,
	BashRule,
	BashRuleAction,
	Config,
	FilePermissions,
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
	const aliases: Record<string, Config['mode']> = {
		approved: 'read-only',
		safe: 'read-only',
	};
	if (!raw) return 'read-only';
	const normalized = raw.toLowerCase().trim();
	if (normalized in aliases) return aliases[normalized];
	if (
		normalized === 'yolo' ||
		normalized === 'read-only' ||
		normalized === 'strict'
	) {
		return normalized;
	}
	return 'read-only';
}

function resolveAction(
	raw: string | undefined,
	fallback: BashRuleAction,
): BashRuleAction {
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

function isBashRule(value: unknown): value is BashRule {
	if (!value || typeof value !== 'object') return false;
	const candidate = value as Partial<BashRule>;
	return (
		(candidate.action === 'allow' ||
			candidate.action === 'ask' ||
			candidate.action === 'deny') &&
		!!candidate.match &&
		typeof candidate.match === 'object'
	);
}

function mergeBashPolicy(
	loaded: Partial<BashPolicyConfig> = {},
): BashPolicyConfig {
	return {
		rules: Array.isArray(loaded.rules) ? loaded.rules.filter(isBashRule) : [],
		unknown: resolveAction(loaded.unknown, DEFAULT_CONFIG.bash.unknown),
	};
}

function mergeConfig(loaded: Partial<Config> | null): Config {
	if (!loaded) {
		return {
			...DEFAULT_CONFIG,
			permissions: { ...DEFAULT_CONFIG.permissions },
			bash: { ...DEFAULT_CONFIG.bash, rules: [] },
		};
	}

	return {
		mode: resolveMode(loaded.mode),
		shortcut: loaded.shortcut ?? DEFAULT_CONFIG.shortcut,
		permissions: mergePermissions(loaded.permissions),
		bash: mergeBashPolicy(loaded.bash),
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
