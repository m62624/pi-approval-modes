import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { getAgentDir } from '@earendil-works/pi-coding-agent';
import { EXTENSION_NAME } from '../constants';
import type { Config } from '../types';
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
	)
		return normalized as Config['mode'];
	return 'read-only';
}

function mergePermissions(
	loaded: Config['permissions'] | undefined,
): Config['permissions'] {
	return {
		allow: loaded?.allow ?? [...DEFAULT_CONFIG.permissions.allow],
		deny: loaded?.deny ?? [...DEFAULT_CONFIG.permissions.deny],
		ask: loaded?.ask ?? [...DEFAULT_CONFIG.permissions.ask],
	};
}

function mergeConfig(loaded: Config | null): Config {
	if (loaded) {
		return {
			mode: resolveMode(loaded.mode),
			shortcut: loaded.shortcut ?? 'shift+tab',
			permissions: mergePermissions(loaded.permissions),
		};
	}
	return {
		...DEFAULT_CONFIG,
		permissions: { ...DEFAULT_CONFIG.permissions },
	};
}

export function loadConfig(): Config | null {
	const paths = configPaths();
	try {
		if (!existsSync(paths.settings)) return null;
		const raw = readFileSync(paths.settings, 'utf-8');
		const loaded = JSON.parse(raw) as Config;
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
