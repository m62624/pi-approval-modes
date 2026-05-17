import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('node:fs', () => ({
	existsSync: vi.fn(),
	mkdirSync: vi.fn(),
	readFileSync: vi.fn(),
	writeFileSync: vi.fn(),
}));

vi.mock('node:path', () => ({
	join: vi.fn((...parts) => parts.join('/')),
	dirname: vi.fn(() => '/mock'),
}));

vi.mock('@earendil-works/pi-coding-agent', () => ({
	getAgentDir: () => '/mock/agent',
}));

import {
	configPaths,
	ensureConfigExists,
	loadConfig,
	saveConfig,
} from './loader';
import { DEFAULT_CONFIG } from './schema';

describe('configPaths', () => {
	it('returns correct path structure', () => {
		const paths = configPaths();
		expect(paths.extensionDir).toBe('/mock/agent/extensions/approval-modes');
		expect(paths.settings).toBe(
			'/mock/agent/extensions/approval-modes/settings.json',
		);
	});
});

describe('loadConfig', () => {
	beforeEach(() => {
		vi.mocked(existsSync).mockReturnValue(false);
	});

	it('returns null when no config file exists', () => {
		const result = loadConfig();
		expect(result).toBeNull();
	});

	it('loads and merges config from file', () => {
		vi.mocked(existsSync).mockReturnValue(true);
		vi.mocked(readFileSync).mockReturnValue(
			JSON.stringify({ mode: 'yolo', shortcut: 'ctrl+shift+a' }),
		);

		const result = loadConfig();
		expect(result).toEqual({
			mode: 'yolo',
			shortcut: 'ctrl+shift+a',
			permissions: { ...DEFAULT_CONFIG.permissions },
			bash: { ...DEFAULT_CONFIG.bash, rules: [] },
		});
	});

	it('loads bash AST rules from file', () => {
		vi.mocked(existsSync).mockReturnValue(true);
		vi.mocked(readFileSync).mockReturnValue(
			JSON.stringify({
				bash: {
					unknown: 'allow',
					rules: [
						{
							action: 'allow',
							match: { command: 'cargo', args: { includes: ['check'] } },
						},
					],
				},
			}),
		);

		const result = loadConfig();
		expect(result?.bash).toEqual({
			unknown: 'allow',
			rules: [
				{
					action: 'allow',
					match: { command: 'cargo', args: { includes: ['check'] } },
				},
			],
		});
	});

	it('resolves aliases (approved → read-only)', () => {
		vi.mocked(existsSync).mockReturnValue(true);
		vi.mocked(readFileSync).mockReturnValue(
			JSON.stringify({ mode: 'approved' }),
		);

		const result = loadConfig();
		expect(result?.mode).toBe('read-only');
	});

	it('resolves aliases (safe → read-only)', () => {
		vi.mocked(existsSync).mockReturnValue(true);
		vi.mocked(readFileSync).mockReturnValue(JSON.stringify({ mode: 'safe' }));

		const result = loadConfig();
		expect(result?.mode).toBe('read-only');
	});
});

describe('saveConfig', () => {
	beforeEach(() => {
		vi.mocked(existsSync).mockReturnValue(false);
	});

	it('writes config to settings file', () => {
		saveConfig({
			...DEFAULT_CONFIG,
			mode: 'strict',
		});

		expect(mkdirSync).toHaveBeenCalledWith(
			'/mock/agent/extensions/approval-modes',
			{ recursive: true },
		);
		expect(writeFileSync).toHaveBeenCalledWith(
			'/mock/agent/extensions/approval-modes/settings.json',
			expect.any(String),
		);
	});
});

describe('ensureConfigExists', () => {
	beforeEach(() => {
		vi.mocked(existsSync).mockReturnValue(false);
		vi.mocked(writeFileSync).mockClear();
	});

	it("creates config file when it doesn't exist", () => {
		ensureConfigExists();

		expect(mkdirSync).toHaveBeenCalledWith(
			'/mock/agent/extensions/approval-modes',
			{ recursive: true },
		);
		expect(writeFileSync).toHaveBeenCalledWith(
			'/mock/agent/extensions/approval-modes/settings.json',
			JSON.stringify(DEFAULT_CONFIG, null, 2),
		);
	});

	it('does nothing when config already exists', () => {
		vi.mocked(existsSync).mockReturnValue(true);

		ensureConfigExists();

		expect(writeFileSync).not.toHaveBeenCalled();
	});
});
