import type { Config, FilePermissions, ShellGuardPolicyConfig } from '../types';

export const DEFAULT_FILE_PERMISSIONS: FilePermissions = {
	allow: [],
	deny: [],
	ask: [],
};

// Backwards-compatible export name used by tests and external imports.
export const DEFAULT_PERMISSIONS = DEFAULT_FILE_PERMISSIONS;

export const DEFAULT_SHELL_GUARD_POLICY: ShellGuardPolicyConfig = {
	rules: [],
	unknown: 'ask',
};

// Backwards-compatible export name used by tests and external imports.
export const DEFAULT_BASH_POLICY = DEFAULT_SHELL_GUARD_POLICY;

export const DEFAULT_CONFIG: Config = {
	mode: 'read-safe',
	shortcut: 'ctrl+shift+f8',
	permissions: { ...DEFAULT_FILE_PERMISSIONS },
	shellGuard: { ...DEFAULT_SHELL_GUARD_POLICY, rules: [] },
};
