import type { BashPolicyConfig, Config, FilePermissions } from '../types';

export const DEFAULT_FILE_PERMISSIONS: FilePermissions = {
	allow: [],
	deny: [],
	ask: [],
};

// Backwards-compatible export name used by tests and external imports.
export const DEFAULT_PERMISSIONS = DEFAULT_FILE_PERMISSIONS;

export const DEFAULT_BASH_POLICY: BashPolicyConfig = {
	rules: [],
	unknown: 'ask',
};

export const DEFAULT_CONFIG: Config = {
	mode: 'read-only',
	shortcut: 'shift+tab',
	permissions: { ...DEFAULT_FILE_PERMISSIONS },
	bash: { ...DEFAULT_BASH_POLICY, rules: [] },
};
