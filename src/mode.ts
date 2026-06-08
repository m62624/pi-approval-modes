import type { ApprovalMode } from './types';

const MODE_ALIASES: Record<string, ApprovalMode> = {
	approved: 'read-safe',
	auto: 'self-guarded',
	'auto-approve': 'self-guarded',
	'folder-yolo': 'folder-trusted',
	'local-yolo': 'folder-trusted',
	'read-only': 'read-safe',
	safe: 'read-safe',
	strict: 'ask-first',
	yolo: 'full-access',
};

const MODES: ApprovalMode[] = [
	'full-access',
	'read-safe',
	'folder-trusted',
	'self-guarded',
	'ask-first',
];

export { MODES };

export function resolveMode(raw: string | undefined): ApprovalMode {
	return tryResolveMode(raw) ?? 'read-safe';
}

export function tryResolveMode(raw: string | undefined): ApprovalMode | null {
	if (!raw) return null;
	const normalized = raw.toLowerCase().trim();
	if (normalized in MODE_ALIASES) return MODE_ALIASES[normalized];
	if (
		normalized === 'full-access' ||
		normalized === 'read-safe' ||
		normalized === 'ask-first' ||
		normalized === 'folder-trusted' ||
		normalized === 'self-guarded'
	)
		return normalized as ApprovalMode;
	return null;
}

export function isApprovalMode(raw: string | undefined): raw is ApprovalMode {
	if (!raw) return false;
	return MODES.includes(raw as ApprovalMode);
}

export function modeLabel(mode: ApprovalMode): string {
	switch (mode) {
		case 'full-access':
			return '🔓 Full Access';
		case 'read-safe':
			return '🔒 Read Safe';
		case 'ask-first':
			return '🛡 Ask First';
		case 'folder-trusted':
			return '📁 Folder Trusted';
		case 'self-guarded':
			return '🤖 Self Guarded';
	}
}

export function modeDescription(mode: ApprovalMode): string {
	switch (mode) {
		case 'full-access':
			return 'Auto-allow most tool calls; hard deny rules still block.';
		case 'read-safe':
			return 'Auto-allow safe reads; ask before mutations and ambiguous shell.';
		case 'folder-trusted':
			return 'Auto-allow path tools inside cwd; ask outside cwd and for launchers.';
		case 'self-guarded':
			return 'Prompt the model to self-check; ask user on uncertain calls.';
		case 'ask-first':
			return 'Ask before shell, write, and edit unless a deny rule blocks.';
	}
}

export function formatModeList(): string {
	return MODES.join('|');
}
