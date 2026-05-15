import type { ApprovalMode } from './types';

const MODE_ALIASES: Record<string, ApprovalMode> = {
	approved: 'read-only',
	safe: 'read-only',
};

const MODES: ApprovalMode[] = ['yolo', 'read-only', 'strict'];

export { MODES };

export function resolveMode(raw: string | undefined): ApprovalMode {
	if (!raw) return 'read-only';
	const normalized = raw.toLowerCase().trim();
	if (normalized in MODE_ALIASES) return MODE_ALIASES[normalized];
	if (
		normalized === 'yolo' ||
		normalized === 'read-only' ||
		normalized === 'strict'
	)
		return normalized as ApprovalMode;
	return 'read-only';
}

export function modeLabel(mode: ApprovalMode): string {
	switch (mode) {
		case 'yolo':
			return '🔓 YOLO';
		case 'read-only':
			return '🔒 Read-Only';
		case 'strict':
			return '🛡 Strict';
	}
}
