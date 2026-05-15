export type ApprovalMode = 'yolo' | 'read-only' | 'strict';

export type BashAnalysis = 'safe' | 'dangerous' | 'pipe-bypass';

export interface PatternRule {
	tool: string;
	pattern: string;
	args?: string;
}

export interface Permissions {
	allow: string[];
	deny: string[];
	ask: string[];
}

export interface Config {
	mode: ApprovalMode;
	shortcut: string;
	permissions: Permissions;
}

export interface BlockedCommand {
	tool: string;
	reason: string;
	timestamp: number;
}
