export type ApprovalMode = 'yolo' | 'read-only' | 'strict';

export type BashAnalysis = 'safe' | 'dangerous' | 'pipe-bypass';
export type BashRuleAction = 'allow' | 'ask' | 'deny';
export type BashRulePrecedence = 'before-builtin' | 'after-builtin';

export interface PatternRule {
	tool: string;
	pattern: string;
	args?: string;
}

export interface FilePermissions {
	allow: string[];
	deny: string[];
	ask: string[];
}

// Backwards-compatible name for older imports.
export type Permissions = FilePermissions;

export interface BashArgMatch {
	includes?: string[];
	includesAny?: string[];
	startsWith?: string[];
	contains?: string[];
}

export interface BashRedirectionMatch {
	target?: string | string[];
	targetKind?: 'any' | 'null' | 'protected' | 'workspace';
	op?: string | string[];
	write?: boolean;
}

export interface BashPipelineMatch {
	from?: string | string[];
	to?: string | string[];
}

export interface BashRuleMatch {
	command?: string | string[];
	commands?: string[];
	args?: BashArgMatch;
	redirection?: BashRedirectionMatch;
	pipeline?: BashPipelineMatch;
	hasExpansion?: boolean;
	hasUnsupportedSyntax?: boolean;
}

export interface BashRule {
	id?: string;
	action: BashRuleAction;
	precedence?: BashRulePrecedence;
	reason?: string;
	match: BashRuleMatch;
}

export interface BashPolicyConfig {
	/**
	 * User AST rules. Empty by default.
	 * Rules with precedence="before-builtin" may override the built-in AST policy.
	 */
	rules: BashRule[];
	/** Decision for unknown commands. Default: ask. */
	unknown: BashRuleAction;
}

export interface Config {
	mode: ApprovalMode;
	shortcut: string;
	/** File tool permissions for write/edit. Bash uses bash.rules instead. */
	permissions: FilePermissions;
	bash: BashPolicyConfig;
}

export interface BlockedCommand {
	tool: string;
	reason: string;
	timestamp: number;
}
