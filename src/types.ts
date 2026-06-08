export type ApprovalMode =
	| 'full-access'
	| 'read-safe'
	| 'ask-first'
	| 'folder-trusted'
	| 'self-guarded';

export type ShellAnalysis = 'safe' | 'dangerous' | 'pipe-bypass';
export type ShellGuardRuleAction = 'allow' | 'ask' | 'deny';
export type ShellGuardRulePrecedence = 'before-builtin' | 'after-builtin';

// Backwards-compatible names for older imports.
export type BashAnalysis = ShellAnalysis;
export type BashRuleAction = ShellGuardRuleAction;
export type BashRulePrecedence = ShellGuardRulePrecedence;

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

export interface ShellGuardArgMatch {
	includes?: string[];
	includesAny?: string[];
	startsWith?: string[];
	contains?: string[];
}

export interface ShellGuardRedirectionMatch {
	target?: string | string[];
	targetKind?: 'any' | 'null' | 'protected' | 'workspace';
	op?: string | string[];
	write?: boolean;
}

export interface ShellGuardPipelineMatch {
	from?: string | string[];
	to?: string | string[];
}

export interface ShellGuardRuleMatch {
	command?: string | string[];
	commands?: string[];
	args?: ShellGuardArgMatch;
	redirection?: ShellGuardRedirectionMatch;
	pipeline?: ShellGuardPipelineMatch;
	hasExpansion?: boolean;
	hasUnsupportedSyntax?: boolean;
}

export interface ShellGuardRule {
	id?: string;
	action: ShellGuardRuleAction;
	precedence?: ShellGuardRulePrecedence;
	reason?: string;
	match: ShellGuardRuleMatch;
}

export interface ShellGuardPolicyConfig {
	/**
	 * User AST rules. Empty by default.
	 * Rules with precedence="before-builtin" may override the built-in AST policy.
	 */
	rules: ShellGuardRule[];
	/** Decision for unknown commands. Default: ask. */
	unknown: ShellGuardRuleAction;
}

// Backwards-compatible names for older imports.
export type BashArgMatch = ShellGuardArgMatch;
export type BashRedirectionMatch = ShellGuardRedirectionMatch;
export type BashPipelineMatch = ShellGuardPipelineMatch;
export type BashRuleMatch = ShellGuardRuleMatch;
export type BashRule = ShellGuardRule;
export type BashPolicyConfig = ShellGuardPolicyConfig;

export type SelfGuardedChecklistMode = 'always' | 'turn';

export interface SelfGuardedConfig {
	/** always = before each model request; turn = once before each user turn. */
	checklist: SelfGuardedChecklistMode;
}

export interface Config {
	mode: ApprovalMode;
	shortcut: string;
	/** File tool permissions for Pi path tools. Shell commands use shellGuard.rules instead. */
	permissions: FilePermissions;
	shellGuard: ShellGuardPolicyConfig;
	selfGuarded: SelfGuardedConfig;
	/** @deprecated Use shellGuard. Loaded for compatibility with existing settings. */
	bash?: ShellGuardPolicyConfig;
}

export interface BlockedCommand {
	tool: string;
	reason: string;
	timestamp: number;
}
