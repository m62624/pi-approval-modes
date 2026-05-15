import type { Permissions } from '../types';

function compilePatterns(patterns: string[]): RegExp[] {
	return patterns.map((p) => new RegExp(p));
}

function arraysEqual(a: string[], b: string[]): boolean {
	if (a.length !== b.length) return false;
	return a.every((v, i) => v === b[i]);
}

let cachedAllow: RegExp[] = [];
let cachedDeny: RegExp[] = [];
let cachedAsk: RegExp[] = [];
let cachedConfig: Permissions | null = null;

export function getCompiledPatterns(permissions: Permissions): {
	allow: RegExp[];
	deny: RegExp[];
	ask: RegExp[];
} {
	if (
		cachedConfig &&
		arraysEqual(cachedConfig.allow, permissions.allow) &&
		arraysEqual(cachedConfig.deny, permissions.deny) &&
		arraysEqual(cachedConfig.ask, permissions.ask)
	) {
		return { allow: cachedAllow, deny: cachedDeny, ask: cachedAsk };
	}

	cachedConfig = { ...permissions };
	cachedAllow = compilePatterns(permissions.allow);
	cachedDeny = compilePatterns(permissions.deny);
	cachedAsk = compilePatterns(permissions.ask);
	return { allow: cachedAllow, deny: cachedDeny, ask: cachedAsk };
}

export function resetPatternCache(): void {
	cachedAllow = [];
	cachedDeny = [];
	cachedAsk = [];
	cachedConfig = null;
}
