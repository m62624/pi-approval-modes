import type { Permissions } from '../types';

function compilePatterns(patterns: string[]): RegExp[] {
	return patterns.map((p) => new RegExp(p));
}

let cachedAllow: RegExp[] = [];
let cachedDeny: RegExp[] = [];
let cachedAsk: RegExp[] = [];

export function getCompiledPatterns(permissions: Permissions): {
	allow: RegExp[];
	deny: RegExp[];
	ask: RegExp[];
} {
	if (
		cachedAllow.length === permissions.allow.length &&
		cachedDeny.length === permissions.deny.length &&
		cachedAsk.length === permissions.ask.length
	) {
		return { allow: cachedAllow, deny: cachedDeny, ask: cachedAsk };
	}
	cachedAllow = compilePatterns(permissions.allow);
	cachedDeny = compilePatterns(permissions.deny);
	cachedAsk = compilePatterns(permissions.ask);
	return { allow: cachedAllow, deny: cachedDeny, ask: cachedAsk };
}

export function resetPatternCache(): void {
	cachedAllow = [];
	cachedDeny = [];
	cachedAsk = [];
}
