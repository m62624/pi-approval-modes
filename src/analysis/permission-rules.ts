import { isPathPattern } from '../path-pattern';
import type { PatternRule } from '../types';

export function parseRule(rule: string): PatternRule | null {
	const match = rule.match(/^(\w+)\((.+)\)$/);
	if (!match) return null;
	const [, tool, rest] = match;
	if (rest.startsWith('args:')) {
		return { tool, pattern: '', args: rest.slice(5) };
	}
	return { tool, pattern: rest, args: undefined };
}

export function checkPermissionRule(
	rules: string[],
	event: { toolName: string },
	input: Record<string, unknown>,
	options?: { deny?: boolean },
): 'allowed' | 'blocked' | 'ask' {
	for (const ruleStr of rules) {
		try {
			const rule = parseRule(ruleStr);
			if (!rule) continue;
			if (rule.tool.toLowerCase() !== event.toolName.toLowerCase()) continue;
			if (rule.args) {
				const inputStr = JSON.stringify(input);
				if (inputStr.includes(rule.args.slice(1, -1)))
					return options?.deny ? 'blocked' : 'allowed';
				continue;
			}
			const filePath = input.path as string | undefined;
			if (filePath && isPathPattern(rule.pattern, filePath))
				return options?.deny ? 'blocked' : 'allowed';
		} catch (e) {
			console.error(
				`[approval-modes] Error checking permission rule: ${e instanceof Error ? e.message : String(e)}`,
			);
		}
	}
	return 'ask';
}
