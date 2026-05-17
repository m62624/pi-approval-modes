import type { BashAnalysis, Config } from '../types';
import { getCompiledPatterns } from './patterns';

function splitShellSegments(cmd: string): string[] {
	const parts: string[] = [];
	let current = '';
	let i = 0;

	while (i < cmd.length) {
		const ch = cmd[i];

		// Handle quotes — skip over quoted strings.
		if (ch === '"' || ch === "'") {
			const quote = ch;
			current += ch;
			i++;
			while (i < cmd.length && cmd[i] !== quote) {
				if (cmd[i] === '\\') {
					current += cmd[i];
					i++;
				}
				if (i < cmd.length) {
					current += cmd[i];
					i++;
				}
			}
			if (i < cmd.length) {
				current += cmd[i]; // closing quote
				i++;
			}
			continue;
		}

		// Check for &&, ||, ;, |.
		if (ch === '&' && cmd[i + 1] === '&') {
			if (current.trim()) parts.push(current.trim());
			current = '';
			i += 2;
			continue;
		}
		if (ch === '|' && cmd[i + 1] === '|') {
			if (current.trim()) parts.push(current.trim());
			current = '';
			i += 2;
			continue;
		}
		if (ch === '|') {
			if (current.trim()) parts.push(current.trim());
			current = '';
			i++;
			continue;
		}
		if (ch === ';') {
			if (current.trim()) parts.push(current.trim());
			current = '';
			i++;
			continue;
		}

		current += ch;
		i++;
	}

	if (current.trim()) parts.push(current.trim());
	return parts;
}

function testPatterns(patterns: RegExp[], command: string): boolean {
	return patterns.some((re) => {
		re.lastIndex = 0;
		return re.test(command);
	});
}

function stripSafeNullRedirections(command: string): string {
	return (
		command
			// POSIX: >/dev/null, 2>/dev/null, >>/dev/null, &>/dev/null.
			// Windows: >NUL, 2>NUL.
			.replace(
				/(^|\s)(?:\d*>>?|&>|\d*<)\s*(?:['"]?\/dev\/null['"]?|['"]?nul['"]?)(?=\s|$)/gi,
				' ',
			)
			// File descriptor duplication, usually used with a null redirect: 2>&1.
			.replace(/(^|\s)\d*>&\d+(?=\s|$)/g, ' ')
			.replace(/\s+/g, ' ')
			.trim()
	);
}

function analyzeSimpleCommand(command: string, config: Config): BashAnalysis {
	const { deny, ask, allow } = getCompiledPatterns(config.permissions);
	const normalizedCommand = stripSafeNullRedirections(command);

	if (!normalizedCommand) return 'safe';
	if (testPatterns(deny, normalizedCommand)) return 'dangerous';
	if (testPatterns(ask, normalizedCommand)) return 'pipe-bypass';
	if (testPatterns(allow, normalizedCommand)) return 'safe';

	return 'pipe-bypass';
}

export function analyzeBashCommand(
	command: string,
	config: Config,
): BashAnalysis {
	command = command.trim();

	if (!command) return 'safe';

	const normalizedCommand = stripSafeNullRedirections(command);
	if (!normalizedCommand) return 'safe';

	const { deny } = getCompiledPatterns(config.permissions);
	if (testPatterns(deny, normalizedCommand)) return 'dangerous';

	// Split by shell operators and check every executable segment individually.
	const shellParts = splitShellSegments(normalizedCommand);
	if (shellParts.length > 1) {
		let result: BashAnalysis = 'safe';
		for (const part of shellParts) {
			const partAnalysis = analyzeBashCommand(part, config);
			if (partAnalysis === 'dangerous') return 'dangerous';
			if (partAnalysis === 'pipe-bypass') result = 'pipe-bypass';
		}
		return result;
	}

	return analyzeSimpleCommand(normalizedCommand, config);
}
