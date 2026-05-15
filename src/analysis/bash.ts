import type { BashAnalysis, Config } from '../types';
import { getCompiledPatterns } from './patterns';

function splitShellSegments(cmd: string): string[] {
	const parts: string[] = [];
	let current = '';
	let i = 0;

	while (i < cmd.length) {
		const ch = cmd[i];

		// Handle quotes — skip over quoted strings
		if (ch === '"' || ch === "'") {
			const quote = ch;
			current += ch;
			i++;
			while (i < cmd.length && cmd[i] !== quote) {
				if (cmd[i] === '\\') {
					current += cmd[i];
					i++;
				}
				current += cmd[i];
				i++;
			}
			if (i < cmd.length) {
				current += cmd[i]; // closing quote
				i++;
			}
			continue;
		}

		// Check for &&, ||, ;, |
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

function analyzeSimpleCommand(command: string, config: Config): BashAnalysis {
	const { deny, ask, allow } = getCompiledPatterns(config.permissions);

	if (testPatterns(deny, command)) return 'dangerous';
	if (testPatterns(ask, command)) return 'pipe-bypass';
	if (testPatterns(allow, command)) return 'safe';

	return 'pipe-bypass';
}

export function analyzeBashCommand(
	command: string,
	config: Config,
): BashAnalysis {
	command = command.trim();

	if (!command) return 'safe';

	const { deny } = getCompiledPatterns(config.permissions);
	if (testPatterns(deny, command)) return 'dangerous';

	// Split by shell operators and check every executable segment individually.
	const shellParts = splitShellSegments(command);
	if (shellParts.length > 1) {
		let result: BashAnalysis = 'safe';
		for (const part of shellParts) {
			const partAnalysis = analyzeBashCommand(part, config);
			if (partAnalysis === 'dangerous') return 'dangerous';
			if (partAnalysis === 'pipe-bypass') result = 'pipe-bypass';
		}
		return result;
	}

	const tool = command.split(/\s+/)[0];
	if (tool === 'base64') {
		const args = command.split(/\s+/).slice(1);
		if (args.includes('-d') || args.includes('--decode')) {
			return 'pipe-bypass';
		}
	}

	return analyzeSimpleCommand(command, config);
}
