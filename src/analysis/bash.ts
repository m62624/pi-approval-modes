import type { BashAnalysis, Config } from '../types';
import { getCompiledPatterns } from './patterns';

function splitChain(cmd: string): string[] {
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

		// Check for &&, ||, ;
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

export function analyzeBashCommand(
	command: string,
	config: Config,
): BashAnalysis {
	command = command.trim();

	if (!command) return 'safe';

	// Split by chaining operators (&&, ||, ;) — check each part individually
	const chainParts = splitChain(command);
	if (chainParts.length > 1) {
		for (const part of chainParts) {
			const partAnalysis = analyzeBashCommand(part, config);
			if (partAnalysis === 'dangerous') return 'dangerous';
			if (partAnalysis === 'pipe-bypass') return 'pipe-bypass';
		}
		return 'safe';
	}

	// Pipe analysis
	const pipeParts = command.split('|').map((s) => s.trim());
	if (pipeParts.length > 1) {
		// Check each pipe part individually
		for (const part of pipeParts) {
			const tool = part.trim().split(/\s+/)[0];

			// base64 decode in pipe
			if (tool === 'base64') {
				const args = part.trim().split(/\s+/).slice(1);
				if (args.includes('-d') || args.includes('--decode')) {
					return 'pipe-bypass';
				}
			}

			// tee in pipe — always ask
			if (tool === 'tee') {
				return 'pipe-bypass';
			}

			// Check each part against deny/ask patterns
			const partAnalysis = analyzeBashCommand(part, config);
			if (partAnalysis === 'dangerous') return 'dangerous';
			if (partAnalysis === 'pipe-bypass') return 'pipe-bypass';
		}
	}

	const { deny, ask, allow } = getCompiledPatterns(config.permissions);

	// 1. deny
	for (const re of deny) {
		if (re.test(command)) return 'dangerous';
	}

	// 2. ask
	for (const re of ask) {
		if (re.test(command)) return 'pipe-bypass';
	}

	// 3. allow
	for (const re of allow) {
		if (re.test(command)) return 'safe';
	}

	// 4. default — ask
	return 'pipe-bypass';
}
