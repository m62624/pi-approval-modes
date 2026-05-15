import type { BashAnalysis, Config } from '../types';
import { getCompiledPatterns } from './patterns';

export function analyzeBashCommand(
	command: string,
	config: Config,
): BashAnalysis {
	command = command.trim();

	if (!command) return 'safe';

	// Chaining operators: always dangerous
	if (/\|\|/.test(command) || /&&/.test(command) || /;/.test(command)) {
		return 'dangerous';
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
