import { describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG } from '../config/schema';
import { buildSelfGuardedSystemPrompt } from './self-guarded-prompt';

describe('buildSelfGuardedSystemPrompt', () => {
	it('adds cwd and configured guard rules to the system prompt', () => {
		const prompt = buildSelfGuardedSystemPrompt({
			basePrompt: 'Base prompt.',
			cwd: '/repo/app',
			config: {
				...DEFAULT_CONFIG,
				mode: 'self-guarded',
				permissions: {
					allow: ['Read(src/**)'],
					ask: ['Write(src/**)'],
					deny: ['Write(.env)'],
				},
				shellGuard: {
					unknown: 'ask',
					rules: [
						{
							id: 'deny-network',
							action: 'deny',
							match: { command: ['curl', 'wget'] },
						},
					],
				},
			},
		});

		expect(prompt).toContain('Base prompt.');
		expect(prompt).toContain('Approval Self Guard');
		expect(prompt).toContain('/repo/app');
		expect(prompt).toContain('Write(.env)');
		expect(prompt).toContain('deny-network');
		expect(prompt).toContain('If any answer is uncertain, ask the user');
	});
});
