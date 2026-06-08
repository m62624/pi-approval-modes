import { describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG } from '../config/schema';
import {
	buildSelfGuardedContextMessages,
	buildSelfGuardedSystemPrompt,
} from './self-guarded-prompt';

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

	it('adds one fresh checklist message for context mode', () => {
		const first = buildSelfGuardedContextMessages({
			messages: [
				{ role: 'user', content: 'Do work', timestamp: 1 },
				{
					role: 'user',
					content: 'stale checklist',
					timestamp: 2,
					customType: 'approval-self-guarded-checklist',
				} as never,
			],
			cwd: '/repo/app',
			config: { ...DEFAULT_CONFIG, mode: 'self-guarded' },
		});

		expect(first).toHaveLength(2);
		expect(first[1]).toMatchObject({
			role: 'user',
			customType: 'approval-self-guarded-checklist',
		});
		expect(JSON.stringify(first[1])).toContain('before each model request');
		expect(JSON.stringify(first[1])).toContain('/repo/app');
	});
});
