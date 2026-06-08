import { describe, expect, it } from 'vitest';
import { isPathInsideRoot } from './path-scope';

describe('isPathInsideRoot', () => {
	it('accepts cwd and descendants', () => {
		expect(isPathInsideRoot('/repo/app', undefined, '/repo/app')).toBe(true);
		expect(isPathInsideRoot('/repo/app', 'src/index.ts', '/repo/app')).toBe(
			true,
		);
		expect(
			isPathInsideRoot('/repo/app', '/repo/app/src/index.ts', '/tmp'),
		).toBe(true);
	});

	it('rejects parent and sibling paths', () => {
		expect(isPathInsideRoot('/repo/app', '../secret.txt', '/repo/app')).toBe(
			false,
		);
		expect(
			isPathInsideRoot('/repo/app', '/repo/other/file.ts', '/repo/app'),
		).toBe(false);
	});
});
