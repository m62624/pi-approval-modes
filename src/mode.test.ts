import { describe, expect, it } from 'vitest';
import { MODES, resolveMode, tryResolveMode } from './mode';

describe('approval modes', () => {
	it('keeps the configured mode order', () => {
		expect(MODES).toEqual([
			'full-access',
			'read-safe',
			'folder-trusted',
			'self-guarded',
			'ask-first',
		]);
	});

	it('resolves legacy aliases', () => {
		expect(tryResolveMode('yolo')).toBe('full-access');
		expect(tryResolveMode('read-only')).toBe('read-safe');
		expect(tryResolveMode('strict')).toBe('ask-first');
	});

	it('falls back only through resolveMode', () => {
		expect(tryResolveMode('unknown')).toBeNull();
		expect(resolveMode('unknown')).toBe('read-safe');
	});
});
