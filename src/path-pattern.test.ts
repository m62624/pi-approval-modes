import { describe, expect, it } from 'vitest';
import { isPathPattern } from './path-pattern';

describe('isPathPattern', () => {
	it('exact match', () => {
		expect(isPathPattern('file.txt', 'file.txt')).toBe(true);
	});

	it('single star matches without slash', () => {
		expect(isPathPattern('*.txt', 'file.txt')).toBe(true);
	});

	it('single star does not match slash', () => {
		expect(isPathPattern('*.txt', 'dir/file.txt')).toBe(false);
	});

	it('double star matches path', () => {
		expect(isPathPattern('**/file.txt', 'dir/file.txt')).toBe(true);
	});

	it('double star matches root', () => {
		expect(isPathPattern('**/file.txt', 'file.txt')).toBe(true);
	});

	it('escape special characters', () => {
		expect(isPathPattern('file+.txt', 'file+.txt')).toBe(true);
	});

	it('partial non-match', () => {
		expect(isPathPattern('*.txt', 'file.js')).toBe(false);
	});
});
