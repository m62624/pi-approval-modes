import { describe, expect, it } from 'vitest';
import {
	DEFAULT_SHORTCUT_ID,
	parseShortcut,
	resolveShortcut,
} from './shortcut';

describe('shortcut parsing', () => {
	it('parses configured modifier shortcuts', () => {
		expect(parseShortcut('ctrl+shift+f8')).toBe('ctrl+shift+f8');
		expect(parseShortcut('ctrl+alt+a')).toBe('ctrl+alt+a');
		expect(parseShortcut('shift+tab')).toBe('shift+tab');
	});

	it('normalizes key names', () => {
		expect(parseShortcut('ctrl+pageup')).toBe('ctrl+pageUp');
		expect(parseShortcut(' CTRL + SHIFT + F8 ')).toBe('ctrl+shift+f8');
	});

	it('rejects invalid shortcuts and falls back to default', () => {
		expect(parseShortcut('ctrl+ctrl+a')).toBeNull();
		expect(parseShortcut('wat')).toBeNull();
		expect(resolveShortcut('wat')).toBe(DEFAULT_SHORTCUT_ID);
		expect(resolveShortcut(undefined)).toBe(DEFAULT_SHORTCUT_ID);
	});
});
