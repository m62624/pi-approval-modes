import { Key, type KeyId } from '@earendil-works/pi-tui';

const MODIFIERS = new Set(['ctrl', 'shift', 'alt', 'super']);
const SPECIAL_KEYS = new Set([
	'escape',
	'esc',
	'enter',
	'return',
	'tab',
	'space',
	'backspace',
	'delete',
	'insert',
	'clear',
	'home',
	'end',
	'pageup',
	'pagedown',
	'up',
	'down',
	'left',
	'right',
	'f1',
	'f2',
	'f3',
	'f4',
	'f5',
	'f6',
	'f7',
	'f8',
	'f9',
	'f10',
	'f11',
	'f12',
]);
const SYMBOL_KEYS = new Set([
	'`',
	'-',
	'=',
	'[',
	']',
	'\\',
	';',
	"'",
	',',
	'.',
	'/',
	'!',
	'@',
	'#',
	'$',
	'%',
	'^',
	'&',
	'*',
	'(',
	')',
	'_',
	'+',
	'|',
	'~',
	'{',
	'}',
	':',
	'<',
	'>',
	'?',
]);

export const DEFAULT_SHORTCUT_ID: KeyId = Key.alt('m');

export function resolveShortcut(raw: string | undefined): KeyId {
	return parseShortcut(raw) ?? DEFAULT_SHORTCUT_ID;
}

export function parseShortcut(raw: string | undefined): KeyId | null {
	if (!raw) return null;
	const parts = raw
		.toLowerCase()
		.split('+')
		.map((part) => part.trim())
		.filter(Boolean);
	if (parts.length === 0) return null;

	const key = normalizeBaseKey(parts[parts.length - 1]);
	if (!key) return null;

	const modifiers = parts.slice(0, -1);
	if (modifiers.length === 0) return key as KeyId;
	const seen = new Set<string>();
	for (const modifier of modifiers) {
		if (!MODIFIERS.has(modifier) || seen.has(modifier)) return null;
		seen.add(modifier);
	}
	return `${modifiers.join('+')}+${key}` as KeyId;
}

function normalizeBaseKey(raw: string | undefined): string | null {
	if (!raw) return null;
	if (/^[a-z0-9]$/.test(raw)) return raw;
	if (raw === 'pageup') return 'pageUp';
	if (raw === 'pagedown') return 'pageDown';
	if (SPECIAL_KEYS.has(raw)) return raw;
	if (SYMBOL_KEYS.has(raw)) return raw;
	return null;
}
