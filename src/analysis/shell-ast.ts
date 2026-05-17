export type ShellOperator = '&&' | '||' | ';' | '|';

export interface ShellWord {
	text: string;
	raw: string;
	hasExpansion: boolean;
}

export interface ShellRedirection {
	op: string;
	target?: ShellWord;
}

export interface ShellCommandNode {
	kind: 'command';
	words: ShellWord[];
	redirections: ShellRedirection[];
}

export interface ShellSequenceNode {
	kind: 'sequence';
	commands: ShellCommandNode[];
	operators: ShellOperator[];
	unsupported: boolean;
	raw: string;
}

type Token =
	| { kind: 'word'; word: ShellWord }
	| { kind: 'op'; value: ShellOperator }
	| { kind: 'redir'; value: string };

function isWhitespace(ch: string): boolean {
	return ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r';
}

function isOperatorStart(ch: string): boolean {
	return ch === '&' || ch === '|' || ch === ';';
}

function isRedirectionStart(ch: string): boolean {
	return ch === '<' || ch === '>';
}

function startsWithRedirection(input: string, index: number): string | null {
	const rest = input.slice(index);
	const match = rest.match(
		/^(?:\d*)?(?:<<<|<<|&>>|&>|\d*<&\d+|\d*>&\d+|>>|>|<)/,
	);
	return match?.[0] ?? null;
}

function readQuoted(
	input: string,
	index: number,
	quote: string,
): { value: string; raw: string; end: number; hasExpansion: boolean } {
	let value = '';
	let raw = quote;
	let i = index + 1;
	let hasExpansion = false;

	while (i < input.length) {
		const ch = input[i];
		raw += ch;

		if (ch === quote) {
			return { value, raw, end: i + 1, hasExpansion };
		}

		if (quote === '"' && ch === '\\' && i + 1 < input.length) {
			const next = input[i + 1];
			raw += next;
			value += next;
			i += 2;
			continue;
		}

		if (quote === '"' && (ch === '`' || ch === '$')) {
			hasExpansion = true;
		}

		value += ch;
		i++;
	}

	return { value, raw, end: i, hasExpansion: true };
}

function readWord(
	input: string,
	index: number,
): { word: ShellWord; end: number } {
	let value = '';
	let raw = '';
	let i = index;
	let hasExpansion = false;

	while (i < input.length) {
		const ch = input[i];
		if (isWhitespace(ch) || isOperatorStart(ch) || isRedirectionStart(ch))
			break;

		if (ch === "'" || ch === '"') {
			const quoted = readQuoted(input, i, ch);
			value += quoted.value;
			raw += quoted.raw;
			hasExpansion ||= quoted.hasExpansion;
			i = quoted.end;
			continue;
		}

		if (ch === '\\' && i + 1 < input.length) {
			value += input[i + 1];
			raw += input.slice(i, i + 2);
			i += 2;
			continue;
		}

		if (ch === '`' || ch === '$' || ch === '~') {
			hasExpansion = true;
		}

		value += ch;
		raw += ch;
		i++;
	}

	return { word: { text: value, raw, hasExpansion }, end: i };
}

function lex(input: string): { tokens: Token[]; unsupported: boolean } {
	const tokens: Token[] = [];
	let unsupported = false;
	let i = 0;
	let atTokenStart = true;

	while (i < input.length) {
		const ch = input[i];
		if (isWhitespace(ch)) {
			atTokenStart = true;
			i++;
			continue;
		}

		if (atTokenStart && ch === '#') break;

		if (ch === '&' && input[i + 1] === '&') {
			tokens.push({ kind: 'op', value: '&&' });
			i += 2;
			atTokenStart = true;
			continue;
		}
		if (ch === '|' && input[i + 1] === '|') {
			tokens.push({ kind: 'op', value: '||' });
			i += 2;
			atTokenStart = true;
			continue;
		}
		if (ch === '|') {
			tokens.push({ kind: 'op', value: '|' });
			i++;
			atTokenStart = true;
			continue;
		}
		if (ch === ';') {
			tokens.push({ kind: 'op', value: ';' });
			i++;
			atTokenStart = true;
			continue;
		}

		const redirection = startsWithRedirection(input, i);
		if (redirection) {
			if (redirection.includes('<<')) unsupported = true;
			tokens.push({ kind: 'redir', value: redirection });
			i += redirection.length;
			atTokenStart = true;
			continue;
		}

		const word = readWord(input, i);
		if (!word.word.text && !word.word.raw) {
			unsupported = true;
			i++;
			continue;
		}
		tokens.push({ kind: 'word', word: word.word });
		i = word.end;
		atTokenStart = false;
	}

	return { tokens, unsupported };
}

function looksLikeProcessSubstitution(redirection: ShellRedirection): boolean {
	return !!redirection.target?.raw.startsWith('(');
}

export function parseShell(input: string): ShellSequenceNode {
	const raw = input.trim();
	const { tokens, unsupported } = lex(raw);
	const commands: ShellCommandNode[] = [];
	const operators: ShellOperator[] = [];
	let current: ShellCommandNode = {
		kind: 'command',
		words: [],
		redirections: [],
	};
	let ambiguous = unsupported;

	function flushCommand(): void {
		if (current.words.length > 0 || current.redirections.length > 0) {
			commands.push(current);
		}
		current = { kind: 'command', words: [], redirections: [] };
	}

	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i];
		if (token.kind === 'op') {
			flushCommand();
			operators.push(token.value);
			continue;
		}

		if (token.kind === 'redir') {
			const next = tokens[i + 1];
			const redirection: ShellRedirection = { op: token.value };
			if (next?.kind === 'word') {
				redirection.target = next.word;
				current.redirections.push(redirection);
				if (looksLikeProcessSubstitution(redirection)) ambiguous = true;
				i++;
			} else if (/&\d+$/.test(token.value)) {
				current.redirections.push(redirection);
			} else {
				current.redirections.push(redirection);
				ambiguous = true;
			}
			continue;
		}

		current.words.push(token.word);
	}
	flushCommand();

	if (operators.length > Math.max(0, commands.length - 1)) ambiguous = true;

	return { kind: 'sequence', commands, operators, unsupported: ambiguous, raw };
}
