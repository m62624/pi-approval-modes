import { describe, expect, it } from 'vitest';
import { parseShell } from './shell-ast';

describe('parseShell', () => {
	it('parses a simple command and args', () => {
		const ast = parseShell('git status --short');
		expect(ast.commands).toHaveLength(1);
		expect(ast.commands[0].words.map((word) => word.text)).toEqual([
			'git',
			'status',
			'--short',
		]);
		expect(ast.unsupported).toBe(false);
	});

	it('preserves quoted text as one word', () => {
		const ast = parseShell('grep "hello world" file.txt');
		expect(ast.commands[0].words.map((word) => word.text)).toEqual([
			'grep',
			'hello world',
			'file.txt',
		]);
	});

	it('marks double-quoted shell expansion', () => {
		const ast = parseShell('echo "$(whoami)"');
		expect(ast.commands[0].words[1].hasExpansion).toBe(true);
	});

	it('keeps escaped command characters normalized', () => {
		const ast = parseShell('r\\m -rf /');
		expect(ast.commands[0].words[0]).toEqual({
			text: 'rm',
			raw: 'r\\m',
			hasExpansion: false,
		});
	});

	it('parses safe null redirection', () => {
		const ast = parseShell('find . -name "*.ts" 2>/dev/null');
		expect(ast.commands[0].redirections).toEqual([
			{
				op: '2>',
				target: { text: '/dev/null', raw: '/dev/null', hasExpansion: false },
			},
		]);
	});

	it('parses pipelines as operators between command nodes', () => {
		const ast = parseShell('cat file | grep foo | wc -l');
		expect(ast.operators).toEqual(['|', '|']);
		expect(ast.commands.map((command) => command.words[0].text)).toEqual([
			'cat',
			'grep',
			'wc',
		]);
	});

	it('marks heredoc as unsupported syntax', () => {
		const ast = parseShell('cat <<EOF');
		expect(ast.unsupported).toBe(true);
	});
});
