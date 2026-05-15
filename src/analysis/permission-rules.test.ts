import { describe, expect, it } from 'vitest';
import { checkPermissionRule, parseRule } from './permission-rules';

// ─── parseRule ───────────────────────────────────────────────────────────────

describe('parseRule', () => {
	it('Write with pattern', () => {
		const result = parseRule('Write(./tmp/**)');
		expect(result).toEqual({
			tool: 'Write',
			pattern: './tmp/**',
			args: undefined,
		});
	});

	it('Read with pattern', () => {
		const result = parseRule('Read(./docs/**)');
		expect(result).toEqual({
			tool: 'Read',
			pattern: './docs/**',
			args: undefined,
		});
	});

	it('Tool with args JSON', () => {
		const result = parseRule('MyTool(args:{"x":1})');
		expect(result).toEqual({ tool: 'MyTool', pattern: '', args: '{"x":1}' });
	});

	it('Bash with command', () => {
		const result = parseRule('Bash(ls -la)');
		expect(result).toEqual({
			tool: 'Bash',
			pattern: 'ls -la',
			args: undefined,
		});
	});

	it('Invalid format returns null', () => {
		expect(parseRule('nope')).toBeNull();
	});
});

// ─── checkPermissionRule ─────────────────────────────────────────────────────

describe('checkPermissionRule', () => {
	it('allow match: Write pattern', () => {
		const result = checkPermissionRule(
			['Write(./tmp/**)'],
			{ toolName: 'write' },
			{ path: './tmp/file.txt' },
		);
		expect(result).toBe('allowed');
	});

	it('deny no match: Write wrong path', () => {
		const result = checkPermissionRule(
			['Write(.env)'],
			{ toolName: 'write' },
			{ path: './src/file.ts' },
		);
		expect(result).toBe('ask');
	});

	it('ask no match: Edit wrong path', () => {
		const result = checkPermissionRule(
			['Edit(./src/**)'],
			{ toolName: 'edit' },
			{ path: './docs/readme.md' },
		);
		expect(result).toBe('ask');
	});

	it('no match: wrong path', () => {
		const result = checkPermissionRule(
			['Write(./tmp/**)'],
			{ toolName: 'write' },
			{ path: './src/file.ts' },
		);
		expect(result).toBe('ask');
	});

	it('args match', () => {
		const result = checkPermissionRule(
			['MyTool(args:{"x":1})'],
			{ toolName: 'myTool' },
			{ x: 1 },
		);
		expect(result).toBe('allowed');
	});

	it('wrong tool name', () => {
		const result = checkPermissionRule(
			['Write(./tmp/**)'],
			{ toolName: 'bash' },
			{ path: './tmp/file' },
		);
		expect(result).toBe('ask');
	});
});

describe('checkPermissionRule — deny', () => {
	it('deny match: Write(.env) blocks', () => {
		const result = checkPermissionRule(
			['Write(.env)'],
			{ toolName: 'write' },
			{ path: '.env' },
			{ deny: true },
		);
		expect(result).toBe('blocked');
	});

	it('deny no match: Write(.env) allows', () => {
		const result = checkPermissionRule(
			['Write(.env)'],
			{ toolName: 'write' },
			{ path: './src/file.ts' },
			{ deny: true },
		);
		expect(result).toBe('ask');
	});

	it('deny with args match', () => {
		const result = checkPermissionRule(
			['MyTool(args:{"x":1})'],
			{ toolName: 'myTool' },
			{ x: 1 },
			{ deny: true },
		);
		expect(result).toBe('blocked');
	});
});
