import { isPathPattern } from '../path-pattern';
import type {
	BashAnalysis,
	BashPipelineMatch,
	BashPolicyConfig,
	BashRedirectionMatch,
	BashRule,
	BashRuleAction,
	BashRuleMatch,
	Config,
} from '../types';
import type {
	ShellCommandNode,
	ShellRedirection,
	ShellSequenceNode,
	ShellWord,
} from './shell-ast';
import { parseShell } from './shell-ast';

const READ_ONLY_COMMANDS = new Set([
	'',
	'ls',
	'cat',
	'head',
	'tail',
	'less',
	'more',
	'grep',
	'rg',
	'find',
	'pwd',
	'whoami',
	'date',
	'uname',
	'hostname',
	'df',
	'free',
	'du',
	'wc',
	'sort',
	'uniq',
	'cut',
	'tr',
	'sed',
	'awk',
	'true',
	'false',
	'test',
	'echo',
	'printf',
	'sleep',
	'stat',
	'file',
	'which',
	'where',
	'whereis',
	'type',
	'readlink',
	'realpath',
	'dirname',
	'basename',
	'cd',
	'export',
	'alias',
	'env',
]);

const INTERPRETERS = new Set([
	'python',
	'python2',
	'python3',
	'node',
	'perl',
	'ruby',
	'php',
	'lua',
	'deno',
	'bun',
]);

const SHELLS = new Set([
	'bash',
	'sh',
	'zsh',
	'fish',
	'powershell',
	'pwsh',
	'cmd',
]);

const NETWORK_TOOLS = new Set([
	'curl',
	'wget',
	'nc',
	'ncat',
	'nmap',
	'ssh',
	'scp',
	'sftp',
	'rsync',
]);

const PACKAGE_AND_BUILD_TOOLS = new Set([
	'npm',
	'pnpm',
	'yarn',
	'cargo',
	'rustup',
	'go',
	'make',
	'cmake',
	'bun',
]);

const MUTATING_TOOLS = new Set([
	'touch',
	'mkdir',
	'rm',
	'cp',
	'mv',
	'ln',
	'install',
	'chmod',
	'chown',
	'chgrp',
	'kill',
	'fuser',
	'pkill',
	'killall',
	'shred',
	'del',
	'erase',
	'rmdir',
	'rd',
]);

const PRIVILEGE_TOOLS = new Set(['sudo', 'su', 'doas', 'runas']);
const DISK_TOOLS = new Set(['mkfs', 'fdisk', 'parted', 'diskpart', 'format']);
const WRAPPERS = new Set(['command', 'builtin', 'nohup', 'time']);
const DEFAULT_RUNTIME_POLICY: BashPolicyConfig = { rules: [], unknown: 'ask' };

interface NormalizedCommand {
	command: string;
	args: string[];
	words: ShellWord[];
}

function toAnalysis(action: BashRuleAction): BashAnalysis {
	switch (action) {
		case 'allow':
			return 'safe';
		case 'ask':
			return 'pipe-bypass';
		case 'deny':
			return 'dangerous';
	}
}

function mergeAnalysis(
	current: BashAnalysis,
	next: BashAnalysis,
): BashAnalysis {
	if (current === 'dangerous' || next === 'dangerous') return 'dangerous';
	if (current === 'pipe-bypass' || next === 'pipe-bypass') return 'pipe-bypass';
	return 'safe';
}

function asArray<T>(value: T | T[] | undefined): T[] {
	if (value === undefined) return [];
	return Array.isArray(value) ? value : [value];
}

function basename(command: string): string {
	const normalized = command.replace(/\\/g, '/');
	const base = normalized.slice(normalized.lastIndexOf('/') + 1);
	return base.toLowerCase().replace(/\.(?:exe|cmd|bat|ps1)$/i, '');
}

function isAssignment(word: string): boolean {
	const eq = word.indexOf('=');
	if (eq <= 0) return false;
	const name = word.slice(0, eq);
	return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name);
}

function normalizePath(path: string): string {
	return path
		.trim()
		.replace(/^['"]|['"]$/g, '')
		.replace(/\\/g, '/')
		.replace(/^([a-zA-Z]):(?!\/)/, '$1:/')
		.replace(/\/+/g, '/')
		.toLowerCase();
}

function isNullDevice(path: string): boolean {
	const p = normalizePath(path);
	return p === '/dev/null' || p === 'nul' || p === '//./nul';
}

function isProtectedPath(path: string): boolean {
	if (isNullDevice(path)) return false;
	const p = normalizePath(path);
	if (p === '/' || p === '/*' || p === '~' || p === '~/*') return true;
	if (/^[a-z]:\/?(?:\*?)$/i.test(p)) return true;
	if (/^\/dev\/(?!null(?:$|\/))/.test(p)) return true;
	if (/^\.?physicaldrive\d*/i.test(p.replace(/[/\\]/g, ''))) return true;
	return [
		'/etc',
		'/root',
		'/boot',
		'/sys',
		'/proc',
		'/usr',
		'/bin',
		'/sbin',
		'/lib',
		'/lib64',
		'c:/windows',
		'c:/program files',
		'c:/programdata',
		'//./physicaldrive',
	].some((prefix) => {
		if (prefix === '//./physicaldrive') {
			return p === prefix || /^\/\/\.\/physicaldrive\d/i.test(p);
		}
		return p === prefix || p.startsWith(`${prefix}/`);
	});
}

function isSensitiveReadPath(path: string): boolean {
	const p = normalizePath(path);
	return (
		p === '.env' ||
		p.endsWith('/.env') ||
		p === '.npmrc' ||
		p.endsWith('/.npmrc') ||
		p === '.pypirc' ||
		p.endsWith('/.pypirc') ||
		p.includes('/.ssh/') ||
		p.endsWith('/.ssh') ||
		p.includes('/.gnupg/') ||
		p.endsWith('/.gnupg') ||
		p.includes('/id_rsa') ||
		p.includes('/id_ed25519')
	);
}

function isWriteRedirection(redirection: ShellRedirection): boolean {
	return redirection.op.includes('>');
}

function isReadRedirection(redirection: ShellRedirection): boolean {
	return redirection.op.includes('<');
}

function isFdDup(redirection: ShellRedirection): boolean {
	return /&\d+$/.test(redirection.op) && !redirection.target;
}

function stripEnvPrefix(words: ShellWord[]): ShellWord[] {
	let index = 0;
	while (index < words.length && isAssignment(words[index].text)) index++;

	if (basename(words[index]?.text ?? '') !== 'env') return words.slice(index);
	index++;

	while (index < words.length) {
		const text = words[index].text;
		if (isAssignment(text)) {
			index++;
			continue;
		}
		if (text === '-i' || text === '--ignore-environment') {
			index++;
			continue;
		}
		if (text.startsWith('-')) {
			index++;
			continue;
		}
		break;
	}
	return words.slice(index);
}

function shellArgText(word: ShellWord): string {
	if (/^[A-Za-z]:\\/.test(word.raw) || word.raw.startsWith('\\\\.\\')) {
		return word.raw;
	}
	return word.text;
}

function unwrapCommand(words: ShellWord[]): NormalizedCommand {
	let rest = stripEnvPrefix(words);
	while (rest.length > 0 && WRAPPERS.has(basename(rest[0].text))) {
		rest = rest.slice(1);
	}
	const command = basename(rest[0]?.text ?? '');
	return {
		command,
		args: rest.slice(1).map(shellArgText),
		words: rest,
	};
}

function commandHasExpansion(command: ShellCommandNode): boolean {
	return (
		command.words.some((word) => word.hasExpansion) ||
		command.redirections.some((redir) => redir.target?.hasExpansion)
	);
}

function positionalArgs(args: string[]): string[] {
	return args.filter((arg) => !arg.startsWith('-'));
}

function lastPositionalArg(args: string[]): string | undefined {
	const items = positionalArgs(args);
	return items[items.length - 1];
}

function hasOption(args: string[], names: string[]): boolean {
	return args.some((arg) => names.includes(arg));
}

function hasShortFlag(args: string[], flag: string): boolean {
	return args.some((arg) => /^-[A-Za-z]+$/.test(arg) && arg.includes(flag));
}

function isVersionOnly(command: string, args: string[]): boolean {
	if (args.length !== 1) return false;
	const versionFlags =
		command === 'node' ||
		command === 'npm' ||
		command === 'pnpm' ||
		command === 'yarn' ||
		command === 'bun'
			? ['--version', '-v']
			: ['--version', '-V'];
	return versionFlags.includes(args[0]);
}

function isReadOnlyGit(args: string[]): boolean {
	const subcommand = args[0];
	if (!subcommand) return false;
	if (subcommand === 'remote') return args[1] === '-v';
	return ['status', 'diff', 'log', 'show', 'branch', 'rev-parse'].includes(
		subcommand,
	);
}

function isReadOnlyRustup(args: string[]): boolean {
	return isVersionOnly('rustup', args) || args[0] === 'show';
}

function isRecursiveForceRm(args: string[]): boolean {
	const hasRecursive = args.some(
		(arg) =>
			arg === '-r' ||
			arg === '-R' ||
			arg === '--recursive' ||
			/^-[A-Za-z]*[rR][A-Za-z]*$/.test(arg),
	);
	const hasForce = args.some(
		(arg) =>
			arg === '-f' || arg === '--force' || /^-[A-Za-z]*f[A-Za-z]*$/.test(arg),
	);
	return hasRecursive && hasForce;
}

function analyzeRedirections(command: ShellCommandNode): BashAnalysis {
	let result: BashAnalysis = 'safe';
	for (const redirection of command.redirections) {
		if (isFdDup(redirection)) continue;
		if (redirection.op.includes('<<')) {
			result = mergeAnalysis(result, 'pipe-bypass');
			continue;
		}
		if (!redirection.target) {
			result = mergeAnalysis(result, 'pipe-bypass');
			continue;
		}

		const target = shellArgText(redirection.target);
		if (isNullDevice(target)) continue;
		if (isWriteRedirection(redirection) && isProtectedPath(target)) {
			return 'dangerous';
		}
		if (isWriteRedirection(redirection)) {
			result = mergeAnalysis(result, 'pipe-bypass');
		}
		if (isReadRedirection(redirection) && isSensitiveReadPath(target)) {
			result = mergeAnalysis(result, 'pipe-bypass');
		}
	}
	return result;
}

function analyzeDd(args: string[]): BashAnalysis {
	const output = args.find((arg) => arg.startsWith('of='));
	if (!output) return 'pipe-bypass';
	return isProtectedPath(output.slice(3)) ? 'dangerous' : 'pipe-bypass';
}

function analyzeTee(args: string[]): BashAnalysis {
	const targets = args.filter((arg) => !arg.startsWith('-'));
	if (targets.some(isProtectedPath)) return 'dangerous';
	return targets.length > 0 ? 'pipe-bypass' : 'safe';
}

function analyzeRm(args: string[]): BashAnalysis {
	const targets = positionalArgs(args);
	if (targets.some(isProtectedPath)) return 'dangerous';
	if (
		isRecursiveForceRm(args) &&
		targets.some((target) => normalizePath(target) === '.')
	) {
		return 'dangerous';
	}
	return 'pipe-bypass';
}

function analyzeMutatingCommand(command: string, args: string[]): BashAnalysis {
	if (command === 'rm' || command === 'del' || command === 'erase') {
		return analyzeRm(args);
	}
	if (command === 'mv' && positionalArgs(args).some(isProtectedPath)) {
		return 'dangerous';
	}
	if (['chmod', 'chown', 'chgrp', 'shred', 'rmdir', 'rd'].includes(command)) {
		return positionalArgs(args).some(isProtectedPath)
			? 'dangerous'
			: 'pipe-bypass';
	}
	const target = lastPositionalArg(args);
	if (target && isProtectedPath(target)) return 'dangerous';
	return 'pipe-bypass';
}

function analyzeReadOnlyCommandArgs(
	command: string,
	args: string[],
): BashAnalysis {
	if (
		command === 'find' &&
		(args.includes('-delete') || args.includes('-exec'))
	) {
		return 'pipe-bypass';
	}
	if (
		command === 'sed' &&
		(hasOption(args, ['-i', '--in-place']) || hasShortFlag(args, 'i'))
	) {
		return 'pipe-bypass';
	}
	if (command === 'base64' && hasOption(args, ['-d', '--decode'])) {
		return 'pipe-bypass';
	}
	if (args.some(isSensitiveReadPath)) return 'pipe-bypass';
	return 'safe';
}

function analyzeXargs(args: string[]): BashAnalysis {
	const commandIndex = args.findIndex((arg) => !arg.startsWith('-'));
	if (commandIndex < 0) return 'pipe-bypass';
	const nested = args.slice(commandIndex);
	const command = basename(nested[0]);
	if (command === 'rm' && analyzeRm(nested.slice(1)) === 'dangerous') {
		return 'dangerous';
	}
	return 'pipe-bypass';
}

function analyzeBuiltinCommand(commandNode: ShellCommandNode): BashAnalysis {
	const redirectionResult = analyzeRedirections(commandNode);
	if (redirectionResult === 'dangerous') return 'dangerous';
	if (commandHasExpansion(commandNode)) return 'pipe-bypass';
	if (commandNode.words.length === 0) return redirectionResult;

	const { command, args } = unwrapCommand(commandNode.words);
	if (!command) return redirectionResult;

	if (PRIVILEGE_TOOLS.has(command)) return 'dangerous';
	if (DISK_TOOLS.has(command) || command.startsWith('mkfs.'))
		return 'dangerous';
	if (command === 'dd') return analyzeDd(args);
	if (command === 'tee')
		return mergeAnalysis(redirectionResult, analyzeTee(args));
	if (command === 'xargs') return analyzeXargs(args);
	if (MUTATING_TOOLS.has(command)) {
		return mergeAnalysis(
			redirectionResult,
			analyzeMutatingCommand(command, args),
		);
	}

	if (
		command === '.' ||
		command === 'source' ||
		command === 'eval' ||
		command === 'exec'
	) {
		return 'pipe-bypass';
	}
	if (SHELLS.has(command)) return 'pipe-bypass';
	if (INTERPRETERS.has(command)) {
		return isVersionOnly(command, args) ? redirectionResult : 'pipe-bypass';
	}
	if (NETWORK_TOOLS.has(command)) return 'pipe-bypass';
	if (command === 'git') {
		return isReadOnlyGit(args) ? redirectionResult : 'pipe-bypass';
	}
	if (command === 'rustup') {
		return isReadOnlyRustup(args) ? redirectionResult : 'pipe-bypass';
	}
	if (PACKAGE_AND_BUILD_TOOLS.has(command)) {
		return isVersionOnly(command, args) ? redirectionResult : 'pipe-bypass';
	}
	if (command === 'rustc') {
		return isVersionOnly(command, args) ? redirectionResult : 'pipe-bypass';
	}
	if (READ_ONLY_COMMANDS.has(command)) {
		return mergeAnalysis(
			redirectionResult,
			analyzeReadOnlyCommandArgs(command, args),
		);
	}
	return 'pipe-bypass';
}

function commandName(commandNode: ShellCommandNode): string {
	return unwrapCommand(commandNode.words).command;
}

function isNetworkCommand(commandNode: ShellCommandNode): boolean {
	return NETWORK_TOOLS.has(commandName(commandNode));
}

function isInterpreterOrShell(commandNode: ShellCommandNode): boolean {
	const command = commandName(commandNode);
	return INTERPRETERS.has(command) || SHELLS.has(command);
}

function hasRemoteCodePipe(ast: ShellSequenceNode): boolean {
	for (let i = 0; i < ast.operators.length; i++) {
		if (ast.operators[i] !== '|') continue;
		const left = ast.commands[i];
		const right = ast.commands[i + 1];
		if (
			left &&
			right &&
			isNetworkCommand(left) &&
			isInterpreterOrShell(right)
		) {
			return true;
		}
	}
	return false;
}

function hasForkBombShape(command: string): boolean {
	return /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*}\s*;\s*:/.test(command);
}

function matchesString(
	value: string,
	expected: string | string[] | undefined,
): boolean {
	const expectedValues = asArray(expected).map((item) => item.toLowerCase());
	return (
		expectedValues.length === 0 || expectedValues.includes(value.toLowerCase())
	);
}

function pathMatches(
	path: string,
	patterns: string | string[] | undefined,
): boolean {
	const normalized = normalizePath(path);
	const patternList = asArray(patterns);
	if (patternList.length === 0) return true;
	return patternList.some((pattern) => {
		const normalizedPattern = normalizePath(pattern);
		return (
			normalized === normalizedPattern ||
			isPathPattern(normalizedPattern, normalized) ||
			isPathPattern(pattern, path)
		);
	});
}

function matchesArgs(args: string[], rule: BashRuleMatch['args']): boolean {
	if (!rule) return true;
	if (rule.includes && !rule.includes.every((arg) => args.includes(arg))) {
		return false;
	}
	if (rule.includesAny && !rule.includesAny.some((arg) => args.includes(arg))) {
		return false;
	}
	if (
		rule.startsWith &&
		!rule.startsWith.every((prefix) =>
			args.some((arg) => arg.startsWith(prefix)),
		)
	) {
		return false;
	}
	if (
		rule.contains &&
		!rule.contains.every((needle) => args.some((arg) => arg.includes(needle)))
	) {
		return false;
	}
	return true;
}

function matchesTargetKind(
	target: string,
	kind: BashRedirectionMatch['targetKind'],
): boolean {
	if (!kind || kind === 'any') return true;
	if (kind === 'null') return isNullDevice(target);
	if (kind === 'protected') return isProtectedPath(target);
	return !isProtectedPath(target) && !isNullDevice(target);
}

function matchesRedirection(
	redirections: ShellRedirection[],
	rule: BashRedirectionMatch | undefined,
): boolean {
	if (!rule) return true;
	return redirections.some((redirection) => {
		if (!matchesString(redirection.op, rule.op)) return false;
		if (
			rule.write !== undefined &&
			isWriteRedirection(redirection) !== rule.write
		) {
			return false;
		}
		if (!redirection.target)
			return rule.target === undefined && !rule.targetKind;
		return (
			matchesTargetKind(redirection.target.text, rule.targetKind) &&
			pathMatches(redirection.target.text, rule.target)
		);
	});
}

function matchesPipeline(
	ast: ShellSequenceNode,
	pipeline: BashPipelineMatch,
): boolean {
	for (let i = 0; i < ast.operators.length; i++) {
		if (ast.operators[i] !== '|') continue;
		const left = ast.commands[i];
		const right = ast.commands[i + 1];
		if (!left || !right) continue;
		if (
			matchesString(commandName(left), pipeline.from) &&
			matchesString(commandName(right), pipeline.to)
		) {
			return true;
		}
	}
	return false;
}

function matchesCommandNode(
	commandNode: ShellCommandNode,
	match: BashRuleMatch,
): boolean {
	const normalized = unwrapCommand(commandNode.words);
	if (!matchesString(normalized.command, match.command)) return false;
	if (!matchesArgs(normalized.args, match.args)) return false;
	if (!matchesRedirection(commandNode.redirections, match.redirection))
		return false;
	if (
		match.hasExpansion !== undefined &&
		commandHasExpansion(commandNode) !== match.hasExpansion
	) {
		return false;
	}
	return true;
}

function ruleHasCommandScope(match: BashRuleMatch): boolean {
	return (
		match.command !== undefined ||
		match.args !== undefined ||
		match.redirection !== undefined ||
		match.hasExpansion !== undefined
	);
}

function matchesRule(ast: ShellSequenceNode, rule: BashRule): boolean {
	const match = rule.match;
	if (
		match.hasUnsupportedSyntax !== undefined &&
		ast.unsupported !== match.hasUnsupportedSyntax
	) {
		return false;
	}
	if (match.commands) {
		const commandNames = ast.commands.map(commandName);
		if (!match.commands.every((command) => commandNames.includes(command))) {
			return false;
		}
	}
	if (match.pipeline && !matchesPipeline(ast, match.pipeline)) return false;
	if (ruleHasCommandScope(match)) {
		return ast.commands.some((commandNode) =>
			matchesCommandNode(commandNode, match),
		);
	}
	return true;
}

function matchesRuleForCommand(
	commandNode: ShellCommandNode,
	rule: BashRule,
): boolean {
	const match = rule.match;
	if (
		match.pipeline ||
		match.commands ||
		match.hasUnsupportedSyntax !== undefined
	) {
		return false;
	}
	return ruleHasCommandScope(match) && matchesCommandNode(commandNode, match);
}

function ruleHasSequenceScope(rule: BashRule): boolean {
	return (
		rule.match.pipeline !== undefined ||
		rule.match.commands !== undefined ||
		rule.match.hasUnsupportedSyntax !== undefined
	);
}

function findSequenceRule(
	ast: ShellSequenceNode,
	policy: BashPolicyConfig,
	precedence: 'before-builtin' | 'after-builtin',
): BashRule | undefined {
	return policy.rules.find(
		(rule) =>
			ruleHasSequenceScope(rule) &&
			(rule.precedence ?? 'before-builtin') === precedence &&
			matchesRule(ast, rule),
	);
}

function findCommandRule(
	commandNode: ShellCommandNode,
	policy: BashPolicyConfig,
	precedence: 'before-builtin' | 'after-builtin',
): BashRule | undefined {
	return policy.rules.find(
		(rule) =>
			(rule.precedence ?? 'before-builtin') === precedence &&
			matchesRuleForCommand(commandNode, rule),
	);
}

function isKnownCommand(command: string): boolean {
	return (
		READ_ONLY_COMMANDS.has(command) ||
		INTERPRETERS.has(command) ||
		SHELLS.has(command) ||
		NETWORK_TOOLS.has(command) ||
		PACKAGE_AND_BUILD_TOOLS.has(command) ||
		MUTATING_TOOLS.has(command) ||
		PRIVILEGE_TOOLS.has(command) ||
		DISK_TOOLS.has(command) ||
		command === 'dd' ||
		command === 'tee' ||
		command === 'xargs' ||
		command === 'git' ||
		command === 'rustc' ||
		command === 'source' ||
		command === 'eval' ||
		command === 'exec' ||
		command === '.' ||
		command.startsWith('mkfs.')
	);
}

function analyzeCommandNode(
	commandNode: ShellCommandNode,
	policy: BashPolicyConfig,
): BashAnalysis {
	const beforeRule = findCommandRule(commandNode, policy, 'before-builtin');
	if (beforeRule) return toAnalysis(beforeRule.action);

	const builtin = analyzeBuiltinCommand(commandNode);

	const afterRule = findCommandRule(commandNode, policy, 'after-builtin');
	if (afterRule) return toAnalysis(afterRule.action);

	const { command } = unwrapCommand(commandNode.words);
	if (command && !isKnownCommand(command)) return toAnalysis(policy.unknown);
	return builtin;
}

export function analyzeBashCommand(
	command: string,
	config: Config,
): BashAnalysis {
	const trimmed = command.trim();
	if (!trimmed) return 'safe';

	const ast = parseShell(trimmed);
	const policy = config.bash ?? DEFAULT_RUNTIME_POLICY;

	const beforeRule = findSequenceRule(ast, policy, 'before-builtin');
	if (beforeRule) return toAnalysis(beforeRule.action);

	if (hasForkBombShape(trimmed)) return 'dangerous';
	if (hasRemoteCodePipe(ast)) return 'dangerous';

	let result: BashAnalysis = ast.unsupported ? 'pipe-bypass' : 'safe';
	for (const commandNode of ast.commands) {
		result = mergeAnalysis(result, analyzeCommandNode(commandNode, policy));
		if (result === 'dangerous') return result;
	}

	const afterRule = findSequenceRule(ast, policy, 'after-builtin');
	if (afterRule) return toAnalysis(afterRule.action);

	return result;
}

export type {
	ShellCommandNode,
	ShellRedirection,
	ShellSequenceNode,
	ShellWord,
} from './shell-ast';
export { parseShell } from './shell-ast';
