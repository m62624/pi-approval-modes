import type { AgentMessage } from '@earendil-works/pi-agent-core';
import type { Config } from '../types';

const MAX_RULES_IN_PROMPT = 20;
const SELF_GUARDED_CONTEXT_MARKER = 'approval-self-guarded-checklist';

export function buildSelfGuardedSystemPrompt(input: {
	basePrompt: string;
	config: Config;
	cwd: string;
}): string {
	return `${input.basePrompt}

${buildSelfGuardedChecklist({
	config: input.config,
	cwd: input.cwd,
	mode: 'turn',
})}`;
}

export function buildSelfGuardedContextMessages(input: {
	messages: AgentMessage[];
	config: Config;
	cwd: string;
}): AgentMessage[] {
	return [
		...input.messages.filter(
			(message) =>
				(message as AgentMessage & { customType?: string }).customType !==
				SELF_GUARDED_CONTEXT_MARKER,
		),
		{
			role: 'user',
			content: buildSelfGuardedChecklist({
				config: input.config,
				cwd: input.cwd,
				mode: 'always',
			}),
			timestamp: Date.now(),
			customType: SELF_GUARDED_CONTEXT_MARKER,
		} as AgentMessage,
	];
}

function buildSelfGuardedChecklist(input: {
	config: Config;
	cwd: string;
	mode: 'always' | 'turn';
}): string {
	const timing =
		input.mode === 'always'
			? 'This checklist is refreshed before each model request, right before you decide whether to call tools.'
			: 'This checklist is attached once for the current user turn.';
	return `
## Approval Self Guard

The approval extension is running in self-guarded mode. ${timing} Before every tool call, run this checklist internally and proceed only when the answer is clear.

Current trusted working directory:
\`${input.cwd}\`

Checklist:
- Is this tool call directly required for the user's current task?
- Does the tool call stay inside the trusted working directory when it reads, searches, writes, edits, or lists paths?
- For shell commands, is the command read-only, deterministic, and free of shell expansion, scripts, interpreters, package runners, network access, privilege escalation, raw disk access, and destructive filesystem operations?
- For edits and writes, is the target path in scope for the requested task and not a secret, credential, generated cache, dependency directory, OS path, or unrelated file?
- For custom tools, can you explain exactly what external state the tool may read or mutate?
- Does the call comply with the user-configured deny and ask rules below?
- If any answer is uncertain, ask the user instead of assuming approval.

User-configured rules visible to this mode:
${formatConfigForPrompt(input.config)}

Runtime behavior:
- User-configured deny rules and built-in hard-deny shell rules are blocked.
- Clearly safe shell calls and allowed in-scope path calls may run without a prompt.
- Ambiguous shell calls, out-of-directory path calls, custom tools without an allow rule, and any configured ask rule require user approval.
`;
}

function formatConfigForPrompt(config: Config): string {
	const lines = [
		`- mode: ${config.mode}`,
		`- permissions.deny: ${formatList(config.permissions.deny)}`,
		`- permissions.ask: ${formatList(config.permissions.ask)}`,
		`- permissions.allow: ${formatList(config.permissions.allow)}`,
		`- shellGuard.unknown: ${config.shellGuard.unknown}`,
		`- shellGuard.rules: ${formatShellRules(config)}`,
	];
	return lines.join('\n');
}

function formatList(values: string[]): string {
	if (values.length === 0) return '(none)';
	return values.slice(0, MAX_RULES_IN_PROMPT).join(', ');
}

function formatShellRules(config: Config): string {
	if (config.shellGuard.rules.length === 0) return '(none)';
	return config.shellGuard.rules
		.slice(0, MAX_RULES_IN_PROMPT)
		.map((rule) =>
			JSON.stringify({
				id: rule.id,
				action: rule.action,
				precedence: rule.precedence,
				match: rule.match,
			}),
		)
		.join('\n  ');
}
