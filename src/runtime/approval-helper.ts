import { getAgentDir } from '@earendil-works/pi-coding-agent';
import { createConfigPaths } from '../config/paths';
import { DEFAULT_CONFIG } from '../config/schema';
import { EXTENSION_NAME } from '../constants';
import { MODES } from '../mode';

export function buildApprovalHelperText(input?: { agentDir?: string }): string {
	const paths = createConfigPaths({
		agentDir: input?.agentDir ?? getAgentDir(),
		cwd: process.cwd(),
		extensionName: EXTENSION_NAME,
	});

	return [
		'# Approval Modes Helper',
		'',
		'Modes:',
		'- full-access: auto-allow most calls; hard deny rules still block.',
		'- read-safe: default; auto-allow safe shell reads, ask before mutations and ambiguous shell.',
		'- folder-trusted: auto-allow path tools and safe shell reads only inside current cwd.',
		'- self-guarded: inject a model checklist; runtime asks on uncertain calls.',
		'- ask-first: ask before shell, write, and edit unless deny rules block.',
		'',
		'Commands:',
		'- /approval: pick a mode.',
		`- /approval <mode>: switch directly. Modes: ${MODES.join(', ')}.`,
		'- /approval-reset: confirm, then reset the whole settings file to factory defaults.',
		'',
		'Config:',
		`- settings: ${paths.settings}`,
		`- default shortcut: ${DEFAULT_CONFIG.shortcut}`,
		'- edit "shortcut" in settings.json, then run /reload.',
		'- use "permissions" for tool/path allow, ask, deny rules.',
		'- use "shellGuard" for shell AST rules and unknown-command policy.',
	].join('\n');
}
