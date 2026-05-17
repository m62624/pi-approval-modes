import type { Config, Permissions } from '../types';

export const DEFAULT_PERMISSIONS: Permissions = {
	allow: [
		'^\\s*$',

		// Read-only shell/file inspection.
		'^ls\\b',
		'^cat\\b',
		'^head\\b',
		'^tail\\b',
		'^less\\b',
		'^more\\b',
		'^grep\\b',
		'^rg\\b',
		'^find\\b',
		'^pwd\\b',
		'^whoami\\b',
		'^date\\b',
		'^uname\\b',
		'^hostname\\b',
		'^df\\b',
		'^free\\b',
		'^du\\b',
		'^wc\\b',
		'^sort\\b',
		'^uniq\\b',
		'^cut\\b',
		'^tr\\b',
		'^sed\\b(?!.*\\s-i(?:\\b|[a-zA-Z]))',
		'^awk\\b',
		'^true\\b',
		'^false\\b',
		'^test\\b',
		'^echo\\b',
		'^printf\\b',
		'^base64\\b(?!.*\\s(?:-d|--decode)\\b)',
		'^stat\\b',
		'^file\\b',
		'^which\\b',
		'^where\\b',
		'^whereis\\b',
		'^type\\b',
		'^readlink\\b',
		'^realpath\\b',
		'^dirname\\b',
		'^basename\\b',
		'^env\\b$',

		// Shell-local operations. They do not write project files by themselves.
		'^cd\\b',
		'^export\\b',
		'^alias\\b',
		'^\\[\\s',
		'^\\[\\[',

		// Common read-only development commands.
		'^git\\s+(?:status|diff|log|show|branch|rev-parse|remote\\s+-v)\\b',
		'^python(?:\\d+(?:\\.\\d+)?)?\\s+(?:--version|-V)\\b',
		'^node\\s+(?:--version|-v)\\b',
		'^npm\\s+(?:--version|-v)\\b',
		'^pnpm\\s+(?:--version|-v)\\b',
		'^yarn\\s+(?:--version|-v)\\b',
		'^bun\\s+(?:--version|-v)\\b',
		'^cargo\\s+(?:--version|-V)\\b',
		'^rustc\\s+(?:--version|-V)\\b',
		'^rustup\\s+(?:--version|-V|show)\\b',
	],
	deny: [
		// Privilege escalation and direct system takeover.
		'^\\bsudo\\b',
		'^\\bsu\\b',
		'^\\bdoas\\b',
		'^\\brunas\\b',

		// Disk, partition and filesystem destructive tools.
		'^\\bdd\\b.*\\bof\\s*=\\s*(?:/dev/(?!null\\b)|/|[a-zA-Z]:\\\\|\\\\\\\\\\.\\\\PhysicalDrive)',
		'^\\bmkfs(?:\\.\\w+)?\\b',
		'^\\bfdisk\\b',
		'^\\bparted\\b',
		'^\\bdiskpart\\b',
		'^\\bformat\\b\\s+(?:[a-zA-Z]:|/)',

		// Recursive forced deletion of roots or system directories.
		'^rm\\s+.*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\\s+(?:/|/\\*|~|~/?\\*|/etc(?:/|$)|/root(?:/|$)|/boot(?:/|$)|/sys(?:/|$)|/proc(?:/|$)|/dev/(?!null\\b)|[a-zA-Z]:\\\\(?:$|\\*)|[a-zA-Z]:\\\\Windows(?:\\\\|$))',
		'^rm\\s+.*-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\\s+(?:/|/\\*|~|~/?\\*|/etc(?:/|$)|/root(?:/|$)|/boot(?:/|$)|/sys(?:/|$)|/proc(?:/|$)|/dev/(?!null\\b)|[a-zA-Z]:\\\\(?:$|\\*)|[a-zA-Z]:\\\\Windows(?:\\\\|$))',

		// Writes to protected OS locations. /dev/null and Windows NUL are stripped before matching.
		'(^|\\s)(?:\\d?>|\\d?>>|&>)\\s*(?:/etc(?:/|$)|/root(?:/|$)|/boot(?:/|$)|/sys(?:/|$)|/proc(?:/|$)|/dev/(?!null\\b)|[a-zA-Z]:\\\\Windows(?:\\\\|$)|[a-zA-Z]:\\\\Program Files(?:\\\\|$)|[a-zA-Z]:\\\\ProgramData(?:\\\\|$))',
		'^>\\s*(?:/etc(?:/|$)|/root(?:/|$)|/boot(?:/|$)|/sys(?:/|$)|/proc(?:/|$)|/dev/(?!null\\b))',
		'^>>\\s*(?:/etc(?:/|$)|/root(?:/|$)|/boot(?:/|$)|/sys(?:/|$)|/proc(?:/|$)|/dev/(?!null\\b))',
		'^tee\\b.*\\s(?:/etc(?:/|$)|/root(?:/|$)|/boot(?:/|$)|/sys(?:/|$)|/proc(?:/|$)|/dev/(?!null\\b)|[a-zA-Z]:\\\\Windows(?:\\\\|$))',

		// Remote code directly piped into an interpreter should stay hard-blocked.
		'\\b(?:curl|wget)\\b.*\\|\\s*(?:ba)?sh\\b',
		'\\b(?:curl|wget)\\b.*\\|\\s*(?:python|python3|node|ruby|perl|php)\\b',

		// Classic shell footgun.
		':\\s*\\(\\s*\\)\\s*\\{\\s*:\\s*\\|\\s*:\\s*&\\s*}\\s*;\\s*:',
	],
	ask: [
		// Shell indirection or hidden execution. Ask instead of deny: useful, but not read-only.
		'\\$\\(',
		'`[^`]+`',
		'^\\beval\\b',
		'^\\bexec\\b',
		'^\\bsource\\b',
		'^\\.\\s',
		'^bash\\b',
		'^sh\\b',
		'^zsh\\b',
		'^fish\\b',

		// Inline interpreters are useful for agents, but they can mutate files.
		'^python(?:\\d+(?:\\.\\d+)?)?\\b(?!\\s+(?:--version|-V)\\b)',
		'^node\\b(?!\\s+(?:--version|-v)\\b)',
		'^perl\\b',
		'^ruby\\b',
		'^php\\b',
		'^lua\\b',
		'^deno\\b',
		'^bun\\b(?!\\s+(?:--version|-v)\\b)',

		// Any real file write/append asks. Redirection to /dev/null/NUL is stripped before this check.
		'(^|\\s)(?:\\d?>|\\d?>>|&>)\\s*\\S+',
		'^>\\s*\\S+',
		'^>>\\s*\\S+',
		'^\\|\\s*tee\\b',
		'^tee\\s+\\S+',
		'^echo\\s+.*>\\s+',
		'^printf\\s+.*>\\s+',

		// Mutating filesystem/process commands. Ask, do not hard-block.
		'^find\\b.*\\s-delete\\b',
		'^find\\b.*\\s-exec\\s+',
		'^touch\\s+\\S+',
		'^mkdir\\s+\\S+',
		'^rm\\s+\\S+',
		'^cp\\s+\\S+',
		'^mv\\s+\\S+',
		'^ln\\s+\\S+',
		'^install\\s+\\S+',
		'^chmod\\b',
		'^chown\\b',
		'^chgrp\\b',
		'^kill\\b',
		'^fuser\\b',
		'^pkill\\b',
		'^killall\\b',
		'^shred\\b',

		// Network/remote tools. Often needed, but should be visible to the user.
		'^curl\\b',
		'^wget\\b',
		'^nc\\b',
		'^ncat\\b',
		'^nmap\\b',
		'^ssh\\b',
		'^scp\\b',
		'^sftp\\b',
		'^rsync\\b',

		// Package managers and build tools usually write caches/build artifacts.
		'^git\\b(?!\\s+(?:status|diff|log|show|branch|rev-parse|remote\\s+-v)\\b)',
		'^npm\\b(?!\\s+(?:--version|-v)\\b)',
		'^pnpm\\b(?!\\s+(?:--version|-v)\\b)',
		'^yarn\\b(?!\\s+(?:--version|-v)\\b)',
		'^cargo\\b(?!\\s+(?:--version|-V)\\b)',
		'^rustup\\b(?!\\s+(?:--version|-V|show)\\b)',
		'^go\\b',
		'^make\\b',
		'^cmake\\b',
	],
};

export const DEFAULT_CONFIG: Config = {
	mode: 'read-only',
	shortcut: 'shift+tab',
	permissions: { ...DEFAULT_PERMISSIONS },
};
