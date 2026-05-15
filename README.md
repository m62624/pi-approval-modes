# @m62624/approval-modes

Approval modes for the pi coding agent. Three modes control how strictly tool calls are approved before execution.

## Modes

### 🔓 YOLO
No approval prompts. Deny rules still block matching bash/write/edit calls.

### 🔒 Read-Only (default)
- **Bash commands:** read-only commands auto-approve. File-modifying commands (`rm`, `touch`, `mkdir`, `cp`, `mv`) require confirmation.
- **Write/Edit:** always asks for confirmation.

### 🛡 Strict
Always asks for confirmation before executing any tool call — bash, write, edit, anything. No exceptions.

## How it works

Two independent systems handle approvals:

### 1. Bash analysis — regex-based

When the agent runs a bash command, it's checked against three regex lists (`permissions.allow` / `deny` / `ask`):

1. **Deny** → blocked (e.g. `rm -rf`, interpreters with `-c`/`-e`, writes to `/etc/`, `/proc/`, etc.)
2. **Ask** → confirmation required (e.g. `rm file`, `echo > file`, `cp src dest`, pipes with `tee`)
3. **Allow** → auto-approved (e.g. `ls`, `cat`, `grep`, `find`, `pwd`, `free`, `df`)
4. **Default** → ask (unknown commands)

Redirects (`>`, `>>`) always trigger confirmation, even for safe commands like `echo`.

Special detection:
- **Pipe bypass:** `cat file | base64 -d | bash` → requires confirmation unless a deny rule matches
- **Chaining/pipes:** `&&`, `||`, `;`, `|` → each command segment is checked, and any deny match blocks the whole command

### 2. File permissions — path patterns

For write/edit tools, rules can use path patterns (gitignore-style):

```json
{
  "permissions": {
    "allow": ["Write(./tmp/**)", "Read(.env)"],
    "deny": ["Write(.env)"]
  }
}
```

Pattern syntax:
- `*.txt` — matches any `.txt` file (no directory crossing)
- `**/file.txt` — matches `file.txt` anywhere in the tree
- `./tmp/**` — matches anything under `./tmp/`

This is a separate system from bash regex — it only applies to `write`/`edit` tool calls. By default, all file operations ask for confirmation.

## Commands

| Command | Description |
|---------|-------------|
| `/approval` | Show current mode |
| `/approval yolo` | Switch to YOLO |
| `/approval read-only` | Switch to Read-Only |
| `/approval strict` | Switch to Strict |
| `/approval-reset` | Reset to defaults |
| `/approval-stats` | Show approval statistics (approved/blocked/total) |
| `/approval-shortcut` | Show or change shortcut (e.g. `/approval-shortcut ctrl+shift+a`) |
| `/approval-reload` | Reload config from disk |

## Keybindings

| Key | Action |
|-----|--------|
| **Shift+Tab** (default) | Cycle modes (yolo → read-only → strict) |

## Configuration

Config file: `~/.pi/agent/extensions/approval-modes/settings.json`

```json
{
  "mode": "read-only",
  "shortcut": "shift+tab",
  "permissions": {
    "allow": ["^ls\\b", "^cat\\b", "^grep\\b", "^find\\b"],
    "deny": ["rm\\s+-[a-z]*[rf][a-z]*[fi]", "\\bsudo\\b", "\\beval\\b"],
    "ask": ["rm\\s+\\S+", ">\\s*[^/]", "tee\\s+\\S+"]
  }
}
```

- `mode` — approval mode (`yolo`, `read-only`, `strict`)
- `shortcut` — keybinding to cycle modes
- `permissions.allow` — regex patterns for auto-approved bash commands
- `permissions.deny` — regex patterns for auto-blocked bash commands
- `permissions.ask` — regex patterns that trigger confirmation

Patterns are checked in order: **deny → ask → allow → default**.

## Installation

```bash
pi install git:github.com/m62624/pi-approval-modes
```

After installing, run `/reload` in the agent to activate.

To remove:

```bash
pi remove /path/to/pi-approval-modes
```

## Development

```bash
cd pi-approval-modes
npm run build      # TypeScript compilation
npm run check      # lint + format check
npm run format     # auto-format
npm run test       # run 137 tests
```

## License

MIT
