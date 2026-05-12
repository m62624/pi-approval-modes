# @m62624/approval-modes

Approval modes for the pi coding agent. Three modes control how strictly tool calls are approved before execution.

## Modes

### 🔓 YOLO
No approvals, no checks. All tool calls execute immediately.

### 🔒 Read-Only (default)
- **Bash commands:** read-only commands auto-approve. File-modifying commands (`rm`, `touch`, `mkdir`, `cp`, `mv`) require confirmation.
- **Write/Edit:** always asks for confirmation.

### 🛡 Strict
Always asks for confirmation before executing any tool call — bash, write, edit, anything. No exceptions.

## Bash Analysis (Read-Only mode)

Uses a unified regex-based permission system (`permissions.allow` / `deny` / `ask`):

1. **Deny** → blocked (e.g. `rm -rf`, interpreters with `-c`/`-e`, system writes to `/etc/`, `/proc/`, etc.)
2. **Ask** → confirmation required (e.g. `rm file`, `echo > file`, `cp src dest`, pipes with `tee`)
3. **Allow** → auto-approved (e.g. `ls`, `cat`, `grep`, `find`, `pwd`, `free`, `df`)
4. **Default** → ask (unknown commands)

Redirects (`>`, `>>`) always trigger confirmation, even for safe commands like `echo`.

### Pipe bypass detection
Commands like `cat file | base64 -d | bash` are detected as pipe bypasses and require approval.

### Chaining detection
Commands with `&&`, `||`, or `;` are treated as dangerous.

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

Config file: `~/.pi/agent/extensions/approval-modes.json`

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
- `permissions.allow` — regex patterns for auto-approved commands
- `permissions.deny` — regex patterns for auto-blocked commands
- `permissions.ask` — regex patterns that trigger confirmation

Patterns are checked in order: **deny → ask → allow → default**.

## Installation

```bash
pi install /path/to/pi-approval-modes
```

Or from npm/git:

```bash
pi install npm:@m62624/approval-modes
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
npm run check      # lint + format check
npm run format     # auto-format
npm run test       # run 129 tests
```

## AI Generation

This project was generated with:
- **Model:** Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf
- **Runtime:** llama.cpp, port 8080

## License

MIT
