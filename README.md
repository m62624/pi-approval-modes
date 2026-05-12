# @m62624/approval-modes

Approval modes for the pi coding agent. Three modes control how strictly tool calls are approved before execution.

## Modes

### 🔓 YOLO
No approvals, no checks. All tool calls execute immediately.

### 🔒 Approved (default)
- **Bash commands:** read-only commands auto-approve. File-modifying commands (`rm`, `touch`, `mkdir`, `cp`, `mv`) require confirmation.
- **Write/Edit:** always asks for confirmation.

### 🛡 Strict
Always asks for confirmation before executing any tool call — bash, write, edit, anything. No exceptions.

## Bash Analysis (Approved mode)

### Safe list (auto-approved)
Read-only / information commands execute without approval:
`cat`, `head`, `tail`, `less`, `more`, `grep`, `find`, `ls`, `pwd`, `whoami`, `date`, `uname`, `hostname`, `df`, `free`, `du`, `wc`, `sort`, `uniq`, `cut`, `tr`, `tee`, `true`, `false`, `test`, `echo`, `base64`, `stat`, `file`, `which`, `type`, `readlink`, `realpath`, `dirname`, `basename`

### File-modifying commands (require approval)
`rm`, `touch`, `mkdir`, `cp`, `mv` — these modify the filesystem and require confirmation.

### Dangerous commands (blocked or requires approval)
These are always flagged:
`python`, `python3`, `bash`, `sh`, `zsh`, `node`, `perl`, `ruby`, `php`, `lua`, `osascript`, `env`, `sudo`, `pwsh`, `chmod`, `chown`

### Flag detection
Specific dangerous flag patterns trigger approval:
`rm -rf` / `rm -fr`, `cp -r`

### Pipe bypass detection
Commands like `cat file | base64 -d | bash` are detected as pipe bypasses and require approval.

### Chaining detection
Commands with `&&`, `||`, or `;` require approval.

## Commands

| Command | Description |
|---------|-------------|
| `/approval` | Show current mode |
| `/approval yolo` | Switch to YOLO |
| `/approval approved` | Switch to Approved |
| `/approval strict` | Switch to Strict |
| `/approval-reset` | Reset to defaults |
| `/approval-stats` | Show approval statistics (approved/blocked/total) |
| `/approval-shortcut` | Show or change shortcut (e.g. `/approval-shortcut ctrl+shift+a`) |

## Keybindings

| Key | Action |
|-----|--------|
| **Shift+Tab** (default) | Cycle modes (yolo → approved → strict) |
| **Alt+Q** | Cycle thinking level |

## Configuration

Config file: `~/.pi/agent/extensions/approval-modes.json`

```json
{
  "mode": "approved",
  "shortcut": "shift+tab",
  "permissions": {
    "allow": [],
    "ask": [],
    "deny": []
  },
  "bashSafeList": [...],
  "bashDangerous": [...]
}
```

- `mode` — current approval mode
- `shortcut` — keybinding to cycle modes (any valid pi shortcut format)
- `permissions.allow` — rules that auto-approve (e.g. `Write(./tmp/**)`)
- `permissions.deny` — rules that auto-block (e.g. `Write(.env)`)
- `bashSafeList` / `bashDangerous` — bash command classification lists

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
npx vitest --run   # run 54 tests
```

## License

MIT
