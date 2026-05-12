# @m62624/approval-modes

Approval modes for the pi coding agent. Three modes control how strictly tool calls are approved before execution.

## Modes

### 🔓 YOLO
No approvals, no checks. All tool calls execute immediately.

### 🔒 Approved (default)
- **Bash commands:** safe-list based. Commands on the safe list execute automatically. Anything else requires confirmation.
- **Write/Edit:** always asks for confirmation.

### 🛡 Strict
Always asks for confirmation before executing any tool call — bash, write, edit, anything. No exceptions.

## Bash Analysis (Approved mode)

### Safe list (auto-approved)
These commands execute without approval:
`cat`, `head`, `tail`, `less`, `more`, `grep`, `find`, `ls`, `pwd`, `whoami`, `date`, `uname`, `hostname`, `df`, `free`, `du`, `wc`, `sort`, `uniq`, `cut`, `tr`, `tee`, `true`, `false`, `test`, `touch`, `mkdir`, `cp`, `mv`, `rm`, `echo`, `base64`, `stat`, `file`, `which`, `type`, `readlink`, `realpath`, `dirname`, `basename`

### Dangerous commands (blocked or requires approval)
These are always flagged:
`python`, `python3`, `bash`, `sh`, `zsh`, `node`, `perl`, `ruby`, `php`, `lua`, `osascript`, `env`, `sudo`, `pwsh`, `chmod`, `chown`

### Flag detection
These flags trigger approval even on safe commands:
`-rf`, `-f`, `-r`, `--force`, `--recursive`, `--interactive`

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

## Keybindings

| Key | Action |
|-----|--------|
| **Shift+Tab** | Cycle modes (yolo → approved → strict) |
| **Alt+Q** | Cycle thinking level |

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

## Configuration

After installation, the package is registered in `~/.pi/agent/settings.json`. To remove:

```bash
pi remove /path/to/pi-approval-modes
```

## Development

```bash
cd pi-approval-modes
npx vitest --run   # run 49 tests
```

## License

MIT
