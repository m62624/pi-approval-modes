# pi-approval-modes

Approval modes for the pi coding agent. Three modes with bash safe-list and permission rules.

## Modes

- **YOLO** — no approvals, no checks
- **Approved** — bash safe-list + ask for write/edit
- **Strict** — pattern-based allow/deny/ask

## Switching

- **Shift+Tab** — cycle modes
- **Alt+Q** — thinking level (was Shift+Tab)
- `/approval` — show current mode
- `/approval <yolo|approved|strict>` — switch mode
- `/approval-reset` — reset to defaults

## Config

`~/.pi/agent/extensions/approval-modes.json`:

```json
{
  "mode": "approved",
  "permissions": {
    "allow": [],
    "ask": [],
    "deny": []
  },
  "bashSafeList": ["cat", "grep", "ls", "find", ...],
  "bashDangerous": ["python", "bash", "node", "sudo", ...]
}
```

## Install

```bash
pi install git:github.com/badlogic/pi-approval-modes
```

Or copy `approval-modes.ts` to `~/.pi/agent/extensions/`.

## License

MIT
