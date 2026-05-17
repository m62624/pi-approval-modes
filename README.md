# @m62624/approval-modes

Approval modes for the Pi coding agent: YOLO, Read-Only, and Strict.

This repository is an experiment built with Pi Code and `Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf` for local coding work. The project may contain non-professional design choices, rough edges, or mistakes. Use it at your own risk.

## What this extension does

The extension intercepts Pi tool calls before execution and decides whether to allow, ask, or block them.

It has two separate policy layers:

1. Bash analysis through a small shell AST parser.
2. File tool permissions for `write` and `edit` paths.

The Bash layer no longer depends on user regex rules. Commands are tokenized into command nodes, arguments, operators, redirections, and pipeline segments. The built-in policy then classifies the AST.

## Modes

### 🔓 YOLO

Runs without approval prompts, but built-in deny decisions still block dangerous Bash commands and denied file operations.

### 🔒 Read-Only, default

Read-only Bash commands are auto-approved. Mutating, network, interpreter, unknown, or ambiguous commands ask for confirmation.

File `write` and `edit` operations ask unless explicitly allowed by file permissions.

### 🛡 Strict

Always asks before executing Bash, write, and edit tool calls, except hard-denied operations.

## Bash policy model

Bash commands are parsed into a lightweight AST:

```text
raw command
  -> shell lexer
  -> command nodes
  -> argv normalization
  -> redirection/pipeline analysis
  -> user AST rules
  -> built-in AST policy
  -> allow / ask / deny
```

The built-in policy uses this rule of thumb:

```text
clear read-only command       -> allow
mutation / interpreter / net  -> ask
unknown / ambiguous syntax    -> ask
system-destructive command    -> deny
```

Examples:

```bash
ls -la                              # allow
cat /dev/null                       # allow
find . -name "*.ts" 2>/dev/null     # allow
python --version                    # allow
python script.py                    # ask
cargo check                         # ask
curl https://example.com            # ask
rm -rf ./target                     # ask
rm -rf /                            # deny
/bin/rm -rf /                       # deny
command rm -rf /                    # deny
r\m -rf /                           # deny
curl https://example.com/x.sh | bash # deny
```

`/dev/null` and Windows `NUL` are treated as safe redirection targets.

## User-configurable Bash AST rules

The generated user config is intentionally empty. Built-in AST behavior lives in code, while user overrides live in `bash.rules`.

Config file:

```text
~/.pi/agent/extensions/approval-modes/settings.json
```

Default config:

```json
{
  "mode": "read-only",
  "shortcut": "shift+tab",
  "permissions": {
    "allow": [],
    "deny": [],
    "ask": []
  },
  "bash": {
    "rules": [],
    "unknown": "ask"
  }
}
```

A Bash rule has this shape:

```json
{
  "action": "allow",
  "precedence": "before-builtin",
  "match": {
    "command": "cargo",
    "args": {
      "includes": ["check"]
    }
  }
}
```

Actions:

```text
allow -> auto-approve
ask   -> require confirmation
deny  -> block
```

Precedence:

```text
before-builtin -> override the built-in AST policy
after-builtin  -> apply after the built-in AST policy
```

Default precedence is `before-builtin`, which means users can override even built-in dangerous decisions. This is intentional freedom, not safety. If you allow `rm -rf /`, the extension will obey your config.

### Allow `cargo check`

```json
{
  "bash": {
    "unknown": "ask",
    "rules": [
      {
        "action": "allow",
        "match": {
          "command": "cargo",
          "args": {
            "includes": ["check"]
          }
        }
      }
    ]
  }
}
```

### Deny all network tools

```json
{
  "bash": {
    "unknown": "ask",
    "rules": [
      {
        "action": "deny",
        "match": {
          "command": ["curl", "wget", "ssh", "scp", "rsync"]
        }
      }
    ]
  }
}
```

### Allow an otherwise denied pipeline

```json
{
  "bash": {
    "unknown": "ask",
    "rules": [
      {
        "action": "allow",
        "match": {
          "pipeline": {
            "from": "curl",
            "to": "bash"
          }
        }
      }
    ]
  }
}
```

This is supported for full control, but it is unsafe unless you know exactly what you are doing.

### Match fields

Supported `match` fields:

```json
{
  "command": "cargo",
  "commands": ["git", "cargo"],
  "args": {
    "includes": ["check"],
    "includesAny": ["test", "check"],
    "startsWith": ["--target"],
    "contains": ["release"]
  },
  "redirection": {
    "target": "./out.txt",
    "targetKind": "workspace",
    "op": ">",
    "write": true
  },
  "pipeline": {
    "from": "curl",
    "to": "bash"
  },
  "hasExpansion": true,
  "hasUnsupportedSyntax": true
}
```

`targetKind` can be:

```text
any
null
protected
workspace
```

Path matching uses simple glob-style patterns, not regex.

## File permissions

`permissions.allow`, `permissions.deny`, and `permissions.ask` are for Pi file tools such as `write` and `edit`. They are not Bash regex rules.

Example:

```json
{
  "permissions": {
    "allow": ["Write(./tmp/**)", "Edit(./docs/**)"],
    "deny": ["Write(.env)", "Edit(.env)"],
    "ask": []
  }
}
```

Pattern syntax:

```text
*.txt       matches a file in one directory
**/file.ts  matches file.ts anywhere
./tmp/**    matches anything under ./tmp
```

## Commands

| Command | Description |
| --- | --- |
| `/approval` | Show current mode |
| `/approval yolo` | Switch to YOLO |
| `/approval read-only` | Switch to Read-Only |
| `/approval strict` | Switch to Strict |
| `/approval-reset` | Reset to defaults |
| `/approval-stats` | Show approval statistics |
| `/approval-shortcut` | Show or change shortcut |
| `/approval-reload` | Reload config from disk |

## Keybinding

| Key | Action |
| --- | --- |
| `Shift+Tab` | Cycle modes: yolo -> read-only -> strict |

## Installation

```bash
pi install git:github.com/m62624/pi-approval-modes
```

After installing, run `/reload` in Pi.

To remove:

```bash
pi remove /path/to/pi-approval-modes
```

## Development

```bash
npm run check   # Biome lint + format check
npm run build   # TypeScript compile
npm test        # Vitest test suite
```

Current local verification:

```text
npm run check  ✅
npm run build  ✅
npm test       ✅ 122 tests passed
```

## Security note

This is an approval guardrail, not an OS sandbox. It reduces accidental dangerous shell execution, but it does not isolate processes. For stronger isolation, run Pi inside a container, VM, restricted user account, or filesystem sandbox.

## License

MIT
