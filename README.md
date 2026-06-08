> ⚠️ This repository is an experiment built with Pi Code and Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf for local coding work. It is maintained with local AI assistance and may contain non-professional design choices, rough edges, broken behavior, or mistakes. Use it at your own risk.

# Pi Approval Modes 🛡️

`pi-approval-modes` is an experimental [Pi Code](https://github.com/badlogic/pi-mono) extension that adds approval policies for built-in Pi tool calls.

It watches shell execution, path tools, and selected custom tool calls before they run. Depending on the active mode, the extension allows the call, asks the user, or blocks it through deterministic deny rules.

Install it directly from GitHub:

```bash
pi install git:github.com/m62624/pi-approval-modes
```

Then run:

```text
/reload
```

## What It Guards 🔍

The extension has two policy layers:

1. `shellGuard`: a small shell AST policy for Pi's `bash` tool.
2. `permissions`: path and argument rules for Pi tools such as `read`, `write`, `edit`, `grep`, `find`, `ls`, and custom tools.

The shell guard is shell-agnostic. Pi still calls the built-in tool `bash`, but the policy handles shell commands, scripts, interpreters, package runners, pipelines, redirections, and suspicious syntax as a general shell guard.

## Modes 🎛️

| Mode | Purpose |
| --- | --- |
| `full-access` | Auto-allow most tool calls. Built-in hard-deny shell decisions and configured deny rules still block. |
| `read-safe` | Default. Auto-allow clearly read-only shell commands. Ask before mutations, network, interpreters, package runners, unknown commands, and file writes/edits. |
| `folder-trusted` | Auto-allow path tools and read-only shell commands only when they stay inside the current Pi `cwd`. Ask outside `cwd` and for scripts, launchers, package runners, network, interpreters, and ambiguous shell. |
| `self-guarded` | Inject a checklist into the system prompt so the model self-evaluates tool calls. Runtime still blocks deny rules and asks the user on uncertain calls. |
| `ask-first` | Ask before shell, `write`, and `edit` calls unless a deny rule blocks first. |

Legacy mode names are still accepted:

```text
yolo      -> full-access
read-only -> read-safe
strict    -> ask-first
approved  -> read-safe
safe      -> read-safe
```

## User Commands ⌨️

| Command | Purpose |
| --- | --- |
| `/approval` | Open a TUI picker for all approval modes. |
| `/approval <mode>` | Switch directly to a mode or legacy alias. |
| `/approval-helper` | Show a compact modes and config helper. |
| `/approval-reset` | Confirm, then reset the whole settings file to factory defaults. |
| `/approval-stats` | Show approved and blocked counts for the session. |
| `/approval-reload` | Reload extension settings from disk. |

## Keybinding 🎚️

Default mode-cycle shortcut:

```text
alt+m
```

This avoids Pi's built-in default bindings while staying simple enough for most terminals. To change it, edit `shortcut` in the extension settings file and run `/reload`.

Pi keybindings can also be customized globally in:

```text
~/.pi/agent/keybindings.json
```

After editing keybindings, run `/reload`.

## Config 🧩

Config file:

```text
~/.pi/agent/extensions/approval-modes/settings.json
```

Default config:

```json
{
  "mode": "read-safe",
  "shortcut": "alt+m",
  "permissions": {
    "allow": [],
    "deny": [],
    "ask": []
  },
  "shellGuard": {
    "rules": [],
    "unknown": "ask"
  }
}
```

Older configs using `bash` instead of `shellGuard` still load. New configs are written with `shellGuard`.

## Shell Guard 🧠

Shell commands are parsed into a lightweight AST:

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

Built-in rule of thumb:

```text
clear read-only command       -> allow
mutation / interpreter / net  -> ask
unknown / ambiguous syntax    -> ask
system-destructive command    -> deny
```

Examples:

```bash
ls -la                               # allow
cat /dev/null                        # allow
find . -name "*.ts" 2>/dev/null      # allow
python --version                     # allow
python script.py                     # ask
cargo check                          # ask
curl https://example.com             # ask
rm -rf ./target                      # ask
rm -rf /                             # deny
/bin/rm -rf /                        # deny
command rm -rf /                     # deny
curl https://example.com/x.sh | bash # deny
```

`/dev/null` and Windows `NUL` are treated as safe redirection targets.

## Shell Guard Rules 📜

A shell guard rule has this shape:

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

Default precedence is `before-builtin`, which means users can override built-in dangerous decisions. This is intentional freedom, not safety. If you allow `rm -rf /`, the extension will obey your config.

Allow `cargo check`:

```json
{
  "shellGuard": {
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

Deny network tools:

```json
{
  "shellGuard": {
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

Allow an otherwise denied pipeline:

```json
{
  "shellGuard": {
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

`targetKind` values:

```text
any
null
protected
workspace
```

## Permission Rules 📁

`permissions.allow`, `permissions.deny`, and `permissions.ask` use Pi-style tool patterns:

```json
{
  "permissions": {
    "allow": ["Write(./tmp/**)", "Edit(./docs/**)", "Read(./src/**)"],
    "deny": ["Write(.env)", "Edit(.env)", "Read(.env)"],
    "ask": ["Bash(args:\"npm test\")"]
  }
}
```

Pattern syntax:

```text
*.txt       matches a file in one directory
**/file.ts  matches file.ts anywhere
./tmp/**    matches anything under ./tmp
```

## Self-Guarded Mode 🤖

`self-guarded` appends a checklist to the system prompt before each agent turn. The checklist tells the model to evaluate task relevance, cwd scope, shell risk, custom tool effects, configured deny/ask/allow rules, and uncertainty before calling a tool.

Runtime behavior in this mode:

- configured deny rules block;
- built-in hard-deny shell rules block;
- safe shell calls and allowed in-cwd path calls run;
- ambiguous shell, out-of-cwd path calls, custom tools without allow rules, and configured ask rules ask the user.

This mode reduces approval noise only when the model follows the checklist. It is not a sandbox.

## Development 🧪

```bash
npm run check   # Biome lint + format check
npm run build   # TypeScript compile
npm test        # Vitest test suite
```

## Security Note 🔐

This is an approval guardrail, not an OS sandbox. It reduces accidental dangerous tool execution, but it does not isolate processes. For stronger isolation, run Pi inside a container, VM, restricted user account, or filesystem sandbox.

## License

MIT
