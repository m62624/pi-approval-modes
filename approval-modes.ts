/**
 * Approval modes: YOLO, Approved, Strict.
 *
 * Modes:
 *   YOLO     - no approvals, no checks
 *   Approved - bash safe-list + ask for write/edit
 *   Strict   - always ask
 *
 * Switch: configurable shortcut (default shift+tab)
 * Status shown in footer via ctx.ui.setStatus
 */

import type { ExtensionFactory } from "@earendil-works/pi-coding-agent";
import { join } from "node:path";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

// ─── Types ───────────────────────────────────────────────────────────────────

export type ApprovalMode = "yolo" | "approved" | "strict";

// ─── Config ──────────────────────────────────────────────────────────────────

interface Config {
	mode: ApprovalMode;
	shortcut: string;
	permissions: {
		allow: string[];
		ask: string[];
		deny: string[];
	};
	bashSafeList: string[];
	bashDangerous: string[];
}

const DEFAULT_BASH_SAFE: string[] = [
	"cat", "head", "tail", "less", "more", "grep", "find", "ls", "pwd",
	"whoami", "date", "uname", "hostname", "df", "free", "du", "wc",
	"sort", "uniq", "cut", "tr", "tee", "true", "false", "test",
	"echo", "base64",
	"stat", "file", "which", "type",
	"readlink", "realpath", "dirname", "basename",
];

const DEFAULT_BASH_DANGEROUS: string[] = [
	"python", "python3", "bash", "sh", "zsh", "node", "perl", "ruby",
	"php", "lua", "osascript", "env", "sudo", "pwsh", "chmod", "chown",
];

const DEFAULT_CONFIG: Config = {
	mode: "approved",
	shortcut: "shift+tab",
	permissions: { allow: [], ask: [], deny: [] },
	bashSafeList: [...DEFAULT_BASH_SAFE],
	bashDangerous: [...DEFAULT_BASH_DANGEROUS],
};

// ─── Config I/O ──────────────────────────────────────────────────────────────

export function configPath(): string {
	const home = process.env.HOME || process.env.USERPROFILE || ".";
	return join(home, ".pi", "agent", "extensions", "approval-modes.json");
}

function loadConfigRaw(): Config | null {
	try {
		const p = configPath();
		if (!existsSync(p)) return null;
		const raw = readFileSync(p, "utf-8");
		const loaded = JSON.parse(raw);
		return {
			mode: loaded.mode ?? "approved",
			shortcut: loaded.shortcut ?? "shift+tab",
			permissions: loaded.permissions ?? { allow: [], ask: [], deny: [] },
			bashSafeList: loaded.bashSafeList ?? [...DEFAULT_BASH_SAFE],
			bashDangerous: loaded.bashDangerous ?? [...DEFAULT_BASH_DANGEROUS],
		};
	} catch (e) {
		console.error(`[approval-modes] Failed to load config: ${e instanceof Error ? e.message : String(e)}`);
		return null;
	}
}

function mergeConfig(loaded: Config | null): Config {
	if (loaded) {
		return {
			mode: loaded.mode,
			shortcut: loaded.shortcut ?? "shift+tab",
			permissions: loaded.permissions ?? { allow: [], ask: [], deny: [] },
			bashSafeList: loaded.bashSafeList ?? [...DEFAULT_BASH_SAFE],
			bashDangerous: loaded.bashDangerous ?? [...DEFAULT_BASH_DANGEROUS],
		};
	}
	return { ...DEFAULT_CONFIG, permissions: { ...DEFAULT_CONFIG.permissions }, bashSafeList: [...DEFAULT_BASH_SAFE], bashDangerous: [...DEFAULT_BASH_DANGEROUS] };
}

function saveConfig(cfg: Config) {
	try {
		const p = configPath();
		const fs = require("node:fs");
		fs.mkdirSync(join(p, ".."), { recursive: true });
		writeFileSync(p, JSON.stringify(cfg, null, 2));
	} catch (e) {
		console.error(`[approval-modes] Failed to save config: ${e instanceof Error ? e.message : String(e)}`);
	}
}

function ensureConfigExists(): void {
	const p = configPath();
	if (!existsSync(p)) {
		const fs = require("node:fs");
		fs.mkdirSync(join(p, ".."), { recursive: true });
		writeFileSync(p, JSON.stringify(DEFAULT_CONFIG, null, 2));
	}
}

// ─── Cached config ───────────────────────────────────────────────────────────

let cachedConfig: Config | null = null;

function getConfig(): Config {
	if (cachedConfig) return cachedConfig;
	cachedConfig = mergeConfig(loadConfigRaw());
	return cachedConfig;
}

function reloadConfig(): void {
	cachedConfig = mergeConfig(loadConfigRaw());
}

// ─── Pattern helpers ─────────────────────────────────────────────────────────

export function isGitignorePattern(pattern: string, pathStr: string): boolean {
	if (pattern.startsWith("**/")) {
		const rest = pattern.slice(3);
		if (isGitignorePattern(rest, pathStr)) return true;
		const slashIdx = pathStr.indexOf("/");
		if (slashIdx > 0) {
			return isGitignorePattern(rest, pathStr.slice(slashIdx + 1));
		}
		return false;
	}
	let regex = pattern
		.replace(/[.+?^${}()|[\]\\]/g, "\\$&")
		.replace(/\*\*/g, "\x00")
		.replace(/\*/g, "[^/]*")
		.replace(/\x00/g, ".*");
	return new RegExp(`^${regex}$`).test(pathStr);
}

// ─── Bash command analysis ───────────────────────────────────────────────────

export type BashAnalysis = "safe" | "dangerous" | "pipe-bypass";

export function analyzeBashCommand(command: string, config: Config): BashAnalysis {
	command = command.trim();

	// Chaining operators: always dangerous
	if (/\|\|/.test(command) || /\&\&/.test(command) || /;/.test(command)) {
		return "dangerous";
	}

	// Pipe analysis
	const pipeParts = command.split("|").map(s => s.trim());
	if (pipeParts.length > 1) {
		// Last command in pipe is dangerous → pipe-bypass
		const lastCmd = pipeParts[pipeParts.length - 1].trim();
		const lastTool = lastCmd.split(/\s+/)[0];
		if (isDangerousCommand(lastTool, config)) {
			return "pipe-bypass";
		}
		// base64 decode pipe: cat file | base64 -d | bash
		for (const part of pipeParts) {
			const tool = part.trim().split(/\s+/)[0];
			if (tool === "base64") {
				const args = part.trim().split(/\s+/).slice(1);
				if (args.includes("-d") || args.includes("--decode")) {
					return "pipe-bypass";
				}
			}
		}
	}

	const firstWord = command.split(/\s+/)[0];

	// Dangerous command check
	if (isDangerousCommand(firstWord, config)) {
		return "dangerous";
	}

	// Dangerous flags — specific patterns only
	if (/\brm\s+.*\b(-[a-zA-Z]*rf|-[a-zA-Z]*fr)\b/.test(command)) return "dangerous";
	if (/\bcp\s+.*\b(-[a-zA-Z]*r)\b/.test(command)) return "dangerous";

	// Safe list
	if (isSafeCommand(firstWord, config)) {
		return "safe";
	}

	return "dangerous";
}

function isSafeCommand(cmd: string, config: Config): boolean {
	return config.bashSafeList.some(s => cmd.startsWith(s));
}

function isDangerousCommand(cmd: string, config: Config): boolean {
	return config.bashDangerous.some(d => cmd.startsWith(d));
}

// ─── Permission rules ────────────────────────────────────────────────────────

interface PatternRule {
	tool: string;
	pattern: string;
	args?: string;
}

export function parseRule(rule: string): PatternRule | null {
	const match = rule.match(/^(\w+)\((.+)\)$/);
	if (!match) return null;
	const [, tool, rest] = match;
	if (rest.startsWith("args:")) {
		return { tool, pattern: "", args: rest.slice(5) };
	}
	return { tool, pattern: rest, args: undefined };
}

function matchesToolRule(rule: PatternRule, toolName: string, filePath?: string): boolean {
	if (rule.tool.toLowerCase() !== toolName.toLowerCase()) return false;
	if (rule.args) return true;
	if (!rule.pattern || !filePath) return false;
	return isGitignorePattern(rule.pattern, filePath);
}

export function checkPermissionRule(
	rules: string[],
	event: { toolName: string },
	input: Record<string, unknown>
): "allowed" | "blocked" | "ask" {
	for (const ruleStr of rules) {
		try {
			const rule = parseRule(ruleStr);
			if (!rule) continue;
			if (rule.tool.toLowerCase() !== event.toolName.toLowerCase()) continue;
			if (rule.args) {
				const inputStr = JSON.stringify(input);
				if (inputStr.includes(rule.args.slice(1, -1))) return "allowed";
				continue;
			}
			const filePath = input.path as string | undefined;
			if (filePath && isGitignorePattern(rule.pattern, filePath)) return "allowed";
		} catch (e) {
			console.error(`[approval-modes] Error checking permission rule: ${e instanceof Error ? e.message : String(e)}`);
		}
	}
	return "ask";
}

export function checkStrictMode(
	_config: Config,
	_event: { toolName: string },
	_input: Record<string, unknown>
): "allowed" | "blocked" | "ask" {
	return "ask";
}

// ─── Mode label ──────────────────────────────────────────────────────────────

export function modeLabel(mode: ApprovalMode): string {
	switch (mode) {
		case "yolo": return "🔓 YOLO";
		case "approved": return "🔒 Approved";
		case "strict": return "🛡 Strict";
	}
}

// ─── Extension ───────────────────────────────────────────────────────────────

const factory: ExtensionFactory = async (api) => {
	ensureConfigExists();
	let config = getConfig();
	const approvedCalls = new Set<string>();
	const blockedCommands: Array<{ tool: string; reason: string; timestamp: number }> = [];

	api.on("session_start", async (_event, ctx) => {
		config = getConfig(); // Reload on session start
		approvedCalls.clear();
		ctx.ui.setStatus("approval", modeLabel(config.mode));
	});

	api.on("session_shutdown", async (event, _ctx) => {
		if (event.reason !== "reload") {
			api.appendEntry("approval-modes-stats", {
				blockedCount: blockedCommands.length,
				mode: config.mode,
			});
		}
	});

	api.on("tool_call", async (event, ctx) => {
		// YOLO mode — skip everything
		if (config.mode === "yolo") return undefined;

		// Already approved
		if (approvedCalls.has(event.toolCallId)) return undefined;

		// === BASH TOOL ===
		if (event.toolName === "bash") {
			const input = event.input as Record<string, unknown>;
			const command = (input.command as string) ?? "";

			if (config.mode === "approved") {
				const analysis = analyzeBashCommand(command, config);

				if (analysis === "safe") {
					approvedCalls.add(event.toolCallId);
					return undefined;
				}

				const summary = analysis === "pipe-bypass"
					? `⚠ Pipe bypass: ${command}`
					: `bash: ${command}`;
				const approved = await ctx.ui.confirm("Approve bash command", summary, {
					timeout: 120000,
					signal: ctx.signal,
				});
				if (!approved) {
					approvedCalls.add(event.toolCallId);
					blockedCommands.push({ tool: "bash", reason: summary, timestamp: Date.now() });
					return { block: true, reason: "User denied approval" };
				}
				approvedCalls.add(event.toolCallId);
				return undefined;
			}

			if (config.mode === "strict") {
				const summary = `bash: ${command}`;
				const approved = await ctx.ui.confirm("Approve bash command", summary, {
					timeout: 120000,
					signal: ctx.signal,
				});
				if (!approved) {
					approvedCalls.add(event.toolCallId);
					blockedCommands.push({ tool: "bash", reason: summary, timestamp: Date.now() });
					return { block: true, reason: "User denied approval" };
				}
				approvedCalls.add(event.toolCallId);
				return undefined;
			}
		}

		// === WRITE/EDIT TOOLS ===
		if (event.toolName !== "write" && event.toolName !== "edit") return undefined;

		const input = event.input as Record<string, unknown>;
		const filePath = (input.path as string) ?? "unknown";

		// Check allow rules first
		const permResult = checkPermissionRule(
			config.permissions.allow,
			{ toolName: event.toolName },
			input
		);
		if (permResult === "allowed") {
			approvedCalls.add(event.toolCallId);
			return undefined;
		}

		// Check deny rules
		const denyResult = checkPermissionRule(
			config.permissions.deny,
			{ toolName: event.toolName },
			input
		);
		if (denyResult === "blocked") {
			approvedCalls.add(event.toolCallId);
			return { block: true, reason: `Blocked by deny rule: ${filePath}` };
		}

		// Default: ask
		const summary = event.toolName === "write" ? `write ${filePath}` : `edit ${filePath}`;
		const approved = await ctx.ui.confirm("Approve file operation", summary, {
			timeout: 120000,
			signal: ctx.signal,
		});
		if (!approved) {
			approvedCalls.add(event.toolCallId);
			blockedCommands.push({ tool: event.toolName, reason: summary, timestamp: Date.now() });
			return { block: true, reason: "User denied approval" };
		}
		approvedCalls.add(event.toolCallId);
		return undefined;
	});

	// Shortcut: cycles mode (from config)
	api.registerShortcut(config.shortcut, {
		description: "Cycle approval mode",
		handler: async (ctx) => {
			const MODES: ApprovalMode[] = ["yolo", "approved", "strict"];
			const currentIdx = MODES.indexOf(config.mode);
			config.mode = MODES[(currentIdx + 1) % MODES.length];
			saveConfig({ ...config });
			cachedConfig = config;
			ctx.ui.setStatus("approval", modeLabel(config.mode));
			ctx.ui.notify(`Mode: ${modeLabel(config.mode)}`, "info");
		},
	});

	// Commands
	api.registerCommand("approval", {
		description: "Switch approval mode (yolo|approved|strict)",
		handler: async (args, ctx) => {
			if (!args) {
				ctx.ui.notify(`${modeLabel(config.mode)} — yolo|approved|strict`, "info");
				return;
			}
			const mode = args.trim().toLowerCase() as ApprovalMode;
			if (!(["yolo", "approved", "strict"] as ApprovalMode[]).includes(mode)) {
				ctx.ui.notify(`Unknown mode: ${args}. Use: yolo, approved, strict`, "error");
				return;
			}
			config.mode = mode;
			saveConfig({ ...config });
			cachedConfig = config;
			ctx.ui.setStatus("approval", modeLabel(config.mode));
			ctx.ui.notify(`Mode: ${modeLabel(mode)}`, "info");
		},
	});

	api.registerCommand("approval-reset", {
		description: "Reset to defaults",
		handler: async (_args, ctx) => {
			config = { ...DEFAULT_CONFIG, permissions: { ...DEFAULT_CONFIG.permissions }, bashSafeList: [...DEFAULT_BASH_SAFE], bashDangerous: [...DEFAULT_BASH_DANGEROUS] };
			saveConfig(config);
			cachedConfig = config;
			ctx.ui.setStatus("approval", modeLabel(config.mode));
			ctx.ui.notify("Reset to defaults", "info");
		},
	});

	api.registerCommand("approval-stats", {
		description: "Show approval statistics",
		handler: async (_args, ctx) => {
			const total = approvedCalls.size + blockedCommands.length;
			ctx.ui.notify(
				`Approved: ${approvedCalls.size} | Blocked: ${blockedCommands.length} | Total: ${total}`,
				"info"
			);
		},
	});

	api.registerCommand("approval-shortcut", {
		description: "Show or change shortcut (e.g. /approval-shortcut ctrl+shift+a)",
		handler: async (args, ctx) => {
			if (!args) {
				ctx.ui.notify(`Current shortcut: ${config.shortcut}`, "info");
				return;
			}
			const newShortcut = args.trim();
			config.shortcut = newShortcut;
			saveConfig({ ...config });
			cachedConfig = config;
			ctx.ui.notify(`Shortcut changed to: ${newShortcut}`, "info");
			ctx.ui.notify("Run /reload to activate the new shortcut", "warning");
		},
	});
};

export default factory;
