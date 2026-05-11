/**
 * Approval modes: YOLO, Approved, Strict.
 *
 * Modes:
 *   YOLO     - no approvals, no checks
 *   Approved - bash safe-list + ask for write/edit
 *   Strict   - pattern-based allow/deny/ask
 *
 * Switch: shift+tab
 * Thinking level: alt+q
 * Status shown in footer via ctx.ui.setStatus
 */

import type { ExtensionFactory } from "@earendil-works/pi-coding-agent";
import { join } from "node:path";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { analyzeBashCommand as analyzeBashCommandInternal } from "./src/analysis.js";

export type ApprovalMode = "yolo" | "approved" | "strict";

const MODES: ApprovalMode[] = ["yolo", "approved", "strict"];

// --- Config ---

interface Config {
	mode: ApprovalMode;
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
	"touch", "mkdir", "cp", "mv", "rm", "echo", "base64",
	"stat", "file", "which", "type",
	"readlink", "realpath", "dirname", "basename",
];

const DEFAULT_BASH_DANGEROUS: string[] = [
	"python", "python3", "bash", "sh", "zsh", "node", "perl", "ruby",
	"php", "lua", "osascript", "env", "sudo", "pwsh", "chmod", "chown",
];

const DEFAULT_CONFIG: Config = {
	mode: "approved",
	permissions: { allow: [], ask: [], deny: [] },
	bashSafeList: [...DEFAULT_BASH_SAFE],
	bashDangerous: [...DEFAULT_BASH_DANGEROUS],
};

export function configPath(): string {
	const home = process.env.HOME || process.env.USERPROFILE || ".";
	return join(home, ".pi", "agent", "extensions", "approval-modes.json");
}

export function loadConfig(): Config {
	try {
		const p = configPath();
		if (existsSync(p)) {
			const raw = readFileSync(p, "utf-8");
			const loaded = JSON.parse(raw);
			// Merge with defaults for backward compatibility
			return {
				mode: loaded.mode ?? "approved",
				permissions: loaded.permissions ?? { allow: [], ask: [], deny: [] },
				bashSafeList: loaded.bashSafeList ?? [...DEFAULT_BASH_SAFE],
				bashDangerous: loaded.bashDangerous ?? [...DEFAULT_BASH_DANGEROUS],
			};
		}
	} catch (e) {
		console.error(`[approval-modes] Failed to load config: ${e instanceof Error ? e.message : String(e)}`);
	}
	return { ...DEFAULT_CONFIG, permissions: { ...DEFAULT_CONFIG.permissions }, bashSafeList: [...DEFAULT_BASH_SAFE], bashDangerous: [...DEFAULT_BASH_DANGEROUS] };
}

export function saveConfig(cfg: Config) {
	try {
		const fs = require("node:fs");
		const path = require("node:path");
		const p = configPath();
		fs.mkdirSync(path.dirname(p), { recursive: true });
		writeFileSync(p, JSON.stringify(cfg, null, 2));
	} catch (e) {
		console.error(`[approval-modes] Failed to save config: ${e instanceof Error ? e.message : String(e)}`);
	}
}

// --- Pattern helpers ---

export function isGitignorePattern(pattern: string, pathStr: string): boolean {
	// Handle **/ prefix: matches zero or more directories
	if (pattern.startsWith("**/")) {
		const rest = pattern.slice(3);
		// **/file.txt should match file.txt (zero dirs) or dir/file.txt (one+ dirs)
		if (isGitignorePattern(rest, pathStr)) return true;
		const slashIdx = pathStr.indexOf("/");
		if (slashIdx > 0) {
			return isGitignorePattern(rest, pathStr.slice(slashIdx + 1));
		}
		return false;
	}
	// Escape regex special chars, then handle wildcards
	let regex = pattern
		.replace(/[.+?^${}()|[\]\\]/g, "\\$&")
		.replace(/\*\*/g, "\x00")
		.replace(/\*/g, "[^/]*")
		.replace(/\x00/g, ".*");
	return new RegExp(`^${regex}$`).test(pathStr);
}

// --- Bash command analysis ---

/**
 * Check if a bash command is dangerous.
 * Returns: "safe" | "dangerous" | "pipe-bypass"
 */
export function analyzeBashCommand(command: string): "safe" | "dangerous" | "pipe-bypass" {
	const config = loadConfig();
	return analyzeBashCommandInternal(command, config);
}

// --- Permission rules (Strict mode) ---

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
			if (rule.tool !== event.toolName) continue;
			if (rule.args) {
				const inputStr = JSON.stringify(input);
				if (inputStr.includes(rule.args.slice(1, -1))) return "allowed";
				continue;
			}
			const filePath = input.path as string | undefined;
			if (filePath && matchesToolRule(rule, event.toolName, filePath)) return "allowed";
		} catch (e) {
			console.error(`[approval-modes] Error checking permission rule: ${e instanceof Error ? e.message : String(e)}`);
		}
	}
	return "ask";
}

export function checkStrictMode(
	config: Config,
	event: { toolName: string },
	input: Record<string, unknown>
): "allowed" | "blocked" | "ask" {
	const denyResult = checkPermissionRule(config.permissions.deny, event, input);
	if (denyResult === "allowed") return "blocked";
	if (denyResult === "ask") return "blocked";

	const allowResult = checkPermissionRule(config.permissions.allow, event, input);
	if (allowResult === "allowed") return "allowed";

	const askResult = checkPermissionRule(config.permissions.ask, event, input);
	if (askResult === "allowed") return "ask";

	return "blocked";
}

// --- Mode label ---

export function modeLabel(mode: ApprovalMode): string {
	switch (mode) {
		case "yolo": return "🔓 YOLO";
		case "approved": return "🔒 Approved";
		case "strict": return "🛡 Strict";
	}
}

// --- Extension ---

const factory: ExtensionFactory = async (api) => {
	let config = loadConfig();
	const approvedCalls = new Set<string>();

	api.on("session_start", async (_event, ctx) => {
		ctx.ui.setStatus("approval", modeLabel(config.mode));
	});

	api.on("tool_call", async (event, ctx) => {
		// YOLO mode - skip everything
		if (config.mode === "yolo") return undefined;

		// Already approved
		if (approvedCalls.has(event.toolCallId)) return undefined;

		// === BASH TOOL ===
		if (event.toolName === "bash") {
			const input = event.input as Record<string, unknown>;
			const command = (input.command as string) ?? "";

			if (config.mode === "approved") {
				const analysis = analyzeBashCommand(command);

				if (analysis === "safe") {
					approvedCalls.add(event.toolCallId);
					return undefined;
				}

				// Dangerous or pipe-bypass - ask
				const summary = analysis === "pipe-bypass"
					? `⚠ Pipe bypass: ${command}`
					: `bash: ${command}`;
				const approved = await ctx.ui.confirm("Approve bash command", summary, { timeout: 120000 });
				if (!approved) {
					approvedCalls.add(event.toolCallId);
					return { block: true, reason: "User denied approval" };
				}
				approvedCalls.add(event.toolCallId);
				return undefined;
			}

			if (config.mode === "strict") {
				const result = checkPermissionRule(config.permissions.allow, event, input);
				if (result === "allowed") {
					approvedCalls.add(event.toolCallId);
					return undefined;
				}
				const denyResult = checkPermissionRule(config.permissions.deny, event, input);
				if (denyResult === "allowed" || denyResult === "ask") {
					return { block: true, reason: "Blocked by strict mode" };
				}
				const askResult = checkPermissionRule(config.permissions.ask, event, input);
				if (askResult === "allowed") {
					const summary = `bash: ${command}`;
					const approved = await ctx.ui.confirm("Approve bash command", summary, { timeout: 120000 });
					if (!approved) {
						approvedCalls.add(event.toolCallId);
						return { block: true, reason: "User denied approval" };
					}
				}
				approvedCalls.add(event.toolCallId);
				return undefined;
			}
		}

		// === WRITE/EDIT TOOLS ===
		if (event.toolName !== "write" && event.toolName !== "edit") return undefined;

		const input = event.input as Record<string, unknown>;
		const filePath = (input.path as string) ?? "unknown";

		if (config.mode === "strict") {
			const result = checkStrictMode(config, event, input);
			if (result === "allowed") {
				approvedCalls.add(event.toolCallId);
				return undefined;
			}
			if (result === "blocked") {
				return { block: true, reason: "Blocked by strict mode rule" };
			}
			// ask - fall through
		}

		const summary = event.toolName === "write" ? `write ${filePath}` : `edit ${filePath}`;
		const approved = await ctx.ui.confirm("Approve file operation", summary, { timeout: 120000 });
		if (!approved) {
			approvedCalls.add(event.toolCallId);
			return { block: true, reason: "User denied approval" };
		}
		approvedCalls.add(event.toolCallId);
		return undefined;
	});

	// Shortcut: shift+tab cycles mode
	api.registerShortcut("shift+tab", {
		description: "Cycle approval mode",
		handler: async (ctx) => {
			try {
				const currentIdx = MODES.indexOf(config.mode);
				config.mode = MODES[(currentIdx + 1) % MODES.length];
				saveConfig(config);
				ctx.ui.setStatus("approval", modeLabel(config.mode));
				ctx.ui.notify(`Mode: ${modeLabel(config.mode)}`, "info");
			} catch (e) {
				console.error(`[approval-modes] Shortcut error: ${e instanceof Error ? e.message : String(e)}`);
				ctx.ui.notify(`Error: ${e instanceof Error ? e.message : String(e)}`, "error");
			}
		},
	});

	// Commands
	api.registerCommand("approval", {
		description: "Switch approval mode (yolo|approved|strict)",
		handler: async (args, ctx) => {
			try {
				if (!args) {
					ctx.ui.notify(`${modeLabel(config.mode)} — yolo|approved|strict`, "info");
					return;
				}
				const mode = args.trim().toLowerCase() as ApprovalMode;
				if (!MODES.includes(mode)) {
					ctx.ui.notify(`Unknown mode: ${args}. Use: yolo, approved, strict`, "error");
					return;
				}
				config.mode = mode;
				saveConfig(config);
				ctx.ui.setStatus("approval", modeLabel(config.mode));
				ctx.ui.notify(`Mode: ${modeLabel(mode)}`, "info");
			} catch (e) {
				console.error(`[approval-modes] Command error: ${e instanceof Error ? e.message : String(e)}`);
				ctx.ui.notify(`Error: ${e instanceof Error ? e.message : String(e)}`, "error");
			}
		},
	});

	api.registerCommand("approval-reset", {
		description: "Reset to defaults",
		handler: async (_args, ctx) => {
			try {
				config = { ...DEFAULT_CONFIG, permissions: { ...DEFAULT_CONFIG.permissions }, bashSafeList: [...DEFAULT_BASH_SAFE], bashDangerous: [...DEFAULT_BASH_DANGEROUS] };
				saveConfig(config);
				ctx.ui.setStatus("approval", modeLabel(config.mode));
				ctx.ui.notify("Reset to defaults", "info");
			} catch (e) {
				console.error(`[approval-modes] Reset error: ${e instanceof Error ? e.message : String(e)}`);
				ctx.ui.notify(`Error: ${e instanceof Error ? e.message : String(e)}`, "error");
			}
		},
	});
};

export default factory;
