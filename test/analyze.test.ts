import { describe, it, expect, vi } from "vitest";

// Mock fs - loadConfig will return defaults
vi.mock("node:fs", () => ({
	existsSync: vi.fn(() => false),
	readFileSync: vi.fn(() => { throw new Error("not found"); }),
	writeFileSync: vi.fn(),
}));

vi.mock("node:path", () => ({
	join: vi.fn(() => "/mock/approval-modes.json"),
	dirname: vi.fn(() => "/mock"),
}));

// Import after mocking
import {
	isGitignorePattern,
	parseRule,
	analyzeBashCommand,
	checkPermissionRule,
	modeLabel,
} from "../approval-modes";

// Shared default config for bash tests
const defaultConfig = {
	mode: "read-only" as const,
	shortcut: "shift+tab" as const,
	permissions: { allow: [], deny: [] },
	bashSafeList: [
		"cat", "head", "tail", "less", "more", "grep", "find", "ls", "pwd",
		"whoami", "date", "uname", "hostname", "df", "free", "du", "wc",
		"sort", "uniq", "cut", "tr", "tee", "true", "false", "test",
		"echo", "base64",
		"stat", "file", "which", "type",
		"readlink", "realpath", "dirname", "basename",
	],
	bashDangerous: [
		"python", "python3", "bash", "sh", "zsh", "node", "perl", "ruby",
		"php", "lua", "osascript", "env", "sudo", "pwsh", "chmod", "chown",
	],
};

// --- isGitignorePattern (7 tests) ---

describe("isGitignorePattern", () => {
	it("exact match", () => {
		expect(isGitignorePattern("file.txt", "file.txt")).toBe(true);
	});

	it("single star matches without slash", () => {
		expect(isGitignorePattern("*.txt", "file.txt")).toBe(true);
	});

	it("single star does not match slash", () => {
		expect(isGitignorePattern("*.txt", "dir/file.txt")).toBe(false);
	});

	it("double star matches path", () => {
		expect(isGitignorePattern("**/file.txt", "dir/file.txt")).toBe(true);
	});

	it("double star matches root", () => {
		expect(isGitignorePattern("**/file.txt", "file.txt")).toBe(true);
	});

	it("escape special characters", () => {
		expect(isGitignorePattern("file+.txt", "file+.txt")).toBe(true);
	});

	it("partial non-match", () => {
		expect(isGitignorePattern("*.txt", "file.js")).toBe(false);
	});
});

// --- parseRule (5 tests) ---

describe("parseRule", () => {
	it("Write with pattern", () => {
		const result = parseRule("Write(./tmp/**)");
		expect(result).toEqual({ tool: "Write", pattern: "./tmp/**", args: undefined });
	});

	it("Read with pattern", () => {
		const result = parseRule("Read(./docs/**)");
		expect(result).toEqual({ tool: "Read", pattern: "./docs/**", args: undefined });
	});

	it("Tool with args JSON", () => {
		const result = parseRule('MyTool(args:{"x":1})');
		expect(result).toEqual({ tool: "MyTool", pattern: "", args: '{"x":1}' });
	});

	it("Bash with command", () => {
		const result = parseRule("Bash(ls -la)");
		expect(result).toEqual({ tool: "Bash", pattern: "ls -la", args: undefined });
	});

	it("Invalid format returns null", () => {
		expect(parseRule("nope")).toBeNull();
	});
});

// --- analyzeBashCommand (23 tests) ---

describe("analyzeBashCommand", () => {
	it("safe: ls -la", () => {
		expect(analyzeBashCommand("ls -la", defaultConfig)).toBe("safe");
	});

	it("safe: grep with pattern", () => {
		expect(analyzeBashCommand('grep "foo" file', defaultConfig)).toBe("safe");
	});

	it("safe: find command", () => {
		expect(analyzeBashCommand("find . -name *.ts", defaultConfig)).toBe("safe");
	});

	it("safe: trims whitespace", () => {
		expect(analyzeBashCommand("  ls -la  ", defaultConfig)).toBe("safe");
	});

	it("safe: cat file", () => {
		expect(analyzeBashCommand("cat file.txt", defaultConfig)).toBe("safe");
	});

	it("safe: head file", () => {
		expect(analyzeBashCommand("head -n 10 file.txt", defaultConfig)).toBe("safe");
	});

	it("safe: echo", () => {
		expect(analyzeBashCommand("echo hello", defaultConfig)).toBe("safe");
	});

	it("safe: base64 without -d", () => {
		expect(analyzeBashCommand("base64 file.txt", defaultConfig)).toBe("safe");
	});

	it("dangerous: python", () => {
		expect(analyzeBashCommand("python -c '1+1'", defaultConfig)).toBe("dangerous");
	});

	it("dangerous: sudo", () => {
		expect(analyzeBashCommand("sudo rm /", defaultConfig)).toBe("dangerous");
	});

	it("dangerous: node", () => {
		expect(analyzeBashCommand("node index.js", defaultConfig)).toBe("dangerous");
	});

	it("dangerous: rm -rf / (not in safe list)", () => {
		expect(analyzeBashCommand("rm -rf /", defaultConfig)).toBe("dangerous");
	});

	it("dangerous: rm -f file (not in safe list)", () => {
		expect(analyzeBashCommand("rm -f file", defaultConfig)).toBe("dangerous");
	});

	it("dangerous: touch (not in safe list)", () => {
		expect(analyzeBashCommand("touch file", defaultConfig)).toBe("dangerous");
	});

	it("dangerous: mkdir (not in safe list)", () => {
		expect(analyzeBashCommand("mkdir dir", defaultConfig)).toBe("dangerous");
	});

	it("dangerous: cp -r (not in safe list)", () => {
		expect(analyzeBashCommand("cp -r src/ dest/", defaultConfig)).toBe("dangerous");
	});

	it("dangerous: mv (not in safe list)", () => {
		expect(analyzeBashCommand("mv src dest", defaultConfig)).toBe("dangerous");
	});

	it("dangerous: chmod", () => {
		expect(analyzeBashCommand("chmod 777 file", defaultConfig)).toBe("dangerous");
	});

	it("dangerous: chown", () => {
		expect(analyzeBashCommand("chown root file", defaultConfig)).toBe("dangerous");
	});

	it("pipe-bypass: base64 -d pipe", () => {
		expect(analyzeBashCommand("cat file | base64 -d | bash", defaultConfig)).toBe("pipe-bypass");
	});

	it("pipe-bypass: base64 --decode", () => {
		expect(analyzeBashCommand("echo a | base64 --decode", defaultConfig)).toBe("pipe-bypass");
	});

	it("dangerous: chaining with &&", () => {
		expect(analyzeBashCommand("echo a && rm -rf /", defaultConfig)).toBe("dangerous");
	});

	it("dangerous: chaining with semicolon", () => {
		expect(analyzeBashCommand("echo a ; rm -rf /", defaultConfig)).toBe("dangerous");
	});

	it("dangerous: unknown command", () => {
		expect(analyzeBashCommand("foobar", defaultConfig)).toBe("dangerous");
	});

	it("safe: ls without dangerous flags", () => {
		expect(analyzeBashCommand("ls -la", defaultConfig)).toBe("safe");
	});

	it("safe: cat without dangerous flags", () => {
		expect(analyzeBashCommand("cat file.txt", defaultConfig)).toBe("safe");
	});
});

// --- checkPermissionRule (6 tests) ---

describe("checkPermissionRule", () => {
	it("allow match: Write pattern", () => {
		const result = checkPermissionRule(
			["Write(./tmp/**)"],
			{ toolName: "write" },
			{ path: "./tmp/file.txt" }
		);
		expect(result).toBe("allowed");
	});

	it("deny no match: Write wrong path", () => {
		const result = checkPermissionRule(
			["Write(.env)"],
			{ toolName: "write" },
			{ path: "./src/file.ts" }
		);
		expect(result).toBe("ask");
	});

	it("ask no match: Edit wrong path", () => {
		const result = checkPermissionRule(
			["Edit(./src/**)"],
			{ toolName: "edit" },
			{ path: "./docs/readme.md" }
		);
		expect(result).toBe("ask");
	});

	it("no match: wrong path", () => {
		const result = checkPermissionRule(
			["Write(./tmp/**)"],
			{ toolName: "write" },
			{ path: "./src/file.ts" }
		);
		expect(result).toBe("ask");
	});

	it("args match", () => {
		const result = checkPermissionRule(
			['MyTool(args:{"x":1})'],
			{ toolName: "myTool" },
			{ x: 1 }
		);
		expect(result).toBe("allowed");
	});

	it("wrong tool name", () => {
		const result = checkPermissionRule(
			["Write(./tmp/**)"],
			{ toolName: "bash" },
			{ path: "./tmp/file" }
		);
		expect(result).toBe("ask");
	});
});

describe("checkPermissionRule deny", () => {
	it("deny match: Write(.env) blocks", () => {
		const result = checkPermissionRule(
			["Write(.env)"],
			{ toolName: "write" },
			{ path: ".env" },
			{ deny: true }
		);
		expect(result).toBe("blocked");
	});

	it("deny no match: Write(.env) allows", () => {
		const result = checkPermissionRule(
			["Write(.env)"],
			{ toolName: "write" },
			{ path: "./src/file.ts" },
			{ deny: true }
		);
		expect(result).toBe("ask");
	});

	it("deny with args match", () => {
		const result = checkPermissionRule(
			['MyTool(args:{"x":1})'],
			{ toolName: "myTool" },
			{ x: 1 },
			{ deny: true }
		);
		expect(result).toBe("blocked");
	});
});
