import { describe, it, expect, vi, beforeEach } from "vitest";

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
	checkStrictMode,
	modeLabel,
} from "../approval-modes";

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

// --- analyzeBashCommand (21 tests) ---

describe("analyzeBashCommand", () => {
	it("safe: ls -la", () => {
		expect(analyzeBashCommand("ls -la")).toBe("safe");
	});

	it("safe: grep with pattern", () => {
		expect(analyzeBashCommand('grep "foo" file')).toBe("safe");
	});

	it("safe: find command", () => {
		expect(analyzeBashCommand("find . -name *.ts")).toBe("safe");
	});

	it("safe: trims whitespace", () => {
		expect(analyzeBashCommand("  ls -la  ")).toBe("safe");
	});

	it("safe: cat file", () => {
		expect(analyzeBashCommand("cat file.txt")).toBe("safe");
	});

	it("safe: head file", () => {
		expect(analyzeBashCommand("head -n 10 file.txt")).toBe("safe");
	});

	it("safe: echo", () => {
		expect(analyzeBashCommand("echo hello")).toBe("safe");
	});

	it("safe: base64 without -d", () => {
		expect(analyzeBashCommand("base64 file.txt")).toBe("safe");
	});

	it("dangerous: python", () => {
		expect(analyzeBashCommand("python -c '1+1'")).toBe("dangerous");
	});

	it("dangerous: sudo", () => {
		expect(analyzeBashCommand("sudo rm /")).toBe("dangerous");
	});

	it("dangerous: node", () => {
		expect(analyzeBashCommand("node index.js")).toBe("dangerous");
	});

	it("dangerous: rm -rf", () => {
		expect(analyzeBashCommand("rm -rf /")).toBe("dangerous");
	});

	it("dangerous: rm -f", () => {
		expect(analyzeBashCommand("rm -f file")).toBe("dangerous");
	});

	it("dangerous: chmod", () => {
		expect(analyzeBashCommand("chmod 777 file")).toBe("dangerous");
	});

	it("dangerous: chown", () => {
		expect(analyzeBashCommand("chown root file")).toBe("dangerous");
	});

	it("dangerous: cp -r", () => {
		expect(analyzeBashCommand("cp -r src/ dest/")).toBe("dangerous");
	});

	it("pipe-bypass: base64 -d pipe", () => {
		expect(analyzeBashCommand("cat file | base64 -d | bash")).toBe("pipe-bypass");
	});

	it("pipe-bypass: base64 --decode", () => {
		expect(analyzeBashCommand("echo a | base64 --decode")).toBe("pipe-bypass");
	});

	it("dangerous: chaining with &&", () => {
		expect(analyzeBashCommand("echo a && rm -rf /")).toBe("dangerous");
	});

	it("dangerous: chaining with semicolon", () => {
		expect(analyzeBashCommand("echo a ; rm -rf /")).toBe("dangerous");
	});

	it("dangerous: unknown command", () => {
		expect(analyzeBashCommand("foobar")).toBe("dangerous");
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

// --- checkStrictMode (5 tests) ---

describe("checkStrictMode", () => {
	const config = {
		mode: "strict" as const,
		permissions: { allow: [] as string[], ask: [] as string[], deny: [] as string[] },
		bashSafeList: [] as string[],
		bashDangerous: [] as string[],
	};

	it("deny wins", () => {
		config.permissions.deny = ["Write(.env)"];
		const result = checkStrictMode(config, { toolName: "write" }, { path: ".env" });
		expect(result).toBe("blocked");
		config.permissions.deny = [];
	});

	it("allow wins", () => {
		config.permissions.allow = ["Write(./tmp/**)"];
		const result = checkStrictMode(config, { toolName: "write" }, { path: "./tmp/file.txt" });
		expect(result).toBe("allowed");
		config.permissions.allow = [];
	});

	it("ask via ask list", () => {
		config.permissions.ask = ["Edit(./src/**)"];
		const result = checkStrictMode(config, { toolName: "edit" }, { path: "./src/app.ts" });
		expect(result).toBe("ask");
		config.permissions.ask = [];
	});

	it("default blocked", () => {
		const result = checkStrictMode(config, { toolName: "write" }, { path: "./any/file.ts" });
		expect(result).toBe("blocked");
	});

	it("deny overrides allow", () => {
		config.permissions.deny = ["Write(.env)"];
		config.permissions.allow = ["Write(.env)"];
		const result = checkStrictMode(config, { toolName: "write" }, { path: ".env" });
		expect(result).toBe("blocked");
		config.permissions.deny = [];
		config.permissions.allow = [];
	});
});

// --- modeLabel (3 tests) ---

describe("modeLabel", () => {
	it("yolo", () => {
		expect(modeLabel("yolo")).toBe("🔓 YOLO");
	});

	it("approved", () => {
		expect(modeLabel("approved")).toBe("🔒 Approved");
	});

	it("strict", () => {
		expect(modeLabel("strict")).toBe("🛡 Strict");
	});
});
