export type BashAnalysis = "safe" | "dangerous" | "pipe-bypass";

export interface BashConfig {
	bashSafeList: string[];
	bashDangerous: string[];
}

export function analyzeBashCommand(command: string, config: BashConfig): BashAnalysis {
	command = command.trim();

	if (/\|\|/.test(command) || /\&\&/.test(command) || /;/.test(command)) {
		return "dangerous";
	}

	const pipeParts = command.split("|").map(s => s.trim());
	if (pipeParts.length > 1) {
		const lastCmd = pipeParts[pipeParts.length - 1].trim();
		const lastTool = lastCmd.split(/\s+/)[0];
		if (isDangerousCommand(lastTool, config)) {
			return "pipe-bypass";
		}
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

	if (isDangerousCommand(firstWord, config)) return "dangerous";

	const dangerousFlags = /(-rf|-f|-r|--force|--recursive|--interactive)/;
	if (dangerousFlags.test(command)) return "dangerous";

	if (isSafeCommand(firstWord, config)) return "safe";

	return "dangerous";
}

function isSafeCommand(cmd: string, config: BashConfig): boolean {
	return config.bashSafeList.some(s => cmd.startsWith(s));
}

function isDangerousCommand(cmd: string, config: BashConfig): boolean {
	return config.bashDangerous.some(d => cmd.startsWith(d));
}
