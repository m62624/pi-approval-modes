import { join } from 'node:path';

export interface ConfigPathInput {
	agentDir: string;
	cwd: string;
	extensionName: string;
}

export interface ConfigPaths {
	agentDir: string;
	extensionDir: string;
	settings: string;
}

export function createConfigPaths(input: ConfigPathInput): ConfigPaths {
	const extensionDir = join(input.agentDir, 'extensions', input.extensionName);
	return {
		agentDir: input.agentDir,
		extensionDir,
		settings: join(extensionDir, 'settings.json'),
	};
}
