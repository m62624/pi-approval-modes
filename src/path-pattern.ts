export function isPathPattern(pattern: string, pathStr: string): boolean {
	if (pattern.startsWith('**/')) {
		const rest = pattern.slice(3);
		if (isPathPattern(rest, pathStr)) return true;
		const slashIdx = pathStr.indexOf('/');
		if (slashIdx > 0) {
			return isPathPattern(rest, pathStr.slice(slashIdx + 1));
		}
		return false;
	}
	const regex = pattern
		.replace(/[.+?^${}()|[\]\\]/g, '\\$&')
		.replace(/\*\*/g, '\x00')
		.replace(/\*/g, '[^/]*')
		.replace(/\0/g, '.*');
	return new RegExp(`^${regex}$`).test(pathStr);
}
