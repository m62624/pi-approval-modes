import { isAbsolute, relative, resolve, sep } from 'node:path';

export function isPathInsideRoot(
	rootPath: string,
	targetPath: string | undefined,
	cwd: string,
): boolean {
	const root = resolve(rootPath);
	const target = targetPath ? resolve(cwd, targetPath) : resolve(cwd);
	const rel = relative(root, target);
	return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

export function formatRootRelativePath(
	rootPath: string,
	targetPath: string | undefined,
	cwd: string,
): string {
	const root = resolve(rootPath);
	const target = targetPath ? resolve(cwd, targetPath) : resolve(cwd);
	const rel = relative(root, target);
	if (!rel || rel === '') return '.';
	if (sep !== '/') return rel.split(sep).join('/');
	return rel;
}
