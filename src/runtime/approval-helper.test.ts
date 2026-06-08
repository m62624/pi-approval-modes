import { describe, expect, it } from 'vitest';
import { buildApprovalHelperText } from './approval-helper';

describe('buildApprovalHelperText', () => {
	it('contains modes, commands, and config pointers', () => {
		const text = buildApprovalHelperText({ agentDir: '/mock/agent' });

		expect(text).toContain('full-access');
		expect(text).toContain('folder-trusted');
		expect(text).toContain('self-guarded');
		expect(text).toContain('/approval-reset');
		expect(text).toContain(
			'/mock/agent/extensions/approval-modes/settings.json',
		);
		expect(text).toContain('shellGuard');
		expect(text).toContain('alt+m');
	});
});
