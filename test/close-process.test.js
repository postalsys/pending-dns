'use strict';

const test = require('node:test');
const { describe } = test;
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const pathlib = require('node:path');

// installCrashHandlers() ends the process, so each case needs its own.
const runCrashingWorker = (crash, { errorReportingEnabled }) =>
    new Promise(resolve => {
        const script = `
            const logger = { fatal: () => false, errorReportingEnabled: ${errorReportingEnabled} };
            require('./lib/close-process.js').installCrashHandlers(logger);
            ${crash}
            setInterval(() => false, 1000);
            setTimeout(() => { console.log('SURVIVED'); process.exit(0); }, 5000);
        `;
        execFile(process.execPath, ['-e', script], { cwd: pathlib.join(__dirname, '..') }, (err, stdout) => resolve({ code: err ? err.code : 0, stdout }));
    });

// The two reporter-enabled cases each wait out the flush window, so run the
// group concurrently rather than paying for it twice.
describe('crash handling', { concurrency: 4 }, () => {
    // A crashed worker has to exit so the supervisor reforks it. Nothing outside
    // this module may be responsible for that: the Sentry integrations stand down
    // whenever another crash listener is registered (lib/logger.js registers one)
    // or the subsystem runs in a worker thread.
    test('an uncaught exception exits the worker even when a reporter is active', async () => {
        const { code, stdout } = await runCrashingWorker(`setImmediate(() => { throw new Error('boom'); });`, { errorReportingEnabled: true });
        assert.ok(!stdout.includes('SURVIVED'), 'worker kept running after an uncaught exception');
        assert.equal(code, 1);
    });

    test('an unhandled rejection exits the worker even when a reporter is active', async () => {
        const { code, stdout } = await runCrashingWorker(`Promise.reject(new Error('boom'));`, { errorReportingEnabled: true });
        assert.ok(!stdout.includes('SURVIVED'), 'worker kept running after an unhandled rejection');
        assert.equal(code, 2);
    });

    test('with no reporter the worker exits immediately', async () => {
        const { code, stdout } = await runCrashingWorker(`Promise.reject(new Error('boom'));`, { errorReportingEnabled: false });
        assert.ok(!stdout.includes('SURVIVED'));
        assert.equal(code, 2);
    });

    test('SIGTERM still shuts the worker down cleanly', async () => {
        const { code, stdout } = await runCrashingWorker(`setImmediate(() => process.kill(process.pid, 'SIGTERM'));`, { errorReportingEnabled: true });
        assert.ok(!stdout.includes('SURVIVED'), 'worker ignored SIGTERM');
        assert.equal(code, 0);
    });
});
