'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { execFile } = require('node:child_process');
const pathlib = require('node:path');

const { initSentry } = require('../lib/sentry');
const logger = require('../lib/logger');

test('initSentry is a no-op when no DSN is configured', () => {
    // Ensure the disabled path: no env DSN, and config.sentry.dsn is empty in the test config
    delete process.env.SENTRY_DSN;

    assert.doesNotThrow(() => initSentry('test'));

    // error reporting stays disabled, so closeProcess() keeps owning the exit
    assert.ok(!logger.errorReportingEnabled);

    // notifyError keeps its safe no-op default from lib/logger.js
    assert.equal(typeof logger.notifyError, 'function');
    assert.equal(logger.notifyError(new Error('boom')), false);
});

// initSentry installs a process-level unhandled-rejection handler; the only way
// to observe whether it ends the process is to run one.
const runWithSentry = script =>
    new Promise(resolve => {
        execFile(
            process.execPath,
            ['-e', script],
            {
                cwd: pathlib.join(__dirname, '..'),
                env: Object.assign({}, process.env, {
                    NODE_ENV: 'test',
                    // points nowhere: the delivery attempt is irrelevant, the exit is not
                    SENTRY_DSN: 'https://0123456789abcdef0123456789abcdef@127.0.0.1:1/1'
                })
            },
            // a non-zero exit is the expected outcome here, so only stdout matters
            (_err, stdout) => resolve(stdout)
        );
    });

test('an unhandled rejection does not leave the process running', async () => {
    // lib/close-process.js owns the exit, but the reporter must not keep the
    // event in flight while that happens - hence mode 'strict' rather than
    // 'warn', which only logs.
    const stdout = await runWithSentry(`
        require('./lib/sentry.js').initSentry('test');
        Promise.reject(new Error('boom'));
        setTimeout(() => { console.log('SURVIVED'); process.exit(0); }, 2500);
    `);
    assert.ok(!stdout.includes('SURVIVED'), 'process kept running after an unhandled rejection');
});
