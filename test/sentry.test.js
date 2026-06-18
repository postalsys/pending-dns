'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

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
