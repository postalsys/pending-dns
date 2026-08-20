'use strict';

const { threadId } = require('worker_threads');
const config = require('wild-config');
const pino = require('pino');

// ioredis attaches the command it was running to its reply errors, and on a
// failed handshake that command is HELLO/AUTH - so pino's default error
// serializer, which copies every enumerable property of an Error, would write
// the Redis password into the log. Censor those arguments centrally: the same
// error reaches the log from lib/db.js, the crash handler in
// lib/close-process.js, and every `logger.error({ err })` in between.
let logger = pino({
    redact: {
        paths: ['err.command.args', '*.err.command.args'],
        censor: '[redacted]'
    }
});
logger.level = config.log.level;

if (threadId) {
    logger = logger.child({ tid: threadId });
}

// No-op by default; lib/sentry.js overrides this with a real reporter when a DSN is configured
logger.notifyError = () => false;

process.on('uncaughtException', err => {
    logger.fatal({
        msg: 'uncaughtException',
        err
    });
});

process.on('unhandledRejection', err => {
    logger.fatal({
        msg: 'unhandledRejection',
        err
    });
});

module.exports = logger;
