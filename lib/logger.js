'use strict';

const { threadId } = require('worker_threads');
const config = require('wild-config');
const pino = require('pino');

let logger = pino();
logger.level = config.log.level;

if (threadId) {
    logger = logger.child({ tid: threadId });
}

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
