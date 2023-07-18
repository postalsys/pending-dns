/* eslint global-require: 0 */

'use strict';

const cluster = require('cluster');
const logger = require('../lib/logger').child({ component: 'public-worker' });
const config = require('wild-config');

const workerName = 'public';

let closing = false;
const closeProcess = (code, errType, err) => {
    if (closing) {
        return;
    }
    closing = true;

    if (!code) {
        return setTimeout(() => {
            process.exit(code);
        }, 10);
    }

    logger.fatal({
        msg: errType,
        _msg: errType,
        err
    });

    if (!logger.notifyError) {
        setTimeout(() => process.exit(code), 10);
    }
};

process.on('uncaughtException', err => closeProcess(1, 'uncaughtException', err));
process.on('unhandledRejection', err => closeProcess(2, 'unhandledRejection', err));
process.on('SIGTERM', () => closeProcess(0));
process.on('SIGINT', () => closeProcess(0));

const packageData = require('../package.json');
const Bugsnag = require('@bugsnag/js');
if (process.env.BUGSNAG_API_KEY) {
    Bugsnag.start({
        apiKey: process.env.BUGSNAG_API_KEY,
        appVersion: packageData.version,
        logger: {
            debug(...args) {
                logger.debug({ msg: args.shift(), worker: workerName, source: 'bugsnag', args: args.length ? args : undefined });
            },
            info(...args) {
                logger.debug({ msg: args.shift(), worker: workerName, source: 'bugsnag', args: args.length ? args : undefined });
            },
            warn(...args) {
                logger.warn({ msg: args.shift(), worker: workerName, source: 'bugsnag', args: args.length ? args : undefined });
            },
            error(...args) {
                logger.error({ msg: args.shift(), worker: workerName, source: 'bugsnag', args: args.length ? args : undefined });
            }
        }
    });
    logger.notifyError = Bugsnag.notify.bind(Bugsnag);
}

const run = () => {
    require(`../lib/${workerName}-server.js`)()
        .then(() => {
            if (config.process.group) {
                process.setgid(config.process.group);
                logger.warn({ msg: 'Changed GID', group: config.process.group });
            }

            if (config.process.user) {
                process.setuid(config.process.user);
                logger.warn({ msg: 'Changed UID', user: config.process.user });
            }
        })
        .catch(err => {
            logger.error(err);
            closeProcess(3);
        });
};

if (cluster.isMaster) {
    logger.warn({ msg: 'Master process running', workerName });

    if (config[workerName].workers === 1 && !config.process.user && !config.process.group) {
        // no cluster needed
        run();
    } else {
        const fork = () => {
            if (closing) {
                return;
            }
            let worker = cluster.fork();
            worker.on('online', () => {
                logger.warn({ msg: 'Worker came online', workerName, worker: worker.process.pid });
            });
        };

        for (let i = 0; i < config[workerName].workers; i++) {
            fork();
        }

        cluster.on('exit', (worker, code, signal) => {
            if (closing) {
                return;
            }
            logger.warn({ msg: 'Worker died', workerName, worker: worker.process.pid, code, signal });
            setTimeout(() => fork(), 2000).unref();
        });
    }
} else {
    process.title = `postal-public:${workerName}`;
    run();
}
