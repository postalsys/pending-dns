/* eslint global-require: 0 */

'use strict';

const cluster = require('cluster');
const logger = require('../lib/logger').child({ component: 'dns-worker' });
const config = require('wild-config');

const workerName = 'dns';

let closing = false;
const closeProcess = code => {
    if (closing) {
        return;
    }
    closing = true;
    setTimeout(() => {
        process.exit(code);
    }, 10);
};

process.on('uncaughtException', () => closeProcess(1));
process.on('unhandledRejection', () => closeProcess(2));
process.on('SIGTERM', () => closeProcess(0));
process.on('SIGINT', () => closeProcess(0));

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
    process.title = `pending-dns:${workerName}`;
    run();
}
