/* eslint global-require: 0 */

'use strict';

const cluster = require('cluster');
const logger = require('../lib/logger').child({ component: 'api-worker' });
const config = require('wild-config');

const workerName = 'api';

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

if (cluster.isMaster) {
    logger.warn({ msg: 'Master process running', workerName });

    if (config[workerName].workers === 1) {
        // no cluster needed
        require(`../lib/${workerName}-server.js`);
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
    process.title = `postal-dns:${workerName}`;
    require(`../lib/${workerName}-server.js`);
}
