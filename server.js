'use strict';

process.title = 'postal-dns';

// cache before wild-config
const argv = process.argv.slice(2);
const config = require('wild-config');
const logger = require('./lib/logger');
const pathlib = require('path');
const { Worker, SHARE_ENV } = require('worker_threads');

let closing = false;

let workers = new Map();

let spawnWorker = type => {
    if (closing) {
        return;
    }

    if (!workers.has(type)) {
        workers.set(type, new Set());
    }

    let worker = new Worker(pathlib.join(__dirname, 'workers', `${type}.js`), {
        argv,
        env: SHARE_ENV
    });

    workers.get(type).add(worker);

    worker.on('exit', exitCode => {
        workers.get(type).delete(worker);

        if (closing) {
            return;
        }

        // spawning a new worker trigger reassign
        logger.error({ msg: 'Worker exited', exitCode });
        setTimeout(() => spawnWorker(type), 1000);
    });
};

if (config.api.enabled) {
    spawnWorker('api');
}

// DNS server
if (config.dns.enabled) {
    spawnWorker('dns');
}

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
