'use strict';

process.title = 'pending-dns';

// cache before wild-config
const argv = process.argv.slice(2);
const config = require('wild-config');
const logger = require('./lib/logger').child({ component: 'server' });
const pathlib = require('path');
const packageData = require('./package.json');
const { Worker, SHARE_ENV } = require('worker_threads');
const { isemail } = require('./lib/tools');

if (!config.acme || !isemail(config.acme.email)) {
    console.error('"acme.email" configuration value is not set or is not a valid email address');
    process.exit(51);
}

const Bugsnag = require('@bugsnag/js');
if (process.env.BUGSNAG_API_KEY) {
    Bugsnag.start({
        apiKey: process.env.BUGSNAG_API_KEY,
        appVersion: packageData.version,
        logger: {
            debug(...args) {
                logger.debug({ msg: args.shift(), worker: 'main', source: 'bugsnag', args: args.length ? args : undefined });
            },
            info(...args) {
                logger.debug({ msg: args.shift(), worker: 'main', source: 'bugsnag', args: args.length ? args : undefined });
            },
            warn(...args) {
                logger.warn({ msg: args.shift(), worker: 'main', source: 'bugsnag', args: args.length ? args : undefined });
            },
            error(...args) {
                logger.error({ msg: args.shift(), worker: 'main', source: 'bugsnag', args: args.length ? args : undefined });
            }
        }
    });
    logger.notifyError = Bugsnag.notify.bind(Bugsnag);
}

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

// Public HTTP/HTTPS server
if (config.public.enabled) {
    spawnWorker('public');
}

// Healthchecks
if (config.health.enabled) {
    spawnWorker('health');
}

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
