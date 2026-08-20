'use strict';

const config = require('wild-config');
const Redis = require('ioredis');
const fs = require('fs');
const pathlib = require('path');
const logger = require('./logger').child({ component: 'db' });

const healthScript = fs.readFileSync(pathlib.join(__dirname, 'lua', 'health.lua'), 'utf-8');

// Options shared by every Redis connection, including the subscriber connection
// that ioredfour creates with `duplicate()` for the shared lock (lib/lock.js).
//
// `maxRetriesPerRequest: null` keeps commands queued while the connection is
// down instead of rejecting the whole queue once the retry counter runs out.
// The default (20) rejects every queued command with a MaxRetriesPerRequestError
// after roughly 13 seconds of downtime, and not all of those commands are ours:
// ioredfour issues SUBSCRIBE from its constructor and ioredis re-issues
// SELECT/SUBSCRIBE on reconnect, both without a rejection handler. Such a
// rejection reaches the global unhandledRejection handler and takes the worker
// down, so a Redis restart crashes every worker at once - and keeps crashing
// them as the supervisor respawns them into the same outage.
//
// The trade-off: the offline queue grows for as long as Redis is away, so a
// permanently unreachable server builds up rather than failing loudly.
const redisOptions = {
    maxRetriesPerRequest: null
};

// Connection errors are expected and recoverable - ioredis reconnects on its
// own - but with no listener at all it prints raw stack traces straight to
// stderr, bypassing the logger. Same level split as lib/dns-server.js uses for
// expected transport errors, so a Redis restart does not fill the log.
const EXPECTED_ERRORS = ['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'EPIPE', 'EAI_AGAIN'];

const reportErrors = (client, role) => {
    client.on('error', err => {
        const method = err && EXPECTED_ERRORS.includes(err.code) ? 'warn' : 'error';
        logger[method]({ msg: 'Redis connection error', role, err });
    });
    return client;
};

const createClient = (url, role) => {
    // ioredis merges a URL string (or an options object) with the second argument
    const client = reportErrors(new Redis(url, redisOptions), role);

    // duplicate() carries the options over but not the listeners, and ioredfour
    // builds its lock subscriber that way without attaching any of its own.
    const duplicate = client.duplicate.bind(client);
    client.duplicate = (...args) => reportErrors(duplicate(...args), `${role}:duplicate`);

    return client;
};

module.exports.redisRead = createClient(config.dbs.redisRead || config.dbs.redis, 'read');
module.exports.redisWrite = createClient(config.dbs.redisWrite || config.dbs.redis, 'write');

module.exports.redisWrite.defineCommand('nextHealth', {
    numberOfKeys: 1,
    lua: healthScript
});
