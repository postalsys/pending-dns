'use strict';

// Shared ioredfour distributed lock (namespace 'd:lock:' on the Redis write
// client). Used by both ACME certificate issuance (lib/certs.js) and DNSSEC key
// management (lib/dnssec.js); callers namespace their own lock keys so the two
// never collide.

const Lock = require('ioredfour');
const util = require('util');
const db = require('./db');
const logger = require('./logger').child({ component: 'lock' });

const lock = new Lock({
    redis: db.redisWrite,
    namespace: 'd:lock:'
});

const waitAcquireLock = util.promisify(lock.waitAcquireLock.bind(lock));

// Release an acquired lock. Safe to call with a missing or unsuccessful lock
// (no-op), so callers can release unconditionally in a finally block. `context`
// is merged into the release-failure log so the caller can identify which lock
// (e.g. which domains) is stuck.
const releaseLock = (acquired, context) =>
    new Promise(resolve => {
        if (!acquired || !acquired.success) {
            return resolve();
        }
        lock.releaseLock(acquired, err => {
            if (err) {
                logger.error(Object.assign({ msg: 'Failed releasing lock' }, context || {}, { err }));
            }
            resolve();
        });
    });

module.exports = { waitAcquireLock, releaseLock };
