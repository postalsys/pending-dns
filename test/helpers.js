'use strict';

// Shared helpers for the test suite. Tests must run with NODE_ENV=test so that
// config/test.toml points Redis at the dedicated test database (db 15).

const config = require('wild-config');
const db = require('../lib/db');

const isTestDatabase = () => /\/15(\?|$)/.test((config.dbs.redis || '').toString());

// Flush the dedicated test database. Refuses to run unless Redis is pointed at
// db 15 to avoid wiping development (db 2) or production data by accident.
const flushTestDb = async () => {
    if (!isTestDatabase()) {
        throw new Error(`Refusing to flush Redis: expected the test database (db 15) but config points at "${config.dbs.redis}". Run tests with NODE_ENV=test.`);
    }
    await db.redisWrite.flushdb();
};

// Close Redis connections so the test process can exit cleanly.
const closeDb = async () => {
    await Promise.allSettled([db.redisRead.quit(), db.redisWrite.quit()]);
};

module.exports = { config, db, flushTestDb, closeDb, isTestDatabase };
