'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const cachedResolver = require('../lib/cached-resolver');
const { db, flushTestDb, closeDb } = require('./helpers');

test.after(async () => {
    await closeDb();
});

test.beforeEach(async () => {
    await flushTestDb();
});

const cacheKey = (target, type) => ['d', 'cache', target, type].join(':');

test('successful lookups are cached in Redis with a TTL', async t => {
    let resolved;
    try {
        resolved = await cachedResolver('one.one.one.one', 'A');
    } catch (err) {
        t.skip(`network unavailable: ${err.message}`);
        return;
    }

    assert.ok(Array.isArray(resolved) && resolved.length, 'should resolve at least one address');

    const ttl = await db.redisRead.ttl(cacheKey('one.one.one.one', 'A'));
    assert.ok(ttl > 0, 'a positive TTL should be set on the cache entry');

    // a second call returns the cached value
    const again = await cachedResolver('one.one.one.one', 'A');
    assert.deepEqual(again.slice().sort(), resolved.slice().sort());
});

test('failed lookups cache an error with a bounded TTL', async t => {
    const bogus = 'does-not-exist-pendingdns-test.invalid';

    let threw = false;
    try {
        await cachedResolver(bogus, 'A');
    } catch (err) {
        threw = true;
    }

    if (!threw) {
        t.skip('resolver unexpectedly succeeded; cannot exercise the error path');
        return;
    }

    const ttl = await db.redisRead.ttl(cacheKey(bogus, 'A'));
    // Regression: the error entry must have a real, positive expiry (not NaN/-1).
    assert.ok(ttl > 0, `error cache entry must expire (ttl was ${ttl})`);
    assert.ok(ttl <= 60 * 60, 'error TTL should be bounded by errorMaxTtl (1h)');
});
