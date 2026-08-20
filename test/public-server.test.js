'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const util = require('node:util');

const { storeTlsTicket, loadTlsTicket } = require('../lib/public-server').testables;
const { db, flushTestDb, closeDb } = require('./helpers');

const store = util.promisify(storeTlsTicket);
const load = util.promisify(loadTlsTicket);

test.after(async () => {
    await closeDb();
});

test.beforeEach(async () => {
    await flushTestDb();
});

const ticketId = Buffer.from('0123456789abcdef', 'hex');
const ticketData = Buffer.from('a tls session ticket');

test('a stored ticket is returned again, with its ttl refreshed', async () => {
    await store(ticketId, ticketData);

    const key = `d:tls:${ticketId.toString('hex')}`;
    assert.ok((await db.redisRead.ttl(key)) > 300, 'stored with the long ttl');

    assert.deepEqual(await load(ticketId), ticketData);

    // the refresh is fired off separately from the read, so let it land
    await db.redisWrite.ping();
    const ttl = await db.redisRead.ttl(key);
    assert.ok(ttl > 0 && ttl <= 300, `ttl was shortened to the resume window, got ${ttl}`);
});

test('an unknown ticket resolves to null rather than failing', async () => {
    assert.equal(await load(Buffer.from('ffffffffffffffff', 'hex')), null);
});

test('resuming issues no write against the read client', async () => {
    // dns-02 reads from a local read-only replica. EXPIRE inside the read
    // transaction made the replica abort the whole MULTI, so the ticket came
    // back empty and session resumption silently never happened.
    await store(ticketId, ticketData);

    const readOnly = db.redisRead;
    const writeCommands = ['multi', 'pipeline', 'set', 'expire', 'del', 'getset'];
    db.redisRead = new Proxy(readOnly, {
        get(target, prop, receiver) {
            if (writeCommands.includes(prop)) {
                throw new Error(`resumeSession used a write command (${String(prop)}) on the read client`);
            }
            const value = Reflect.get(target, prop, receiver);
            return typeof value === 'function' ? value.bind(target) : value;
        }
    });

    try {
        assert.deepEqual(await load(ticketId), ticketData);
    } finally {
        db.redisRead = readOnly;
    }
});
