'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { zoneStore, ZoneStore, allowedTypes, allowedTags } = require('../lib/zone-store');
const { flushTestDb, closeDb } = require('./helpers');

test.after(async () => {
    await closeDb();
});

test.beforeEach(async () => {
    await flushTestDb();
});

// ---------------------------------------------------------------------------
// Pure helpers (no Redis)
// ---------------------------------------------------------------------------

test('module exports the allowed record types and CAA tags', () => {
    assert.deepEqual(allowedTypes, ['A', 'AAAA', 'ANAME', 'CNAME', 'MX', 'TXT', 'CAA', 'URL', 'NS']);
    assert.deepEqual(allowedTags, ['issue', 'issuewild', 'iodef']);
});

test('getFullId / parseFullId round-trip', () => {
    const id = zoneStore.getFullId('com.example.www', 'CNAME', 'abc123');
    const parsed = zoneStore.parseFullId(id);
    assert.deepEqual(parsed, { name: 'com.example.www', type: 'CNAME', hid: 'abc123' });
});

test('getFullId produces URL-safe ids (no +, /, =)', () => {
    // Use values likely to produce base64 padding / special chars
    const id = zoneStore.getFullId('com.example.subsubsub', 'AAAA', 'zzzzz');
    assert.match(id, /^[A-Za-z0-9_-]+$/);
});

test('parseFullId returns empty object for garbage input', () => {
    const parsed = zoneStore.parseFullId('!!!not base64!!!');
    // name/type/hid will be undefined for malformed ids
    assert.equal(parsed.hid, undefined);
});

test('domainToName reverses labels and nameToDomain restores them', () => {
    assert.equal(zoneStore.domainToName('www.example.com'), 'com.example.www');
    assert.equal(zoneStore.nameToDomain('com.example.www'), 'www.example.com');
    // round trip
    assert.equal(zoneStore.nameToDomain(zoneStore.domainToName('a.b.c.example.com')), 'a.b.c.example.com');
});

test('getsubdomain extracts the subdomain relative to a zone', () => {
    assert.equal(zoneStore.getsubdomain('example.com', 'www.example.com'), 'www');
    assert.equal(zoneStore.getsubdomain('example.com', 'a.b.example.com'), 'a.b');
    assert.equal(zoneStore.getsubdomain('example.com', 'example.com'), '');
    // unrelated domain returned as-is
    assert.equal(zoneStore.getsubdomain('example.com', 'other.org'), 'other.org');
});

test('formatValue shapes each record type for API output', () => {
    const store = new ZoneStore();

    assert.deepEqual(store.formatValue({ id: '1', type: 'A', value: ['1.2.3.4', false] }), {
        id: '1',
        type: 'A',
        address: '1.2.3.4',
        healthCheck: false
    });

    assert.deepEqual(store.formatValue({ id: '2', type: 'CNAME', zone: 'example.com', value: ['@'] }), {
        id: '2',
        type: 'CNAME',
        target: 'example.com'
    });

    assert.deepEqual(store.formatValue({ id: '3', type: 'MX', value: ['mx.example.com', 10] }), {
        id: '3',
        type: 'MX',
        exchange: 'mx.example.com',
        priority: 10
    });

    assert.deepEqual(store.formatValue({ id: '4', type: 'CAA', value: ['letsencrypt.org', 'issue', 0] }), {
        id: '4',
        type: 'CAA',
        value: 'letsencrypt.org',
        tag: 'issue',
        flags: 0
    });

    assert.deepEqual(store.formatValue({ id: '5', type: 'TXT', value: ['hello world'] }), {
        id: '5',
        type: 'TXT',
        data: 'hello world'
    });
});

// ---------------------------------------------------------------------------
// Redis-backed behaviour
// ---------------------------------------------------------------------------

test('add stores a record and list returns it', async () => {
    const id = await zoneStore.add('example.com', '', 'A', ['1.2.3.4']);
    assert.ok(id, 'add should return a record id');

    const list = await zoneStore.list('example.com');
    assert.equal(list.length, 1);
    assert.equal(list[0].type, 'A');
    assert.deepEqual(list[0].value, ['1.2.3.4']);
    assert.equal(list[0].id, id);
});

test('add rejects unknown types and empty values', async () => {
    assert.equal(await zoneStore.add('example.com', '', 'BOGUS', ['x']), false);
    assert.equal(await zoneStore.add('example.com', '', 'A', []), false);
});

test('resolveZone / resolveDomainZone find the closest zone', async () => {
    await zoneStore.add('example.com', '', 'A', ['1.2.3.4']);

    assert.equal(await zoneStore.resolveDomainZone('example.com'), 'example.com');
    assert.equal(await zoneStore.resolveDomainZone('www.example.com'), 'example.com');
    assert.equal(await zoneStore.resolveDomainZone('deep.sub.example.com'), 'example.com');
    assert.equal(await zoneStore.resolveDomainZone('nonexistent-zone.org'), false);
});

test('resolve returns exact records', async () => {
    await zoneStore.add('example.com', 'www', 'CNAME', ['example.com']);
    const res = await zoneStore.resolve('www.example.com', 'CNAME', false);
    assert.ok(Array.isArray(res));
    assert.equal(res.length, 1);
    assert.deepEqual(res[0].value, ['example.com']);
});

test('resolve falls back to a one-level wildcard record', async () => {
    await zoneStore.add('example.com', '*.test', 'CNAME', ['example.com']);
    const res = await zoneStore.resolve('anything.test.example.com', 'CNAME', false);
    assert.ok(Array.isArray(res));
    assert.equal(res.length, 1);
    assert.equal(res[0].wildcard, '*.test.example.com');
});

test('update keeps the id when only the value changes', async () => {
    const id = await zoneStore.add('example.com', '', 'A', ['1.2.3.4']);
    const newId = await zoneStore.update('example.com', id, '', 'A', ['5.6.7.8']);
    assert.equal(newId, id, 'id is stable when domain and type are unchanged');

    const res = await zoneStore.resolve('example.com', 'A', false);
    assert.deepEqual(res[0].value, ['5.6.7.8']);
});

test('update changes the id when the type changes', async () => {
    const id = await zoneStore.add('example.com', 'host', 'A', ['1.2.3.4']);
    const newId = await zoneStore.update('example.com', id, 'host', 'AAAA', ['::1']);
    assert.ok(newId);
    assert.notEqual(newId, id);

    // old A record is gone, new AAAA record exists
    assert.equal(await zoneStore.resolve('host.example.com', 'A', false), false);
    const res = await zoneStore.resolve('host.example.com', 'AAAA', false);
    assert.deepEqual(res[0].value, ['::1']);
});

test('del removes a single record by id', async () => {
    const id = await zoneStore.add('example.com', '', 'A', ['1.2.3.4']);
    assert.equal(await zoneStore.del('example.com', id), true);
    assert.equal((await zoneStore.list('example.com')).length, 0);
});

test('deleting one of several same-type records keeps the others listed', async () => {
    // Regression test: deleting one entry from a record hash that still has
    // other entries must NOT drop the whole record key from the zone listing.
    const id1 = await zoneStore.add('example.com', '', 'A', ['1.1.1.1']);
    const id2 = await zoneStore.add('example.com', '', 'A', ['2.2.2.2']);
    assert.ok(id1 && id2);

    assert.equal((await zoneStore.list('example.com')).length, 2);

    assert.equal(await zoneStore.del('example.com', id1), true);

    const list = await zoneStore.list('example.com');
    assert.equal(list.length, 1, 'the remaining A record must still be listed');
    assert.deepEqual(list[0].value, ['2.2.2.2']);

    // resolve must also still find it
    const res = await zoneStore.resolve('example.com', 'A', false);
    assert.ok(res && res.length === 1);
    assert.deepEqual(res[0].value, ['2.2.2.2']);
});

test('deleteDomain removes matching records and reports the count', async () => {
    await zoneStore.add('example.com', 'multi', 'A', ['1.1.1.1']);
    await zoneStore.add('example.com', 'multi', 'A', ['2.2.2.2']);

    const deleted = await zoneStore.deleteDomain('multi.example.com', 'A');
    assert.equal(deleted, 2);
    assert.equal(await zoneStore.resolve('multi.example.com', 'A', false), false);
});

test('deleteDomain can match a specific value', async () => {
    await zoneStore.add('example.com', 'pick', 'A', ['1.1.1.1']);
    await zoneStore.add('example.com', 'pick', 'A', ['2.2.2.2']);

    const deleted = await zoneStore.deleteDomain('pick.example.com', 'A', ['1.1.1.1']);
    assert.equal(deleted, 1);

    const res = await zoneStore.resolve('pick.example.com', 'A', false);
    assert.equal(res.length, 1);
    assert.deepEqual(res[0].value, ['2.2.2.2']);
});
