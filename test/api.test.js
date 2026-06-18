'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createServer } = require('../lib/api-server');
const { flushTestDb, closeDb } = require('./helpers');

let server;

test.before(async () => {
    server = await createServer();
    await server.initialize();
});

test.after(async () => {
    if (server) {
        await server.stop();
    }
    await closeDb();
});

test.beforeEach(async () => {
    await flushTestDb();
});

const inject = opts => server.inject(opts);

test('GET records returns an empty list for an unknown zone', async () => {
    const res = await inject({ method: 'GET', url: '/v1/zone/example.com/records' });
    assert.equal(res.statusCode, 200);
    const body = JSON.parse(res.payload);
    assert.equal(body.zone, 'example.com');
    assert.deepEqual(body.records, []);
});

test('unknown routes return 404', async () => {
    const res = await inject({ method: 'GET', url: '/does/not/exist' });
    assert.equal(res.statusCode, 404);
});

test('POST creates an A record and GET lists it alongside SOA/NS', async () => {
    const create = await inject({
        method: 'POST',
        url: '/v1/zone/example.com/records',
        payload: { subdomain: 'www', type: 'A', address: '1.2.3.4' }
    });
    assert.equal(create.statusCode, 200);
    const created = JSON.parse(create.payload);
    assert.ok(created.record, 'should return the new record id');

    const res = await inject({ method: 'GET', url: '/v1/zone/example.com/records' });
    const body = JSON.parse(res.payload);

    const a = body.records.find(r => r.type === 'A');
    assert.ok(a);
    assert.equal(a.address, '1.2.3.4');
    assert.equal(a.subdomain, 'www');

    // system records are appended with id=null
    assert.ok(body.records.some(r => r.type === 'SOA' && r.id === null));
    assert.ok(body.records.some(r => r.type === 'NS' && r.id === null));
});

test('POST rejects an A record without an address', async () => {
    const res = await inject({
        method: 'POST',
        url: '/v1/zone/example.com/records',
        payload: { type: 'A' }
    });
    assert.equal(res.statusCode, 400);
    const body = JSON.parse(res.payload);
    assert.ok(Array.isArray(body.fields), 'validation errors are reported in the fields array');
});

test('POST creates a CAA record and stores its tag', async () => {
    // Regression: the CAA "tag" field must be accepted and persisted.
    const create = await inject({
        method: 'POST',
        url: '/v1/zone/example.com/records',
        payload: { type: 'CAA', value: 'letsencrypt.org', tag: 'issue', flags: 0 }
    });
    assert.equal(create.statusCode, 200, `expected CAA create to succeed, got ${create.payload}`);

    const res = await inject({ method: 'GET', url: '/v1/zone/example.com/records' });
    const body = JSON.parse(res.payload);
    const caa = body.records.find(r => r.type === 'CAA' && r.id);
    assert.ok(caa, 'CAA record should be listed');
    assert.equal(caa.value, 'letsencrypt.org');
    assert.equal(caa.tag, 'issue');
});

test('PUT updates a record and echoes back the record id', async () => {
    const create = await inject({
        method: 'POST',
        url: '/v1/zone/example.com/records',
        payload: { subdomain: 'www', type: 'A', address: '1.2.3.4' }
    });
    const id = JSON.parse(create.payload).record;

    const update = await inject({
        method: 'PUT',
        url: `/v1/zone/example.com/records/${id}`,
        payload: { subdomain: 'www', type: 'A', address: '5.6.7.8' }
    });
    assert.equal(update.statusCode, 200);
    const body = JSON.parse(update.payload);
    assert.equal(body.zone, 'example.com');
    assert.ok(body.record, 'PUT should return the (possibly new) record id under "record"');
});

test('DELETE removes a record', async () => {
    const create = await inject({
        method: 'POST',
        url: '/v1/zone/example.com/records',
        payload: { type: 'A', address: '1.2.3.4' }
    });
    const id = JSON.parse(create.payload).record;

    const del = await inject({ method: 'DELETE', url: `/v1/zone/example.com/records/${id}` });
    assert.equal(del.statusCode, 200);
    const body = JSON.parse(del.payload);
    assert.equal(body.deleted, true);

    const res = await inject({ method: 'GET', url: '/v1/zone/example.com/records' });
    assert.deepEqual(JSON.parse(res.payload).records, []);
});

test('POST /v1/acme requires at least one domain', async () => {
    // Fails Joi validation (min 1) before the handler runs, so no ACME/network work.
    const res = await inject({ method: 'POST', url: '/v1/acme', payload: { domains: [] } });
    assert.equal(res.statusCode, 400);
});

// NB: the "domain without a managed zone" rejection path is intentionally not
// exercised here - the /v1/acme handler calls acme.init() (a live Let's Encrypt
// directory fetch) before the zone check, which is slow and network-dependent.
// The underlying behaviour is covered offline by the zone-store tests
// (resolveDomainZone returns false for unknown domains).
