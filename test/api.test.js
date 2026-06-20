'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createServer } = require('../lib/api-server');
const { config, flushTestDb, closeDb } = require('./helpers');

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

test('POST creates a TLSA record with an underscore-labelled subdomain', async () => {
    const certHex = '92003ba34942dc74152e2f2c408d29eca5a520e7f2e06bb944f4dca346baf63c';
    const create = await inject({
        method: 'POST',
        url: '/v1/zone/example.com/records',
        payload: { subdomain: '_443._tcp.www', type: 'TLSA', usage: 3, selector: 1, matchingType: 1, certificate: certHex }
    });
    assert.equal(create.statusCode, 200, `expected TLSA create to succeed, got ${create.payload}`);

    const res = await inject({ method: 'GET', url: '/v1/zone/example.com/records' });
    const body = JSON.parse(res.payload);
    const tlsa = body.records.find(r => r.type === 'TLSA' && r.id);
    assert.ok(tlsa, 'TLSA record should be listed');
    assert.equal(tlsa.subdomain, '_443._tcp.www');
    assert.equal(tlsa.usage, 3);
    assert.equal(tlsa.selector, 1);
    assert.equal(tlsa.matchingType, 1);
    assert.equal(tlsa.certificate, certHex);
});

test('POST rejects a TLSA record with odd-length hex', async () => {
    const res = await inject({
        method: 'POST',
        url: '/v1/zone/example.com/records',
        payload: { subdomain: '_443._tcp.www', type: 'TLSA', usage: 3, selector: 1, matchingType: 1, certificate: 'abc' }
    });
    assert.equal(res.statusCode, 400);
});

test('POST rejects TLSA-only fields on a non-TLSA record type', async () => {
    const res = await inject({
        method: 'POST',
        url: '/v1/zone/example.com/records',
        payload: { subdomain: '', type: 'A', address: '1.2.3.4', usage: 3, certificate: 'abcd' }
    });
    assert.equal(res.statusCode, 400);
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

test('DNSSEC can be enabled, inspected and disabled over the API', async () => {
    const enable = await inject({ method: 'POST', url: '/v1/zone/example.com/dnssec', payload: { algorithm: 13 } });
    assert.equal(enable.statusCode, 200, `expected enable to succeed, got ${enable.payload}`);
    const enabled = JSON.parse(enable.payload);
    assert.equal(enabled.enabled, true);
    assert.ok(enabled.ds.length >= 1 && enabled.ds[0].presentation, 'DS presentation should be returned');

    const status = await inject({ method: 'GET', url: '/v1/zone/example.com/dnssec' });
    assert.equal(status.statusCode, 200);
    assert.equal(JSON.parse(status.payload).enabled, true);

    const disable = await inject({ method: 'DELETE', url: '/v1/zone/example.com/dnssec' });
    assert.equal(disable.statusCode, 200);
    assert.equal(JSON.parse(disable.payload).disabled, true);

    const after = await inject({ method: 'GET', url: '/v1/zone/example.com/dnssec' });
    assert.equal(JSON.parse(after.payload).enabled, false);
});

test('DNSSEC algorithm rollover and key removal over the API', async () => {
    const enable = JSON.parse((await inject({ method: 'POST', url: '/v1/zone/example.com/dnssec', payload: { algorithm: 13 } })).payload);
    const oldKeyTag = enable.keyTag;

    // Re-enable with a new algorithm -> rollover keeps both keys.
    const rolled = await inject({ method: 'POST', url: '/v1/zone/example.com/dnssec', payload: { algorithm: 15 } });
    const rolledBody = JSON.parse(rolled.payload);
    assert.equal(rolledBody.algorithm, 15);
    assert.equal(rolledBody.ds.length, 2, 'both keys are published during the rollover');
    assert.notEqual(rolledBody.keyTag, oldKeyTag);

    // The active key cannot be removed.
    const refuse = await inject({ method: 'DELETE', url: `/v1/zone/example.com/dnssec/key/${rolledBody.keyTag}` });
    assert.equal(refuse.statusCode, 400);

    // Removing the old key finishes the rollover.
    const remove = await inject({ method: 'DELETE', url: `/v1/zone/example.com/dnssec/key/${oldKeyTag}` });
    assert.equal(remove.statusCode, 200);
    assert.equal(JSON.parse(remove.payload).removed, true);

    const final = JSON.parse((await inject({ method: 'GET', url: '/v1/zone/example.com/dnssec' })).payload);
    assert.equal(final.ds.length, 1);
    assert.equal(final.keyTag, rolledBody.keyTag);
});

test('POST /dnssec is refused (400) when DNSSEC is globally disabled', async () => {
    config.dnssec.enabled = false;
    try {
        const res = await inject({ method: 'POST', url: '/v1/zone/example.com/dnssec', payload: { algorithm: 13 } });
        assert.equal(res.statusCode, 400, `expected 400, got ${res.statusCode}: ${res.payload}`);
    } finally {
        config.dnssec.enabled = true;
    }
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
