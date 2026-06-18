'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const dns2 = require('dns2');
const Packet = dns2.Packet;

const dnsHandler = require('../lib/dns-handler');
const { zoneStore } = require('../lib/zone-store');
const { db, flushTestDb, closeDb } = require('./helpers');

const { formatTXTData, shuffle, filterUnhealthy, reversedTypes } = dnsHandler.testables;

test.after(async () => {
    await closeDb();
});

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

test('formatTXTData always returns an array of chunks', () => {
    const short = formatTXTData('hello');
    assert.ok(Array.isArray(short));
    assert.deepEqual(short, ['hello']);
});

test('formatTXTData splits long values into <=255 byte chunks that recombine', () => {
    const long = 'x'.repeat(600);
    const chunks = formatTXTData(long);
    assert.ok(Array.isArray(chunks));
    assert.ok(chunks.length > 1);
    for (const chunk of chunks) {
        assert.ok(chunk.length <= 255);
    }
    assert.equal(chunks.join(''), long);
});

test('formatTXTData coerces non-strings', () => {
    assert.deepEqual(formatTXTData(undefined), ['']);
    assert.deepEqual(formatTXTData(null), ['']);
});

test('shuffle returns the same elements (a permutation)', () => {
    const input = [1, 2, 3, 4, 5, 6, 7, 8];
    const out = shuffle(input.slice());
    assert.equal(out.length, input.length);
    assert.deepEqual(out.slice().sort((a, b) => a - b), input);
});

test('filterUnhealthy drops unhealthy entries when at least one is healthy', () => {
    const list = [
        { address: '1.1.1.1', health: { status: true } },
        { address: '2.2.2.2', health: { status: false } },
        { address: '3.3.3.3' } // no health info -> treated as healthy
    ];
    const out = filterUnhealthy(list);
    assert.deepEqual(
        out.map(e => e.address),
        ['1.1.1.1', '3.3.3.3']
    );
});

test('filterUnhealthy returns all entries when none are healthy', () => {
    const list = [
        { address: '1.1.1.1', health: { status: false } },
        { address: '2.2.2.2', health: { status: false } }
    ];
    const out = filterUnhealthy(list);
    assert.equal(out.length, 2);
});

test('reversedTypes maps numeric DNS types back to strings', () => {
    assert.equal(reversedTypes.get(Packet.TYPE.A), 'A');
    assert.equal(reversedTypes.get(Packet.TYPE.AAAA), 'AAAA');
    assert.equal(reversedTypes.get(Packet.TYPE.MX), 'MX');
});

// ---------------------------------------------------------------------------
// Handler integration (Redis backed)
// ---------------------------------------------------------------------------

const buildRequest = (name, type) => {
    const req = new Packet({});
    req.questions = [{ name, type: Packet.TYPE[type], class: Packet.CLASS.IN }];
    req.source = { type: 'udp', address: '127.0.0.1', port: 5353 };
    return req;
};

test('dnsHandler answers an A query from stored records', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '', 'A', ['9.8.7.6']);

    const response = await dnsHandler(buildRequest('example.com', 'A'));
    const addresses = response.answers.filter(a => a.type === Packet.TYPE.A).map(a => a.address);
    assert.ok(addresses.includes('9.8.7.6'));
});

test('dnsHandler returns configured NS records when none are stored', async () => {
    await flushTestDb();
    const response = await dnsHandler(buildRequest('example.com', 'NS'));
    const nsAnswers = response.answers.filter(a => a.type === Packet.TYPE.NS);
    assert.ok(nsAnswers.length >= 1, 'should fall back to configured name servers');
});

test('dnsHandler synthesises a SOA record', async () => {
    await flushTestDb();
    const response = await dnsHandler(buildRequest('example.com', 'SOA'));
    const soa = response.answers.find(a => a.type === Packet.TYPE.SOA);
    assert.ok(soa, 'a SOA record should be returned');
});

test('dnsHandler filters unhealthy AAAA records', async () => {
    await flushTestDb();
    // Two AAAA records with health checks; mark one unhealthy in the health store.
    const healthyId = await zoneStore.add('example.com', '', 'AAAA', ['2001:db8::1', 'tcp://check:1']);
    const unhealthyId = await zoneStore.add('example.com', '', 'AAAA', ['2001:db8::2', 'tcp://check:2']);
    assert.ok(healthyId && unhealthyId);

    // Health results are keyed by "<zone-name>:<record-id>"
    const zoneName = zoneStore.domainToName('example.com');
    await db.redisWrite.hset('d:health:r', `${zoneName}:${unhealthyId}`, JSON.stringify({ status: false }));

    const response = await dnsHandler(buildRequest('example.com', 'AAAA'));
    const aaaa = response.answers.filter(a => a.type === Packet.TYPE.AAAA);
    assert.equal(aaaa.length, 1, 'the unhealthy AAAA record should be filtered out');
});

test('dnsHandler resolves CNAME chains', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', 'alias', 'CNAME', ['example.com']);
    await zoneStore.add('example.com', '', 'A', ['4.4.4.4']);

    const response = await dnsHandler(buildRequest('alias.example.com', 'A'));
    const types = response.answers.map(a => a.type);
    assert.ok(types.includes(Packet.TYPE.CNAME), 'should include the CNAME answer');
    const addresses = response.answers.filter(a => a.type === Packet.TYPE.A).map(a => a.address);
    assert.ok(addresses.includes('4.4.4.4'), 'should follow the CNAME to the A record');
});
