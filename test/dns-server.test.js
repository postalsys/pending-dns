'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Resolver } = require('node:dns').promises;

const dns2 = require('dns2');
const Packet = dns2.Packet;

const initDnsServer = require('../lib/dns-server');
const { parseEdns, finalizeResponse } = initDnsServer.testables;
const { zoneStore } = require('../lib/zone-store');
const { config, flushTestDb, closeDb } = require('./helpers');

const EDNS = Packet.TYPE.EDNS;

let servers;
let resolver;

test.before(async () => {
    await flushTestDb();

    servers = await initDnsServer();

    resolver = new Resolver();
    resolver.setServers([`127.0.0.1:${config.dns.port}`]);

    await zoneStore.add('example.com', '', 'A', ['9.8.7.6']);
    await zoneStore.add('example.com', 'host', 'AAAA', ['2001:db8::1']);
    await zoneStore.add('example.com', 'txt', 'TXT', ['hello world']);
    // a value longer than a single 255-byte DNS character-string, but still
    // small enough to fit in a 512-byte UDP response
    await zoneStore.add('example.com', 'long', 'TXT', ['y'.repeat(300)]);
    await zoneStore.add('example.com', 'mail', 'MX', ['mx.example.com', 10]);
});

test.after(async () => {
    if (servers) {
        servers.udpServer.close();
        await new Promise(resolve => servers.tcpServer.close(resolve));
    }
    await closeDb();
});

test('resolves A records over the wire', async () => {
    const addrs = await resolver.resolve4('example.com');
    assert.deepEqual(addrs, ['9.8.7.6']);
});

test('resolves AAAA records over the wire', async () => {
    const addrs = await resolver.resolve6('host.example.com');
    assert.ok(addrs.includes('2001:db8::1'));
});

test('resolves a TXT record over the wire', async () => {
    const txt = await resolver.resolveTxt('txt.example.com');
    const flat = txt.map(chunks => chunks.join(''));
    assert.ok(flat.includes('hello world'));
});

test('resolves a long, multi-chunk TXT record over the wire', async () => {
    const txt = await resolver.resolveTxt('long.example.com');
    const flat = txt.map(chunks => chunks.join(''));
    assert.ok(flat.includes('y'.repeat(300)));
});

test('resolves MX records over the wire', async () => {
    const mx = await resolver.resolveMx('mail.example.com');
    assert.ok(mx.some(rec => rec.exchange === 'mx.example.com' && rec.priority === 10));
});

test('returns configured NS records over the wire', async () => {
    const ns = await resolver.resolveNs('example.com');
    assert.ok(Array.isArray(ns) && ns.length >= 1);
});

// ---------------------------------------------------------------------------
// EDNS / OPT handling (pure, no network)
// ---------------------------------------------------------------------------

const mkResponse = answers => {
    const p = new Packet({});
    p.header = new Packet.Header({ id: 1, qr: 1, aa: 1 });
    p.questions = [{ name: 'example.com', type: Packet.TYPE.A, class: Packet.CLASS.IN }];
    p.answers = answers;
    return p;
};

test('parseEdns reads the DO bit and payload size from an OPT record', () => {
    // eslint-disable-next-line new-cap
    const withOpt = { additionals: [Packet.Resource.EDNS([], { udpPayloadSize: 1232, doFlag: true })] };
    const edns = parseEdns(withOpt);
    assert.equal(edns.hasOpt, true);
    assert.equal(edns.doFlag, true);
    assert.equal(edns.udpPayloadSize, 1232);

    const noOpt = parseEdns({ additionals: [] });
    assert.equal(noOpt.hasOpt, false);
    assert.equal(noOpt.doFlag, false);
});

test('finalizeResponse adds an OPT to EDNS replies and drops leaked additionals', () => {
    const response = mkResponse([{ name: 'example.com', type: Packet.TYPE.A, class: Packet.CLASS.IN, ttl: 300, address: '1.2.3.4' }]);
    // simulate a leaked inbound OPT plus stray additional
    response.additionals = [
        // eslint-disable-next-line new-cap
        Packet.Resource.EDNS([], { udpPayloadSize: 4096, doFlag: true }),
        { name: 'x', type: Packet.TYPE.A, class: 1, ttl: 1, address: '9.9.9.9' }
    ];

    const out = finalizeResponse(response, { hasOpt: true, doFlag: true, udpPayloadSize: 4096 }, 'tcp');
    assert.equal(out.additionals.length, 1);
    assert.equal(out.additionals[0].type, EDNS);
    assert.equal(out.additionals[0].doFlag, true);
});

test('finalizeResponse omits OPT when the query had none', () => {
    const response = mkResponse([{ name: 'example.com', type: Packet.TYPE.A, class: Packet.CLASS.IN, ttl: 300, address: '1.2.3.4' }]);
    const out = finalizeResponse(response, { hasOpt: false, doFlag: false, udpPayloadSize: 512 }, 'tcp');
    assert.deepEqual(out.additionals, []);
});

test('finalizeResponse truncates oversized UDP responses with TC set', () => {
    // Many large TXT answers easily exceed the 512-byte floor.
    const answers = [];
    for (let i = 0; i < 20; i++) {
        answers.push({ name: 'example.com', type: Packet.TYPE.TXT, class: Packet.CLASS.IN, ttl: 300, data: ['z'.repeat(200)] });
    }
    const response = mkResponse(answers);
    const out = finalizeResponse(response, { hasOpt: true, doFlag: true, udpPayloadSize: 512 }, 'udp');
    // truncated path returns a serialized Buffer (TC=1, empty body, our OPT)
    assert.ok(Buffer.isBuffer(out));
    const reparsed = Packet.parse(out);
    assert.equal(reparsed.header.tc, 1);
    assert.equal(reparsed.answers.length, 0);
    assert.ok(reparsed.additionals.some(r => r.type === EDNS));
});

test('finalizeResponse caps UDP at our configured size, not the requestor advertised max', () => {
    // A response between our 1232 cap and the 4096 ceiling: a resolver advertising
    // 4096 must still get TC=1, because we never emit a datagram larger than our
    // configured udpPayloadSize (anti-fragmentation), regardless of the advertised max.
    const answers = [];
    for (let i = 0; i < 10; i++) {
        answers.push({ name: 'example.com', type: Packet.TYPE.TXT, class: Packet.CLASS.IN, ttl: 300, data: ['z'.repeat(200)] });
    }
    const response = mkResponse(answers);
    const out = finalizeResponse(response, { hasOpt: true, doFlag: true, udpPayloadSize: 4096 }, 'udp');
    assert.ok(Buffer.isBuffer(out));
    const reparsed = Packet.parse(out);
    assert.equal(reparsed.header.tc, 1, 'response above our configured cap is truncated even when 4096 is advertised');
    assert.equal(reparsed.answers.length, 0);
});

test('finalizeResponse returns a serialized buffer for UDP responses that fit', () => {
    const response = mkResponse([{ name: 'example.com', type: Packet.TYPE.A, class: Packet.CLASS.IN, ttl: 300, address: '1.2.3.4' }]);
    const out = finalizeResponse(response, { hasOpt: true, doFlag: false, udpPayloadSize: 1232 }, 'udp');
    assert.ok(Buffer.isBuffer(out));
    // reparse to confirm the OPT made it onto the wire
    const reparsed = Packet.parse(out);
    assert.ok(reparsed.additionals.some(r => r.type === EDNS));
});
