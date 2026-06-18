'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Resolver } = require('node:dns').promises;

const initDnsServer = require('../lib/dns-server');
const { zoneStore } = require('../lib/zone-store');
const { config, flushTestDb, closeDb } = require('./helpers');

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
