'use strict';

// Key-management and signing tests for lib/dnssec.js. Backed by Redis (db 15).

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const dnssec = require('../lib/dnssec');
const wire = require('../lib/dnssec-wire');
const db = require('../lib/db');
const { config, flushTestDb, closeDb } = require('./helpers');

test.after(async () => {
    await closeDb();
});

// Parse an RRSIG RDATA buffer back into its fields + signature.
const parseRRSIG = data => {
    let off = 18;
    while (data[off] !== 0) {
        off += 1 + data[off];
    }
    off += 1; // include the root label
    return {
        typeCovered: data.readUInt16BE(0),
        algorithm: data.readUInt8(2),
        labels: data.readUInt8(3),
        originalTtl: data.readUInt32BE(4),
        expiration: data.readUInt32BE(8),
        inception: data.readUInt32BE(12),
        keyTag: data.readUInt16BE(16),
        preimage: data.slice(0, off),
        signature: data.slice(off)
    };
};

test('enableZone generates a CSK and reports consistent DS/DNSKEY', async () => {
    await flushTestDb();
    const status = await dnssec.enableZone('example.com', { algorithm: 13 });

    assert.equal(status.enabled, true);
    assert.equal(status.algorithm, 13);
    assert.equal(status.ds.length, 1);
    assert.equal(status.dnskey.length, 1);
    assert.equal(status.ds[0].keyTag, status.dnskey[0].keyTag);

    // The DS digest must recompute from the published DNSKEY.
    const dnskeyRdata = wire.encodeDNSKEYRdata({
        flags: status.dnskey[0].flags,
        protocol: status.dnskey[0].protocol,
        algorithm: status.dnskey[0].algorithm,
        pubkey: Buffer.from(status.dnskey[0].publicKey, 'base64')
    });
    assert.equal(wire.dnskeyKeyTag(dnskeyRdata), status.ds[0].keyTag);
    assert.equal(wire.dsDigest('example.com', dnskeyRdata, status.ds[0].digestType).toString('hex'), status.ds[0].digest);
});

test('enableZone is idempotent and keeps the same key', async () => {
    await flushTestDb();
    const first = await dnssec.enableZone('example.com', { algorithm: 13 });
    const second = await dnssec.enableZone('example.com', { algorithm: 13 });
    assert.equal(first.dnskey[0].keyTag, second.dnskey[0].keyTag);
    assert.equal(first.dnskey[0].publicKey, second.dnskey[0].publicKey);
});

test('isZoneSigned reflects enable/disable', async () => {
    await flushTestDb();
    assert.equal(await dnssec.isZoneSigned('example.com'), false);
    await dnssec.enableZone('example.com', { algorithm: 13 });
    assert.equal(await dnssec.isZoneSigned('example.com'), true);
    await dnssec.disableZone('example.com');
    assert.equal(await dnssec.isZoneSigned('example.com'), false);
});

for (const algorithm of [13, 15, 8]) {
    test(`signRRset produces a verifiable RRSIG for algorithm ${algorithm}`, async () => {
        await flushTestDb();
        await dnssec.enableZone('example.com', { algorithm });
        const signer = await dnssec.getSigner('example.com');
        assert.ok(signer, 'signer should be available');
        assert.equal(signer.keys.length, 1, 'a single-algorithm zone has one signing key');
        const key = signer.keys[0];

        const rrs = [
            { name: 'example.com', type: wire.TYPE.A, class: 1, ttl: 300, address: '1.2.3.4' },
            { name: 'example.com', type: wire.TYPE.A, class: 1, ttl: 300, address: '5.6.7.8' }
        ];
        // signRRset returns one RRSIG per signing key (one per algorithm).
        const rrsigs = dnssec.signRRset(signer, 'example.com', 'example.com', wire.TYPE.A, 300, rrs);
        assert.equal(rrsigs.length, 1, 'one RRSIG per signing key');
        const rrsig = rrsigs[0];

        assert.equal(rrsig.type, wire.TYPE.RRSIG);
        const parsed = parseRRSIG(rrsig.data);
        assert.equal(parsed.typeCovered, wire.TYPE.A);
        assert.equal(parsed.algorithm, algorithm);
        assert.equal(parsed.keyTag, key.keyTag);
        assert.ok(parsed.inception < parsed.expiration);

        // Rebuild the signed bytes and verify with the public half of the key.
        const canonical = rrs
            .map(rr => wire.canonicalRdata(wire.TYPE.A, rr))
            .sort(wire.compareCanonicalRdata)
            .map(rdata => wire.canonicalRR('example.com', wire.TYPE.A, 1, 300, rdata));
        const tbs = Buffer.concat([parsed.preimage, ...canonical]);
        const publicKey = crypto.createPublicKey(key.privateKeyObj);
        assert.ok(wire.ALGS[algorithm].verify(tbs, publicKey, parsed.signature), 'RRSIG must verify');
    });
}

test('enableZone rolls to a new algorithm and removeKey finishes the rollover', async () => {
    await flushTestDb();
    const first = await dnssec.enableZone('example.com', { algorithm: 13 });
    assert.equal(first.dnskey.length, 1);
    const oldKeyTag = first.keyTag;

    // Re-enable with a different algorithm -> rollover: both keys are kept and
    // the zone is signed with both algorithms (RFC 6840 5.11).
    const rolled = await dnssec.enableZone('example.com', { algorithm: 15 });
    assert.equal(rolled.algorithm, 15, 'active algorithm switches to the new one');
    assert.equal(rolled.dnskey.length, 2, 'both keys are published during overlap');
    assert.notEqual(rolled.keyTag, oldKeyTag, 'a new active key is generated');
    const newKeyTag = rolled.keyTag;

    const signer = await dnssec.getSigner('example.com');
    assert.deepEqual(
        signer.keys.map(k => k.algorithm).sort((a, b) => a - b),
        [13, 15],
        'signs with both algorithms during the rollover'
    );

    // The active key cannot be removed - roll away from it first.
    await assert.rejects(() => dnssec.removeKey('example.com', newKeyTag), /active key/);

    // Remove the old key to finish the rollover.
    assert.equal(await dnssec.removeKey('example.com', oldKeyTag), true);
    const after = await dnssec.getZoneStatus('example.com');
    assert.equal(after.dnskey.length, 1);
    assert.equal(after.keyTag, newKeyTag);

    const signerAfter = await dnssec.getSigner('example.com');
    assert.deepEqual(
        signerAfter.keys.map(k => k.algorithm),
        [15]
    );

    // The last remaining key cannot be removed.
    await assert.rejects(() => dnssec.removeKey('example.com', newKeyTag), /last remaining key/);
});

test('re-enabling with no algorithm preserves the rolled-to active key', async () => {
    await flushTestDb();
    await dnssec.enableZone('example.com', { algorithm: 13 });
    const rolled = await dnssec.enableZone('example.com', { algorithm: 15 });
    assert.equal(rolled.algorithm, 15);

    // Empty body (no algorithm) must NOT revert the active key to the config default.
    const reenabled = await dnssec.enableZone('example.com');
    assert.equal(reenabled.algorithm, 15, 'active stays on the rolled-to algorithm');
    assert.equal(reenabled.keyTag, rolled.keyTag, 'active key is unchanged');
});

test('enableZone refuses when the global switch is off', async () => {
    await flushTestDb();
    config.dnssec.enabled = false;
    try {
        await assert.rejects(() => dnssec.enableZone('example.com', { algorithm: 13 }), /disabled globally/);
    } finally {
        config.dnssec.enabled = true;
    }
});

test('getSigner caches the signer for the configured TTL', async () => {
    await flushTestDb();
    await dnssec.enableZone('example.com', { algorithm: 13 });
    config.dnssec.signerCacheTtl = 30;
    try {
        assert.ok(await dnssec.getSigner('example.com'), 'signer is built and cached');
        // Disable via raw Redis, bypassing invalidateSigner: the cache must keep
        // serving the signer until the TTL expires.
        await db.redisWrite.hset(`d:dnssec:${dnssec.testables.zoneName('example.com')}`, 'enabled', '0');
        assert.ok(await dnssec.getSigner('example.com'), 'still served from cache despite the raw disable');
    } finally {
        config.dnssec.signerCacheTtl = 0;
    }
});

test('a configured inception skew and signature validity of 0 are honored', async () => {
    await flushTestDb();
    await dnssec.enableZone('example.com', { algorithm: 13 });
    const signer = await dnssec.getSigner('example.com');

    const origSkew = config.dnssec.inceptionSkew;
    const origValidity = config.dnssec.signatureValidity;
    config.dnssec.inceptionSkew = 0;
    config.dnssec.signatureValidity = 0;
    try {
        const before = Math.floor(Date.now() / 1000);
        const rrsigs = dnssec.signRRset(signer, 'example.com', 'example.com', wire.TYPE.A, 300, [
            { name: 'example.com', type: wire.TYPE.A, class: 1, ttl: 300, address: '1.2.3.4' }
        ]);
        const after = Math.floor(Date.now() / 1000);
        const parsed = parseRRSIG(rrsigs[0].data);
        // inceptionSkew = 0 means no backdating: inception is "now", not now - 3600.
        assert.ok(parsed.inception >= before && parsed.inception <= after, 'inception is now, not backdated');
        // signatureValidity = 0 means expiration equals inception, not now + 604800.
        assert.equal(parsed.expiration, parsed.inception, 'validity 0 yields expiration equal to inception');
    } finally {
        config.dnssec.inceptionSkew = origSkew;
        config.dnssec.signatureValidity = origValidity;
    }
});
