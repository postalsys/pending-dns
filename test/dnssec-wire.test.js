'use strict';

// Pure unit tests for the DNSSEC wire layer. No Redis or network - safe to run
// anywhere. The cross-checks against dns2's own DNSKEY encoder/decoder and the
// RFC 4509 DS vector are what guarantee our bytes match what validators expect.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { promisify } = require('util');

const dns2 = require('dns2');
const Packet = dns2.Packet;

const wire = require('../lib/dnssec-wire');

const generateKeyPairAsync = promisify(crypto.generateKeyPair);

test('encodeName produces canonical lowercased uncompressed labels', () => {
    assert.equal(wire.encodeName('Example.COM').toString('hex'), '076578616d706c6503636f6d00');
    assert.equal(wire.encodeName('').toString('hex'), '00');
    assert.equal(wire.encodeName('example.com.').toString('hex'), wire.encodeName('example.com').toString('hex'));
});

test('nameLabelCount excludes root and leading wildcard', () => {
    assert.equal(wire.nameLabelCount('example.com'), 2);
    assert.equal(wire.nameLabelCount('www.example.com'), 3);
    assert.equal(wire.nameLabelCount('*.example.com'), 2);
    assert.equal(wire.nameLabelCount(''), 0);
});

test('nsecTypeBitmap encodes window blocks (RFC 4034 4.1.2)', () => {
    // bits 1 (A), 46 (RRSIG), 47 (NSEC) in window 0
    assert.equal(wire.nsecTypeBitmap([wire.TYPE.A, wire.TYPE.RRSIG, wire.TYPE.NSEC]).toString('hex'), '0006400000000003');
    // CAA (257) lives in window 1, bit 1
    assert.equal(wire.nsecTypeBitmap([wire.TYPE.CAA]).toString('hex'), '010140');
});

test('canonicalRdata matches dns2 wire RDATA for natively-encoded types', () => {
    const cases = [
        { type: wire.TYPE.A, rr: { address: '9.8.7.6' }, dns2: { name: 'x', type: Packet.TYPE.A, class: 1, ttl: 1, address: '9.8.7.6' } },
        { type: wire.TYPE.AAAA, rr: { address: '2001:db8::1' }, dns2: { name: 'x', type: Packet.TYPE.AAAA, class: 1, ttl: 1, address: '2001:db8::1' } },
        {
            type: wire.TYPE.MX,
            rr: { priority: 10, exchange: 'mx.example.com' },
            dns2: { name: 'x', type: Packet.TYPE.MX, class: 1, ttl: 1, priority: 10, exchange: 'mx.example.com' }
        },
        {
            type: wire.TYPE.TXT,
            rr: { data: ['hello', 'world'] },
            dns2: { name: 'x', type: Packet.TYPE.TXT, class: 1, ttl: 1, data: ['hello', 'world'] }
        },
        {
            type: wire.TYPE.CAA,
            rr: { flags: 0, tag: 'issue', value: 'letsencrypt.org' },
            dns2: { name: 'x', type: Packet.TYPE.CAA, class: 1, ttl: 1, flags: 0, tag: 'issue', value: 'letsencrypt.org' }
        }
    ];

    for (const c of cases) {
        // Extract dns2's RDATA by encoding a full resource and reparsing it.
        const buf = Packet.Resource.encode(c.dns2);
        const reparsed = Packet.Resource.parse(new Packet.Reader(buf));
        const reEncoded = Packet.Resource.encode(reparsed);
        // RDATA is the tail after name(uncompressed for a standalone record)+type(2)+class(2)+ttl(4)+rdlen(2).
        const nameLen = wire.encodeName(c.dns2.name).length;
        const dns2Rdata = reEncoded.slice(nameLen + 10);
        assert.equal(wire.canonicalRdata(c.type, c.rr).toString('hex'), dns2Rdata.toString('hex'), `type ${c.type}`);
    }
});

test('encodeDNSKEYRdata matches dns2 DNSKEY encoder byte-for-byte', async () => {
    const { publicKey } = await generateKeyPairAsync('ec', { namedCurve: 'prime256v1' });
    const jwk = publicKey.export({ format: 'jwk' });
    const pubkey = wire.ALGS[13].pubkeyFromJwk(jwk);

    const flags = wire.DNSKEY_FLAGS_CSK;
    const mine = wire.encodeDNSKEYRdata({ flags, protocol: wire.DNSKEY_PROTOCOL, algorithm: 13, pubkey });

    const writer = new Packet.Writer();
    Packet.Resource.DNSKEY.encode({ flags, protocol: wire.DNSKEY_PROTOCOL, algorithm: 13, key: pubkey.toString('base64') }, writer);
    const dns2Rdata = writer.toBuffer();

    assert.ok(mine.equals(dns2Rdata), 'DNSKEY RDATA must match dns2 output');
});

test('dnskeyKeyTag agrees with dns2 decoder', async () => {
    const { publicKey } = await generateKeyPairAsync('ed25519');
    const jwk = publicKey.export({ format: 'jwk' });
    const pubkey = wire.ALGS[15].pubkeyFromJwk(jwk);
    const rdata = wire.encodeDNSKEYRdata({ flags: 257, protocol: 3, algorithm: 15, pubkey });

    const decoded = Packet.Resource.DNSKEY.decode.call({}, new Packet.Reader(rdata), rdata.length);
    assert.equal(wire.dnskeyKeyTag(rdata), decoded.keyTag);
});

test('dsDigest and dnskeyKeyTag match the RFC 4509 example', () => {
    // dskey.example.com. DNSKEY 256 3 5 (...)  ->  DS 60485 5 2 D4B7...
    const pubkey = Buffer.from(
        'AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==',
        'base64'
    );
    const rdata = wire.encodeDNSKEYRdata({ flags: 256, protocol: 3, algorithm: 5, pubkey });

    assert.equal(wire.dnskeyKeyTag(rdata), 60485);
    assert.equal(
        wire.dsDigest('dskey.example.com', rdata, 2).toString('hex').toUpperCase(),
        'D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A'
    );
});

test('encodeTLSARdata lays out usage/selector/matchingType/cert', () => {
    const rdata = wire.encodeTLSARdata({ usage: 3, selector: 1, matchingType: 1, certificate: 'abcd' });
    assert.equal(rdata.toString('hex'), '030101abcd');
});

test('encodeTLSARdata rejects empty, odd-length, and out-of-range input', () => {
    // empty certificate would otherwise emit a TLSA with no association data
    assert.throws(() => wire.encodeTLSARdata({ usage: 3, selector: 1, matchingType: 1, certificate: '' }), /non-empty even-length hex/);
    assert.throws(() => wire.encodeTLSARdata({ usage: 3, selector: 1, matchingType: 1, certificate: 'abc' }), /even-length hex/);
    // u8() would otherwise wrap these silently (256 -> 0)
    assert.throws(() => wire.encodeTLSARdata({ usage: 256, selector: 1, matchingType: 1, certificate: 'abcd' }), /0-255/);
    assert.throws(() => wire.encodeTLSARdata({ usage: 3, selector: -1, matchingType: 1, certificate: 'abcd' }), /0-255/);
});

// RRSIG signing round-trips: prove the canonical signing input + per-algorithm
// crypto calls are internally consistent (the CI-grade DNSSEC guarantee).
for (const [algId, keygen] of [
    [13, ['ec', { namedCurve: 'prime256v1' }]],
    [15, ['ed25519', {}]],
    [8, ['rsa', { modulusLength: 2048, publicExponent: 65537 }]]
]) {
    test(`RRSIG over an A RRset verifies for algorithm ${algId} (${wire.ALGS[algId].name})`, async () => {
        const { publicKey, privateKey } = await generateKeyPairAsync(keygen[0], keygen[1]);

        const rrset = [
            { name: 'example.com', address: '1.2.3.4' },
            { name: 'example.com', address: '5.6.7.8' }
        ]
            .map(rr => wire.canonicalRdata(wire.TYPE.A, rr))
            .sort(wire.compareCanonicalRdata)
            .map(rdata => wire.canonicalRR('example.com', wire.TYPE.A, 1, 300, rdata));

        const preimage = wire.encodeRRSIGSigningPreimage({
            typeCovered: wire.TYPE.A,
            algorithm: algId,
            labels: wire.nameLabelCount('example.com'),
            originalTtl: 300,
            expiration: 2000000000,
            inception: 1000000000,
            keyTag: 12345,
            signerName: 'example.com'
        });

        const tbs = Buffer.concat([preimage, ...rrset]);
        const signature = wire.ALGS[algId].sign(tbs, privateKey);
        assert.ok(wire.ALGS[algId].verify(tbs, publicKey, signature), 'signature must verify');

        // A tampered RRset must fail.
        const tampered = Buffer.concat([preimage, ...rrset.slice(0, 1)]);
        assert.equal(wire.ALGS[algId].verify(tampered, publicKey, signature), false);
    });
}
