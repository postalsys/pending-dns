'use strict';

/* eslint-disable no-bitwise */

// End-to-end DNSSEC signing through the DNS handler (Redis db 15). RRSIGs are
// verified by reconstructing the canonical signing input and checking the
// signature with the public half of the zone key.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const dns2 = require('dns2');
const Packet = dns2.Packet;

const dnsHandler = require('../lib/dns-handler');
const dnssec = require('../lib/dnssec');
const wire = require('../lib/dnssec-wire');
const { zoneStore } = require('../lib/zone-store');
const { config, flushTestDb, closeDb } = require('./helpers');

test.after(async () => {
    await closeDb();
});

const DO = { hasOpt: true, doFlag: true };

const buildRequest = (name, type) => {
    const req = new Packet({});
    req.questions = [{ name, type: typeof type === 'number' ? type : Packet.TYPE[type], class: Packet.CLASS.IN }];
    req.source = { type: 'udp', address: '127.0.0.1', port: 5353 };
    return req;
};

const parseRRSIG = data => {
    let off = 18;
    while (data[off] !== 0) {
        off += 1 + data[off];
    }
    off += 1;
    return {
        typeCovered: data.readUInt16BE(0),
        algorithm: data.readUInt8(2),
        labels: data.readUInt8(3),
        originalTtl: data.readUInt32BE(4),
        keyTag: data.readUInt16BE(16),
        preimage: data.slice(0, off),
        signature: data.slice(off)
    };
};

// Find the RRSIG covering `typeNum` at `owner` in a section and verify it the
// way a real validator would. `signingOwner` is the name the signature was
// computed over: for a wildcard expansion that is the wildcard owner
// (`*.zone`), reconstructed from the RRSIG labels (RFC 4035 5.3.2), not the
// expanded wire owner.
const verifyRRSIG = async (section, owner, typeNum, zone, signingOwner) => {
    signingOwner = signingOwner || owner;
    const signer = await dnssec.getSigner(zone);
    const rrs = section.filter(rr => rr.name === owner && rr.type === typeNum);
    assert.ok(rrs.length, `expected ${typeNum} records at ${owner}`);
    const rrsig = section.find(rr => rr.type === wire.TYPE.RRSIG && rr.name === owner && rr.data.readUInt16BE(0) === typeNum);
    assert.ok(rrsig, `expected an RRSIG covering ${typeNum} at ${owner}`);

    const parsed = parseRRSIG(rrsig.data);
    const canonical = rrs
        .map(rr => wire.canonicalRdata(typeNum, rr))
        .sort(wire.compareCanonicalRdata)
        .map(rdata => wire.canonicalRR(signingOwner, typeNum, 1, parsed.originalTtl, rdata));
    const tbs = Buffer.concat([parsed.preimage, ...canonical]);
    // Pick the key whose algorithm matches this RRSIG (a zone mid-rollover has
    // one signing key per algorithm).
    const key = signer.keys.find(k => k.algorithm === parsed.algorithm) || signer.keys[0];
    const publicKey = crypto.createPublicKey(key.privateKeyObj);
    assert.ok(wire.ALGS[parsed.algorithm].verify(tbs, publicKey, parsed.signature), `RRSIG over ${typeNum} must verify`);
    return parsed;
};

test('a signed A answer carries a verifiable RRSIG (and no AD bit)', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '', 'A', ['9.8.7.6']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('example.com', 'A'), DO);
    // AD is a validating-resolver signal (RFC 6840 5.7); an authoritative server
    // leaves it clear.
    assert.notEqual(response.header.ad, 1);
    assert.ok(response.answers.some(a => a.type === Packet.TYPE.A));
    await verifyRRSIG(response.answers, 'example.com', Packet.TYPE.A, 'example.com');
});

test('a DNSKEY query returns a self-signed DNSKEY RRset', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '', 'A', ['9.8.7.6']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('example.com', 'DNSKEY'), DO);
    assert.ok(
        response.answers.some(a => a.type === wire.TYPE.DNSKEY),
        'DNSKEY present'
    );
    await verifyRRSIG(response.answers, 'example.com', wire.TYPE.DNSKEY, 'example.com');
});

test('a signed CAA answer carries a verifiable RRSIG', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '', 'CAA', ['letsencrypt.org', 'issue', 0]);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('example.com', 'CAA'), DO);
    assert.ok(
        response.answers.some(a => a.type === Packet.TYPE.CAA),
        'CAA answer is returned'
    );
    // CAA uses dns2's native encoder; the RRSIG must verify over its canonical RDATA.
    await verifyRRSIG(response.answers, 'example.com', Packet.TYPE.CAA, 'example.com');
});

test('a signed TLSA answer carries a verifiable RRSIG (raw-RDATA type)', async () => {
    await flushTestDb();
    const certHex = '92003ba34942dc74152e2f2c408d29eca5a520e7f2e06bb944f4dca346baf63c';
    await zoneStore.add('example.com', '_443._tcp.www', 'TLSA', [3, 1, 1, certHex]);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('_443._tcp.www.example.com', wire.TYPE.TLSA), DO);
    assert.ok(
        response.answers.some(a => a.type === wire.TYPE.TLSA),
        'TLSA answer is returned'
    );
    // TLSA is emitted as pre-built raw RDATA (the {type, data} path); the RRSIG must
    // verify over those exact bytes.
    await verifyRRSIG(response.answers, '_443._tcp.www.example.com', wire.TYPE.TLSA, 'example.com');
});

test('NODATA is proven with a signed SOA and NSEC (NOERROR)', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '', 'A', ['9.8.7.6']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('example.com', 'TXT'), DO);
    assert.equal(response.header.rcode || 0, 0, 'NODATA is NOERROR');
    assert.equal(response.answers.length, 0);

    const nsec = response.authorities.find(a => a.type === wire.TYPE.NSEC);
    assert.ok(nsec, 'NSEC present in authority');
    assert.ok(
        response.authorities.some(a => a.type === Packet.TYPE.SOA),
        'SOA present in authority'
    );

    // bitmap must include A (exists) and CAA (synthesized for every name) but
    // not TXT (queried, absent)
    const bitmap = nsec.data.slice(wire.encodeName('example.com').length);
    const present = decodeBitmap(bitmap);
    assert.ok(present.has(Packet.TYPE.A), 'A is listed');
    assert.ok(present.has(Packet.TYPE.CAA), 'CAA is listed (synthesized for any name)');
    assert.ok(!present.has(Packet.TYPE.TXT), 'TXT is not listed');

    // NSEC TTL tracks the SOA minimum so the proof and the negative answer
    // expire together (RFC 2308).
    assert.equal(nsec.ttl, config.soa.minimum, 'NSEC TTL equals the SOA minimum');

    await verifyRRSIG(response.authorities, 'example.com', wire.TYPE.NSEC, 'example.com');
    await verifyRRSIG(response.authorities, 'example.com', Packet.TYPE.SOA, 'example.com');
});

test('a nonexistent name is denied with signed NODATA (NOERROR, black lies)', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '', 'A', ['9.8.7.6']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('nope.example.com', 'A'), DO);
    // Denial is always NOERROR - never wire NXDOMAIN - because the server can
    // synthesize CAA/NS/SOA for any name, so no name is truly nonexistent.
    assert.equal(response.header.rcode || 0, 0, 'denial is NOERROR, never NXDOMAIN');
    assert.equal(response.answers.length, 0);
    const nsec = response.authorities.find(a => a.type === wire.TYPE.NSEC && a.name === 'nope.example.com');
    assert.ok(nsec, 'NSEC at the queried name');
    await verifyRRSIG(response.authorities, 'nope.example.com', wire.TYPE.NSEC, 'example.com');
});

test('a name covered only by a wildcard is NODATA (NOERROR) for other types', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '*', 'A', ['1.2.3.4']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const a = await dnsHandler(buildRequest('nope.example.com', 'A'), DO);
    assert.ok(
        a.answers.some(rr => rr.type === Packet.TYPE.A),
        'the wildcard answers A'
    );

    // The same name queried for a type the wildcard does not supply must be
    // NODATA (NOERROR), not NXDOMAIN - the name exists via the wildcard.
    const aaaa = await dnsHandler(buildRequest('nope.example.com', 'AAAA'), DO);
    assert.equal(aaaa.header.rcode || 0, 0, 'AAAA at a wildcard-covered name is NODATA, not NXDOMAIN');
});

test('a wildcard answer is signed over the wildcard owner with reduced labels and a proving NSEC', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '*', 'A', ['1.1.1.1']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('foo.example.com', 'A'), DO);
    // The signature must verify when reconstructed with the wildcard owner
    // (*.example.com), which is what a real validator does (RFC 4035 5.3.2).
    const parsed = await verifyRRSIG(response.answers, 'foo.example.com', Packet.TYPE.A, 'example.com', '*.example.com');
    assert.equal(parsed.labels, 2, 'RRSIG labels reflect the wildcard owner, not the qname');

    // It must NOT verify when reconstructed with the expanded query name - that
    // would be the bug where the server signed over the wrong owner.
    const signer = await dnssec.getSigner('example.com');
    const aRecords = response.answers.filter(rr => rr.name === 'foo.example.com' && rr.type === Packet.TYPE.A);
    const rrsig = response.answers.find(rr => rr.type === wire.TYPE.RRSIG && rr.name === 'foo.example.com');
    const p = parseRRSIG(rrsig.data);
    const expandedCanonical = aRecords
        .map(rr => wire.canonicalRdata(Packet.TYPE.A, rr))
        .sort(wire.compareCanonicalRdata)
        .map(rd => wire.canonicalRR('foo.example.com', Packet.TYPE.A, 1, p.originalTtl, rd));
    const pub = crypto.createPublicKey(signer.keys[0].privateKeyObj);
    assert.equal(
        wire.ALGS[p.algorithm].verify(Buffer.concat([p.preimage, ...expandedCanonical]), pub, p.signature),
        false,
        'must NOT verify when reconstructed with the expanded owner'
    );

    assert.ok(
        response.authorities.some(a => a.type === wire.TYPE.NSEC && a.name === 'foo.example.com'),
        'a proving NSEC for the exact name is included'
    );
});

test('an IDN zone signs with punycode (A-label) names', async () => {
    await flushTestDb();
    await zoneStore.add('xn--mnchen-3ya.example', '', 'A', ['9.8.7.6']);
    await dnssec.enableZone('xn--mnchen-3ya.example', { algorithm: 13 });

    const signer = await dnssec.getSigner('xn--mnchen-3ya.example');
    assert.equal(signer.zone, 'xn--mnchen-3ya.example', 'signer name is the A-label form, not Unicode');

    // Query using the Unicode form; the answer + RRSIG must use A-label names so
    // a validator that follows the punycode delegation can verify.
    // Query in the Unicode form (escaped so the source stays printable ASCII per
    // CLAUDE.md); 'm\u00fcnchen.example' is the IDN for the xn--mnchen-3ya zone above.
    const response = await dnsHandler(buildRequest('m\u00fcnchen.example', 'A'), DO);
    await verifyRRSIG(response.answers, 'xn--mnchen-3ya.example', Packet.TYPE.A, 'xn--mnchen-3ya.example');
});

test('a delegation (non-apex) NS RRset is not signed; apex NS is', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '', 'NS', ['ns1.example.com']);
    await zoneStore.add('example.com', 'sub', 'NS', ['ns1.other.example']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const apex = await dnsHandler(buildRequest('example.com', 'NS'), DO);
    assert.ok(
        apex.answers.some(rr => rr.type === wire.TYPE.RRSIG && rr.name === 'example.com' && rr.data.readUInt16BE(0) === Packet.TYPE.NS),
        'apex NS is signed'
    );

    const deleg = await dnsHandler(buildRequest('sub.example.com', 'NS'), DO);
    assert.ok(
        deleg.answers.some(rr => rr.type === Packet.TYPE.NS && rr.name === 'sub.example.com'),
        'delegation NS is returned'
    );
    assert.ok(!deleg.answers.some(rr => rr.type === wire.TYPE.RRSIG && rr.name === 'sub.example.com'), 'delegation NS RRset is not signed (RFC 4035 2.2)');
});

test('after an algorithm rollover every RRset carries an RRSIG per algorithm', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '', 'A', ['9.8.7.6']);
    await dnssec.enableZone('example.com', { algorithm: 13 });
    await dnssec.enableZone('example.com', { algorithm: 15 });

    const response = await dnsHandler(buildRequest('example.com', 'A'), DO);
    const sigs = response.answers.filter(rr => rr.type === wire.TYPE.RRSIG && rr.name === 'example.com' && rr.data.readUInt16BE(0) === Packet.TYPE.A);
    assert.equal(sigs.length, 2, 'one A RRSIG per algorithm during rollover');
    assert.deepEqual(
        sigs.map(s => parseRRSIG(s.data).algorithm).sort((a, b) => a - b),
        [13, 15]
    );

    // Both RRSIGs must verify with their respective key.
    const signer = await dnssec.getSigner('example.com');
    const aRecords = response.answers.filter(rr => rr.name === 'example.com' && rr.type === Packet.TYPE.A);
    for (const sig of sigs) {
        const parsed = parseRRSIG(sig.data);
        const canonical = aRecords
            .map(rr => wire.canonicalRdata(Packet.TYPE.A, rr))
            .sort(wire.compareCanonicalRdata)
            .map(rd => wire.canonicalRR('example.com', Packet.TYPE.A, 1, parsed.originalTtl, rd));
        const key = signer.keys.find(k => k.algorithm === parsed.algorithm);
        const pub = crypto.createPublicKey(key.privateKeyObj);
        assert.ok(
            wire.ALGS[parsed.algorithm].verify(Buffer.concat([parsed.preimage, ...canonical]), pub, parsed.signature),
            `alg ${parsed.algorithm} RRSIG verifies`
        );
    }
});

test('without the DO bit the response is unsigned', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '', 'A', ['9.8.7.6']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('example.com', 'A'));
    assert.ok(!response.answers.some(a => a.type === wire.TYPE.RRSIG), 'no RRSIG without DO');
    assert.notEqual(response.header.ad, 1);
});

test('a duplicate-valued RRset is signed over the de-duplicated set (RFC 4034 6.3)', async () => {
    await flushTestDb();
    // The API/store assigns a fresh hid per add, so the same value can be stored twice.
    await zoneStore.add('example.com', 'dup', 'A', ['1.2.3.4']);
    await zoneStore.add('example.com', 'dup', 'A', ['1.2.3.4']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('dup.example.com', 'A'), DO);
    const aRecords = response.answers.filter(rr => rr.name === 'dup.example.com' && rr.type === Packet.TYPE.A);
    assert.equal(aRecords.length, 2, 'both duplicate A records are returned');

    const rrsig = response.answers.find(rr => rr.type === wire.TYPE.RRSIG && rr.name === 'dup.example.com' && rr.data.readUInt16BE(0) === Packet.TYPE.A);
    assert.ok(rrsig, 'an A RRSIG is present');
    const parsed = parseRRSIG(rrsig.data);

    // Reconstruct the way a validator does: de-duplicate identical RRs first.
    const dedup = [...new Map(aRecords.map(rr => [wire.canonicalRdata(Packet.TYPE.A, rr).toString('hex'), rr])).values()];
    assert.equal(dedup.length, 1, 'the RRset de-duplicates to a single RR');
    const canonical = dedup
        .map(rr => wire.canonicalRdata(Packet.TYPE.A, rr))
        .sort(wire.compareCanonicalRdata)
        .map(rd => wire.canonicalRR('dup.example.com', Packet.TYPE.A, 1, parsed.originalTtl, rd));
    const signer = await dnssec.getSigner('example.com');
    const pub = crypto.createPublicKey(signer.keys[0].privateKeyObj);
    assert.ok(
        wire.ALGS[parsed.algorithm].verify(Buffer.concat([parsed.preimage, ...canonical]), pub, parsed.signature),
        'RRSIG verifies over the de-duplicated RRset'
    );
});

test('non-apex NODATA NSEC bitmap lists SOA but not NS', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '', 'A', ['9.8.7.6']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('nope.example.com', 'A'), DO);
    const nsec = response.authorities.find(a => a.type === wire.TYPE.NSEC && a.name === 'nope.example.com');
    assert.ok(nsec, 'NSEC at the queried name');
    const present = decodeBitmap(nsec.data.slice(wire.encodeName('nope.example.com').length));
    assert.ok(present.has(Packet.TYPE.SOA), 'SOA is listed (synthesized for any name)');
    assert.ok(present.has(Packet.TYPE.CAA), 'CAA is listed');
    assert.ok(!present.has(Packet.TYPE.NS), 'NS is NOT listed below the apex (would signal a delegation)');
});

test('a wildcard-covered NODATA bitmap lists the wildcard type so it cannot be suppressed', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '*', 'A', ['1.2.3.4']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    // Query a type the wildcard does NOT supply -> NODATA. The bitmap must still
    // list A so an RFC 8198 aggressive-NSEC resolver cannot synthesize a NODATA
    // that suppresses the wildcard A on a later query.
    const response = await dnsHandler(buildRequest('foo.example.com', 'AAAA'), DO);
    const nsec = response.authorities.find(a => a.type === wire.TYPE.NSEC && a.name === 'foo.example.com');
    assert.ok(nsec, 'NSEC at the queried name');
    const present = decodeBitmap(nsec.data.slice(wire.encodeName('foo.example.com').length));
    assert.ok(present.has(Packet.TYPE.A), 'the wildcard-supplied A is listed');
    assert.ok(!present.has(Packet.TYPE.AAAA), 'the queried-absent AAAA is not listed');
});

test('a wildcard-positive proving NSEC excludes the answered type', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '*', 'A', ['1.1.1.1']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('foo.example.com', 'A'), DO);
    assert.ok(
        response.answers.some(rr => rr.type === Packet.TYPE.A && rr.name === 'foo.example.com'),
        'the wildcard answers A'
    );
    const nsec = response.authorities.find(a => a.type === wire.TYPE.NSEC && a.name === 'foo.example.com');
    assert.ok(nsec, 'a proving NSEC is included');
    const present = decodeBitmap(nsec.data.slice(wire.encodeName('foo.example.com').length));
    assert.ok(!present.has(Packet.TYPE.A), 'the proving NSEC must not list the wildcard-answered type');
});

test('a below-apex record-less NS query is a signed NODATA (not unsigned NS)', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '', 'A', ['9.8.7.6']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('sub.example.com', 'NS'), DO);
    // No synthesized (unsigned) NS in the answer below the apex.
    assert.ok(!response.answers.some(rr => rr.type === Packet.TYPE.NS), 'no NS records in the answer');
    assert.equal(response.header.rcode || 0, 0, 'NODATA is NOERROR');

    const nsec = response.authorities.find(a => a.type === wire.TYPE.NSEC && a.name === 'sub.example.com');
    assert.ok(nsec, 'a signed NSEC denial is present at the queried name');
    assert.ok(
        response.authorities.some(a => a.type === Packet.TYPE.SOA),
        'SOA present in authority'
    );

    // The NSEC bitmap must NOT set the NS bit below the apex (RFC 4034 4.1.3).
    const present = decodeBitmap(nsec.data.slice(wire.encodeName('sub.example.com').length));
    assert.ok(!present.has(Packet.TYPE.NS), 'NSEC bitmap does not list NS below the apex');

    await verifyRRSIG(response.authorities, 'sub.example.com', wire.TYPE.NSEC, 'example.com');
    await verifyRRSIG(response.authorities, 'example.com', Packet.TYPE.SOA, 'example.com');
});

test('an apex NS query is still answered with signed (synthesized) NS', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '', 'A', ['9.8.7.6']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('example.com', 'NS'), DO);
    assert.ok(
        response.answers.some(rr => rr.type === Packet.TYPE.NS && rr.name === 'example.com'),
        'apex NS is synthesized'
    );
    await verifyRRSIG(response.answers, 'example.com', Packet.TYPE.NS, 'example.com');
});

test('a multi-question NODATA packet emits a single SOA and NSEC per owner', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '', 'A', ['9.8.7.6']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const req = new Packet({});
    req.questions = [
        { name: 'nope.example.com', type: Packet.TYPE.TXT, class: Packet.CLASS.IN },
        { name: 'nope.example.com', type: Packet.TYPE.MX, class: Packet.CLASS.IN }
    ];
    req.source = { type: 'udp', address: '127.0.0.1', port: 5353 };

    const response = await dnsHandler(req, DO);
    const nsec = response.authorities.filter(a => a.type === wire.TYPE.NSEC && a.name === 'nope.example.com');
    const soa = response.authorities.filter(a => a.type === Packet.TYPE.SOA && a.name === 'example.com');
    assert.equal(nsec.length, 1, 'exactly one NSEC at the owner');
    assert.equal(soa.length, 1, 'exactly one SOA in the authority');
    await verifyRRSIG(response.authorities, 'nope.example.com', wire.TYPE.NSEC, 'example.com');
});

test('a multi-question wildcard+NODATA packet emits one consistent NSEC per owner', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '*', 'A', ['1.2.3.4']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    // {A (wildcard hit), AAAA (NODATA)} at the same name previously produced two
    // contradictory NSEC RDATAs (one with the A bit, one without) signed as one RRset.
    const req = new Packet({});
    req.questions = [
        { name: 'foo.example.com', type: Packet.TYPE.A, class: Packet.CLASS.IN },
        { name: 'foo.example.com', type: Packet.TYPE.AAAA, class: Packet.CLASS.IN }
    ];
    req.source = { type: 'udp', address: '127.0.0.1', port: 5353 };

    const response = await dnsHandler(req, DO);
    const nsec = response.authorities.filter(a => a.type === wire.TYPE.NSEC && a.name === 'foo.example.com');
    assert.equal(nsec.length, 1, 'exactly one NSEC at foo.example.com (no contradictory pair)');
    assert.ok(
        response.answers.some(rr => rr.type === Packet.TYPE.A && rr.name === 'foo.example.com'),
        'wildcard A is still answered'
    );
    await verifyRRSIG(response.authorities, 'foo.example.com', wire.TYPE.NSEC, 'example.com');
});

test('an ANY query for a record-less name is a signed NODATA', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', '', 'A', ['9.8.7.6']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('ghost.example.com', 'ANY'), DO);
    assert.equal(response.answers.length, 0, 'no answers');
    const nsec = response.authorities.find(a => a.type === wire.TYPE.NSEC && a.name === 'ghost.example.com');
    assert.ok(nsec, 'a signed NSEC denial is present for ANY NODATA');
    assert.ok(
        response.authorities.some(a => a.type === Packet.TYPE.SOA),
        'SOA present in authority'
    );
    await verifyRRSIG(response.authorities, 'ghost.example.com', wire.TYPE.NSEC, 'example.com');
});

test('an ANY query at a name with records returns them with no denial', async () => {
    await flushTestDb();
    await zoneStore.add('example.com', 'host', 'A', ['9.8.7.6']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('host.example.com', 'ANY'), DO);
    assert.ok(
        response.answers.some(rr => rr.type === Packet.TYPE.A && rr.name === 'host.example.com'),
        'A is returned for ANY'
    );
    assert.ok(!response.authorities.some(a => a.type === wire.TYPE.NSEC), 'no NSEC denial when records exist');
});

test('a URL record does not put an unanswerable AAAA in the NODATA NSEC bitmap', async () => {
    await flushTestDb();
    // config.public.hosts.AAAA defaults to [] - a URL record answers no AAAA, so an
    // AAAA query is NODATA. The NSEC bitmap must NOT claim AAAA exists, or a
    // validating resolver treats the (denied-but-listed) AAAA answer as bogus.
    await zoneStore.add('example.com', 'www', 'URL', ['https://example.com/', 301, false]);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('www.example.com', 'AAAA'), DO);
    assert.equal(response.answers.filter(a => a.type === Packet.TYPE.AAAA).length, 0, 'AAAA is NODATA when public.hosts.AAAA is empty');
    const nsec = response.authorities.find(a => a.type === wire.TYPE.NSEC && a.name === 'www.example.com');
    assert.ok(nsec, 'a signed NSEC denial is present at the queried name');
    const present = decodeBitmap(nsec.data.slice(wire.encodeName('www.example.com').length));
    assert.ok(!present.has(Packet.TYPE.AAAA), 'AAAA must NOT be listed (unanswerable + queried-absent)');
    assert.ok(present.has(Packet.TYPE.A), 'A is listed (the URL answers A from a non-empty public.hosts.A)');
    await verifyRRSIG(response.authorities, 'www.example.com', wire.TYPE.NSEC, 'example.com');
});

test('an ANAME with no resolvable AAAA gives a NODATA NSEC without the AAAA bit', async () => {
    await flushTestDb();
    // The ANAME target does not resolve (RFC 6761 reserved .invalid TLD), so the
    // AAAA query is NODATA. The queried-absent type must be excluded from the bitmap.
    await zoneStore.add('example.com', 'alias', 'ANAME', ['no-such-host.invalid']);
    await dnssec.enableZone('example.com', { algorithm: 13 });

    const response = await dnsHandler(buildRequest('alias.example.com', 'AAAA'), DO);
    assert.equal(response.answers.filter(a => a.type === Packet.TYPE.AAAA).length, 0, 'AAAA is NODATA');
    const nsec = response.authorities.find(a => a.type === wire.TYPE.NSEC && a.name === 'alias.example.com');
    assert.ok(nsec, 'a signed NSEC denial is present at the queried name');
    const present = decodeBitmap(nsec.data.slice(wire.encodeName('alias.example.com').length));
    assert.ok(!present.has(Packet.TYPE.AAAA), 'AAAA must NOT be listed when the ANAME yields no AAAA');
    await verifyRRSIG(response.authorities, 'alias.example.com', wire.TYPE.NSEC, 'example.com');
});

// Minimal NSEC type-bitmap decoder for assertions.
function decodeBitmap(buf) {
    const types = new Set();
    let i = 0;
    while (i < buf.length) {
        const window = buf[i++];
        const len = buf[i++];
        for (let b = 0; b < len; b++) {
            const byte = buf[i + b];
            for (let bit = 0; bit < 8; bit++) {
                if (byte & (0x80 >> bit)) {
                    types.add((window << 8) | (b * 8 + bit));
                }
            }
        }
        i += len;
    }
    return types;
}
