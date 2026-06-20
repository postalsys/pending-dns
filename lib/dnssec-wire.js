'use strict';

/* eslint-disable no-bitwise */
// Bit/byte manipulation is intrinsic to DNS wire encoding.

// Pure DNSSEC wire-format layer. No Redis, no config, no I/O - only `crypto`
// (for DS digests) and `ipaddr.js` (to turn an AAAA string into 16 octets).
// Everything here is deterministic and unit-testable in isolation.
//
// Invariant: DNSSEC signatures are computed over the canonical, UNCOMPRESSED,
// lowercased wire form produced here (RFC 4034 6.2), never over what dns2
// serializes. dns2 may apply name compression on the wire; validators
// decompress and re-canonicalize before verifying, so the two always agree.

const crypto = require('crypto');
const ipaddr = require('ipaddr.js');

// IANA RR type numbers used by this server. dns2's Packet.TYPE only knows a
// subset; these fill the gaps so the dns-handler normalize loop and the signer
// can address every type by number.
const TYPE = {
    A: 1,
    NS: 2,
    CNAME: 5,
    SOA: 6,
    MX: 15,
    TXT: 16,
    AAAA: 28,
    SRV: 33,
    DS: 43,
    RRSIG: 46,
    NSEC: 47,
    DNSKEY: 48,
    TLSA: 52,
    CDS: 59,
    CDNSKEY: 60,
    CAA: 257
};

// Types dns2 cannot encode natively (not in its Packet.TYPE). The dns-handler
// emits these by setting `{ type:<num>, data:<Buffer> }`, which routes through
// dns2's raw-RDATA fallback (RFC 3597).
const EXTRA_TYPES = {
    TLSA: TYPE.TLSA,
    RRSIG: TYPE.RRSIG,
    NSEC: TYPE.NSEC,
    DS: TYPE.DS,
    CDS: TYPE.CDS,
    CDNSKEY: TYPE.CDNSKEY
};

const u8 = value => Buffer.from([value & 0xff]);

const u16 = value => {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(value & 0xffff, 0);
    return b;
};

const u32 = value => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(value >>> 0, 0);
    return b;
};

const b64url = value => Buffer.from((value || '').toString(), 'base64url');

const MAX_LABEL = 63;

// Canonical, uncompressed, lowercased wire form of a domain name (RFC 4034 6.2).
// Input names are already punycode ASCII by the time they reach here.
const encodeName = name => {
    name = (name || '').toString().replace(/\.+$/, '').toLowerCase();
    if (!name) {
        return Buffer.from([0]);
    }
    const parts = [];
    for (const label of name.split('.')) {
        if (!label.length) {
            continue;
        }
        const buf = Buffer.from(label, 'utf8');
        if (buf.length > MAX_LABEL) {
            throw new Error(`Name encode: label "${label}" exceeds ${MAX_LABEL} octets`);
        }
        parts.push(u8(buf.length), buf);
    }
    parts.push(Buffer.from([0]));
    return Buffer.concat(parts);
};

// RFC 4034 3.1.3 label count: excludes the root and a leading "*" wildcard.
const nameLabelCount = name => {
    name = (name || '').toString().replace(/\.+$/, '').toLowerCase();
    if (!name) {
        return 0;
    }
    let labels = name.split('.').filter(label => label.length);
    if (labels[0] === '*') {
        labels = labels.slice(1);
    }
    return labels.length;
};

// One DNS character-string list, matching dns2's TXT encoder byte-for-byte
// (length octet + bytes per chunk). `data` is an array of <=255 byte strings.
const encodeCharacterStrings = data => {
    const chunks = (Array.isArray(data) ? data : [data]).map(chunk => (Buffer.isBuffer(chunk) ? chunk : Buffer.from((chunk || '').toString(), 'utf8')));
    const parts = [];
    for (const chunk of chunks) {
        parts.push(u8(chunk.length), chunk);
    }
    return Buffer.concat(parts);
};

const encodeDNSKEYRdata = ({ flags, protocol, algorithm, pubkey }) =>
    // DNSKEY public keys are presented in standard base64 (RFC 4034), not base64url.
    Buffer.concat([u16(flags), u8(protocol), u8(algorithm), Buffer.isBuffer(pubkey) ? pubkey : Buffer.from((pubkey || '').toString(), 'base64')]);

// Canonical RDATA for a single resource record (RFC 4034 6.2). For the types
// dns2 encodes natively this MUST reproduce dns2's wire RDATA (modulo name
// compression/case, which validators normalize); for the raw types the handler
// has already built `rr.data` so we pass it straight through.
const canonicalRdata = (type, rr) => {
    if (Buffer.isBuffer(rr.data)) {
        // TLSA/DS/NSEC/RRSIG and any other pre-built raw RDATA.
        return rr.data;
    }

    switch (type) {
        case TYPE.A:
            return Buffer.from(rr.address.split('.').map(part => parseInt(part, 10) & 0xff));

        case TYPE.AAAA:
            return Buffer.from(ipaddr.parse(rr.address).toByteArray());

        case TYPE.NS:
            return encodeName(rr.ns);

        case TYPE.CNAME:
            return encodeName(rr.domain);

        case TYPE.MX:
            return Buffer.concat([u16(rr.priority), encodeName(rr.exchange)]);

        case TYPE.TXT:
            return encodeCharacterStrings(rr.data !== undefined ? rr.data : rr.value);

        case TYPE.CAA: {
            const tag = (rr.tag || '').toString();
            const value = (rr.value || '').toString();
            return Buffer.concat([u8(rr.flags || 0), u8(tag.length), Buffer.from(tag + value, 'utf8')]);
        }

        case TYPE.SOA:
            return Buffer.concat([
                encodeName(rr.primary),
                encodeName(rr.admin),
                u32(rr.serial),
                u32(rr.refresh),
                u32(rr.retry),
                u32(rr.expiration),
                u32(rr.minimum)
            ]);

        case TYPE.DNSKEY:
            return encodeDNSKEYRdata({ flags: rr.flags, protocol: rr.protocol, algorithm: rr.algorithm, pubkey: rr.key });

        default:
            throw new Error(`canonicalRdata: unsupported type ${type}`);
    }
};

// Canonical wire form of a full RR for signing (RFC 4034 6.2): owner name,
// type, class, the RRSIG Original TTL, RDLENGTH and canonical RDATA.
const canonicalRR = (name, type, klass, ttl, rdata) => Buffer.concat([encodeName(name), u16(type), u16(klass), u32(ttl), u16(rdata.length), rdata]);

const compareCanonicalRdata = (a, b) => Buffer.compare(a, b);

const encodeTLSARdata = ({ usage, selector, matchingType, certificate }) => {
    const hex = (certificate || '').toString();
    // Buffer.from(hex, 'hex') silently drops a trailing nibble / invalid chars,
    // and an empty string would serve a TLSA with no association data - both are
    // corrupt DANE records. Fail loud instead; callers on the query path skip the
    // record rather than dropping the whole response.
    if (!hex.length || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
        throw new Error('encodeTLSARdata: certificate must be non-empty even-length hex');
    }
    // u8() masks to a single byte, so reject out-of-range fields instead of
    // wrapping them (usage 256 -> 0 would silently flip the cert-usage semantics).
    for (const field of [usage, selector, matchingType]) {
        if (!Number.isInteger(field) || field < 0 || field > 255) {
            throw new Error('encodeTLSARdata: usage/selector/matchingType must be integers in 0-255');
        }
    }
    return Buffer.concat([u8(usage), u8(selector), u8(matchingType), Buffer.from(hex, 'hex')]);
};

// RFC 4034 Appendix B key tag, computed over the full DNSKEY RDATA.
const dnskeyKeyTag = rdata => {
    let ac = 0;
    for (let i = 0; i < rdata.length; i++) {
        ac += i & 1 ? rdata[i] : rdata[i] << 8;
    }
    ac += (ac >> 16) & 0xffff;
    return ac & 0xffff;
};

const DIGEST_ALG = { 1: 'sha1', 2: 'sha256', 4: 'sha384' };

// DS digest (RFC 4034 5.1.4): hash of canonical owner name || DNSKEY RDATA.
const dsDigest = (ownerName, dnskeyRdata, digestType) => {
    const algo = DIGEST_ALG[digestType];
    if (!algo) {
        throw new Error(`dsDigest: unsupported digest type ${digestType}`);
    }
    return crypto
        .createHash(algo)
        .update(Buffer.concat([encodeName(ownerName), dnskeyRdata]))
        .digest();
};

// RFC 4034 4.1.2 type bitmap: window-block list, each block is
// window(1) || bitmapLength(1) || bitmap. Empty windows are omitted.
const nsecTypeBitmap = typeNums => {
    const windows = new Map();
    for (const type of typeNums) {
        const window = type >> 8;
        const bit = type & 0xff;
        if (!windows.has(window)) {
            windows.set(window, []);
        }
        windows.get(window).push(bit);
    }

    const blocks = [];
    for (const window of [...windows.keys()].sort((a, b) => a - b)) {
        const bits = windows.get(window);
        const maxBit = Math.max(...bits);
        const bitmap = Buffer.alloc((maxBit >> 3) + 1);
        for (const bit of bits) {
            bitmap[bit >> 3] |= 0x80 >> (bit & 7);
        }
        blocks.push(u8(window), u8(bitmap.length), bitmap);
    }
    return Buffer.concat(blocks);
};

const encodeNSECRdata = (nextName, typeNums) => Buffer.concat([encodeName(nextName), nsecTypeBitmap(typeNums)]);

// RRSIG RDATA up to and including the signer name - the bytes that, prepended
// to the canonical RRset, form the signing input (RFC 4034 3.1.8.1).
const encodeRRSIGSigningPreimage = ({ typeCovered, algorithm, labels, originalTtl, expiration, inception, keyTag, signerName }) =>
    Buffer.concat([u16(typeCovered), u8(algorithm), u8(labels), u32(originalTtl), u32(expiration), u32(inception), u16(keyTag), encodeName(signerName)]);

const encodeRRSIGRdata = (fields, signature) => Buffer.concat([encodeRRSIGSigningPreimage(fields), signature]);

// Per-algorithm crypto. `sign`/`verify` operate on the canonical signing input
// (the validator-visible bytes), `pubkeyFromJwk` yields the DNSSEC public-key
// octets that go into DNSKEY RDATA. Key tags 8/13/15 cover the algorithms this
// server offers; the table is the single place to add more.
const ALGS = {
    // RSASHA256
    8: {
        name: 'RSASHA256',
        dsDigestType: 2,
        generate: { type: 'rsa', options: { modulusLength: 2048, publicExponent: 65537 } },
        sign: (tbs, key) => crypto.sign('sha256', tbs, { key, padding: crypto.constants.RSA_PKCS1_PADDING }),
        verify: (tbs, key, sig) => crypto.verify('sha256', tbs, { key, padding: crypto.constants.RSA_PKCS1_PADDING }, sig),
        // RFC 3110: exponent length prefix, exponent, modulus.
        pubkeyFromJwk: jwk => {
            const exp = b64url(jwk.e);
            const mod = b64url(jwk.n);
            const prefix = exp.length < 256 ? Buffer.from([exp.length]) : Buffer.concat([Buffer.from([0]), u16(exp.length)]);
            return Buffer.concat([prefix, exp, mod]);
        }
    },

    // ECDSAP256SHA256 - signature is raw r||s (IEEE P1363), 64 bytes (RFC 6605).
    13: {
        name: 'ECDSAP256SHA256',
        dsDigestType: 2,
        generate: { type: 'ec', options: { namedCurve: 'prime256v1' } },
        sign: (tbs, key) => crypto.sign('sha256', tbs, { key, dsaEncoding: 'ieee-p1363' }),
        verify: (tbs, key, sig) => crypto.verify('sha256', tbs, { key, dsaEncoding: 'ieee-p1363' }, sig),
        // Uncompressed point x||y without the 0x04 prefix.
        pubkeyFromJwk: jwk => Buffer.concat([b64url(jwk.x), b64url(jwk.y)])
    },

    // ED25519 - signature already raw 64 bytes (RFC 8080).
    15: {
        name: 'ED25519',
        dsDigestType: 2,
        generate: { type: 'ed25519', options: {} },
        sign: (tbs, key) => crypto.sign(null, tbs, key),
        verify: (tbs, key, sig) => crypto.verify(null, tbs, key, sig),
        pubkeyFromJwk: jwk => b64url(jwk.x)
    }
};

module.exports = {
    TYPE,
    EXTRA_TYPES,
    DNSKEY_FLAGS_CSK: 257, // ZONE (bit 7) + SEP (bit 15)
    DNSKEY_PROTOCOL: 3,
    ALGS,
    encodeName,
    nameLabelCount,
    canonicalRdata,
    canonicalRR,
    compareCanonicalRdata,
    encodeCharacterStrings,
    encodeTLSARdata,
    encodeDNSKEYRdata,
    dnskeyKeyTag,
    dsDigest,
    nsecTypeBitmap,
    encodeNSECRdata,
    encodeRRSIGSigningPreimage,
    encodeRRSIGRdata
};
