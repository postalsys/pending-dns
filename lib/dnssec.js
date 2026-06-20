'use strict';

// Online (live) DNSSEC signing. Per-zone keys live in Redis; RRsets are signed
// at query time and denial-of-existence is synthesized with compact NSEC
// "black lies" - no pre-signed zone, no stored RRSIG/NSEC chains.
//
// Signatures are always computed over the canonical wire form from
// dnssec-wire.js (uncompressed, lowercased), never over dns2's serialization.

const config = require('wild-config');
const crypto = require('crypto');
const util = require('util');
const punycode = require('punycode/');
const db = require('./db');
const { waitAcquireLock, releaseLock } = require('./lock');
const { zoneStore } = require('./zone-store');
const logger = require('./logger').child({ component: 'dnssec' });
const wire = require('./dnssec-wire');

const generateKeyPairAsync = util.promisify(crypto.generateKeyPair);

// Parsing a PEM into a KeyObject is relatively expensive; cache by PEM string
// (a PEM uniquely identifies its key, so this is always safe and never stale).
// Bounded LRU so the cache cannot grow without limit as keys roll over: on a
// hit we refresh recency, and once over the cap we drop the oldest entry.
// Bounded-LRU insert: (re)insert the key as most-recent and evict the oldest
// entry once over the cap. Re-inserting an existing key refreshes its recency.
const lruSet = (map, key, value, max) => {
    map.delete(key);
    map.set(key, value);
    if (map.size > max) {
        map.delete(map.keys().next().value);
    }
};

const PRIVATE_KEY_CACHE_MAX = 1000;
const privateKeyCache = new Map();
const cachedPrivateKey = pem => {
    let key = privateKeyCache.get(pem) || crypto.createPrivateKey(pem);
    lruSet(privateKeyCache, pem, key, PRIVATE_KEY_CACHE_MAX);
    return key;
};

// `<name>` is the label-reversed zone name, matching the d:<name>:z keyspace.
const zoneName = zone => zoneStore.domainToName(zone);
const stateKey = name => `d:dnssec:${name}`;
const keysKey = name => `d:dnssec:${name}:keys`;

const dnssecConfig = () => config.dnssec || {};

// keyTag is a number when freshly generated but a string after a JSON/Redis round
// trip or as a route param, so compare key tags through one string coercion.
const sameTag = (a, b) => String(a) === String(b);

// A key is "preferred" within its algorithm when it is the recorded active key
// (by tag) or, lacking that, one explicitly marked active. Shared by getSigner
// so the per-algorithm selection rule lives in one place.
const isPreferredKey = (key, activeKeyTag) => sameTag(key.keyTag, activeKeyTag) || key.status === 'active';

// Assembled-signer cache (zone reversed-name -> { signer, expires }). getSigner
// is on the DNS hot path and otherwise re-reads + re-parses the zone keys on
// every DO query (including null for unsigned zones). The API and DNS subsystems
// run as separate workers, so a mutation in the API worker cannot invalidate
// this cache directly - a short TTL ([dnssec] signerCacheTtl) bounds staleness
// and DNSSEC key changes are rare. Within one process the mutating calls below
// invalidate the entry explicitly.
const SIGNER_CACHE_MAX = 1000;
const signerCache = new Map();
const invalidateSigner = name => signerCache.delete(name);

const getKeysRaw = async (name, client) => {
    const stored = await (client || db.redisRead).hgetall(keysKey(name));
    const keys = [];
    for (const hid of Object.keys(stored || {})) {
        try {
            keys.push(Object.assign({ hid }, JSON.parse(stored[hid])));
        } catch (err) {
            logger.error({ msg: 'Failed to parse DNSSEC key', name, hid, err });
        }
    }
    return keys;
};

// Generate a single Combined Signing Key (KSK+ZSK in one) for a zone.
const generateCsk = async (zone, algorithm) => {
    const alg = wire.ALGS[algorithm];
    if (!alg) {
        throw new Error(`Unsupported DNSSEC algorithm ${algorithm}`);
    }

    const { publicKey, privateKey } = await generateKeyPairAsync(
        alg.generate.type,
        Object.assign({}, alg.generate.options, {
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        })
    );

    const jwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
    const pubkey = alg.pubkeyFromJwk(jwk);

    const flags = wire.DNSKEY_FLAGS_CSK;
    const protocol = wire.DNSKEY_PROTOCOL;
    const dnskeyRdata = wire.encodeDNSKEYRdata({ flags, protocol, algorithm, pubkey });

    return {
        hid: crypto.randomUUID(),
        keyTag: wire.dnskeyKeyTag(dnskeyRdata),
        algorithm,
        flags,
        protocol,
        privateKey,
        publicKeyDnssec: pubkey.toString('base64'),
        status: 'active',
        created: new Date().toISOString()
    };
};

// DNSKEY RDATA Buffer for a stored key.
const keyDnskeyRdata = key =>
    wire.encodeDNSKEYRdata({
        flags: key.flags,
        protocol: key.protocol,
        algorithm: key.algorithm,
        pubkey: Buffer.from(key.publicKeyDnssec, 'base64')
    });

// Presentation + component form of a key's DS record (digest computed by us;
// the operator pastes this at the registrar).
const keyDsRecord = (zone, key) => {
    const digestType = wire.ALGS[key.algorithm].dsDigestType;
    // The DS digest covers the canonical (punycode A-label) DNSKEY owner name,
    // regardless of whether the operator passed an IDN zone in Unicode form.
    const digest = wire.dsDigest(punycode.toASCII(zone), keyDnskeyRdata(key), digestType).toString('hex');
    return {
        keyTag: key.keyTag,
        algorithm: key.algorithm,
        digestType,
        digest,
        presentation: `${key.keyTag} ${key.algorithm} ${digestType} ${digest}`
    };
};

// DNSKEY presentation form of a key.
const keyDnskeyRecord = key => ({
    flags: key.flags,
    protocol: key.protocol,
    algorithm: key.algorithm,
    publicKey: key.publicKeyDnssec,
    keyTag: key.keyTag,
    presentation: `${key.flags} ${key.protocol} ${key.algorithm} ${key.publicKeyDnssec}`
});

// Pick the active key for a zone from its stored key set + state hash.
const activeKey = (state, keys) => {
    const activeKeyTag = state && state.activeKeyTag;
    return keys.find(key => sameTag(key.keyTag, activeKeyTag)) || keys.find(key => key.status === 'active') || keys[0] || null;
};

const summarize = (zone, state, keys) => {
    const active = activeKey(state, keys);
    return {
        zone,
        enabled: !!(state && state.enabled === '1'),
        // Report the active key's algorithm/keyTag (during an algorithm rollover
        // several keys of different algorithms coexist); ds/dnskey list them all.
        algorithm: active ? active.algorithm : Number((state && state.algorithm) || dnssecConfig().algorithm || 13),
        keyTag: active ? active.keyTag : null,
        ds: keys.map(key => keyDsRecord(zone, key)),
        dnskey: keys.map(keyDnskeyRecord)
    };
};

// Enable DNSSEC for a zone, generating a CSK on first call. Idempotent for the
// same algorithm. Requesting a different algorithm performs an algorithm
// rollover: a new CSK is generated and made active while the old key is kept, so
// the zone keeps being signed with every algorithm in the DNSKEY RRset
// (RFC 6840 5.11) until the operator removes the old key (removeKey) after
// updating the parent DS.
const enableZone = async (zone, opts = {}) => {
    // The query-time signing path is additionally gated on config.dnssec.enabled
    // (see dns-handler.js). Refuse here when the global switch is off so the API
    // never hands back a DS the server will not honour - publishing that DS would
    // SERVFAIL the whole zone.
    if (!dnssecConfig().enabled) {
        throw Object.assign(new Error('DNSSEC is disabled globally; set [dnssec] enabled = true to enable signing'), {
            statusCode: 400,
            code: 'DnssecGloballyDisabled'
        });
    }

    const name = zoneName(zone);
    const requestedAlgorithm = opts.algorithm || dnssecConfig().algorithm || 13;

    const lock = await waitAcquireLock(`dnssec:${name}`, 60 * 1000, 60 * 1000);
    if (!lock || !lock.success) {
        throw new Error('Failed to acquire DNSSEC lock');
    }
    try {
        // Read from the write client: this is a mutating, lock-held section and
        // must not act on a possibly-stale replica view.
        let keys = await getKeysRaw(name, db.redisWrite);
        // state is only needed to preserve the active key when no algorithm is
        // requested; skip the read on the explicit-algorithm (rollover) path.
        const state = opts.algorithm ? null : await db.redisWrite.hgetall(stateKey(name));

        const haveRequestedAlg = keys.some(key => Number(key.algorithm) === Number(requestedAlgorithm));
        // Generate a key when none exist, or when the caller explicitly asked for
        // an algorithm we do not yet have (rollover - keep the existing keys).
        if (!keys.length || (opts.algorithm && !haveRequestedAlg)) {
            const key = await generateCsk(zone, requestedAlgorithm);
            await db.redisWrite.hset(keysKey(name), key.hid, JSON.stringify(key));
            keys.push(key);
            logger.info({ msg: 'Generated DNSSEC key', zone, algorithm: requestedAlgorithm, keyTag: key.keyTag, rollover: keys.length > 1 });
        }

        // When an algorithm was explicitly requested, that key becomes active (the
        // freshly generated one on a rollover). With no algorithm in the request,
        // preserve the current active key rather than reverting to the config
        // default - re-enabling a zone mid-rollover must not flip the active key
        // away from the one the operator rolled to.
        const active = opts.algorithm ? keys.find(key => Number(key.algorithm) === Number(requestedAlgorithm)) || keys[0] : activeKey(state, keys);
        await db.redisWrite.hmset(stateKey(name), {
            enabled: '1',
            algorithm: String(active.algorithm),
            activeKeyTag: String(active.keyTag),
            created: new Date().toISOString()
        });
        invalidateSigner(name);

        return summarize(zone, { enabled: '1', activeKeyTag: String(active.keyTag) }, keys);
    } finally {
        await releaseLock(lock);
    }
};

// Remove a (non-active) signing key from a zone, e.g. to finish an algorithm
// rollover once the new DS is published at the parent. Refuses to remove the
// active key or the last remaining key so a signed zone never loses its signer.
const removeKey = async (zone, keyTag) => {
    const name = zoneName(zone);

    const lock = await waitAcquireLock(`dnssec:${name}`, 60 * 1000, 60 * 1000);
    if (!lock || !lock.success) {
        throw new Error('Failed to acquire DNSSEC lock');
    }
    try {
        // Read from the write client inside the lock: the active-key guard below
        // must not be decided on a stale replica view, or it could permit
        // removing the key that is actually active.
        const keys = await getKeysRaw(name, db.redisWrite);
        const target = keys.find(key => sameTag(key.keyTag, keyTag));
        if (!target) {
            return false;
        }
        if (keys.length <= 1) {
            throw Object.assign(new Error('Cannot remove the last remaining key; disable the zone instead'), {
                statusCode: 400,
                code: 'CannotRemoveLastKey'
            });
        }
        const state = await db.redisWrite.hgetall(stateKey(name));
        if (state && sameTag(state.activeKeyTag, keyTag)) {
            throw Object.assign(new Error('Cannot remove the active key; roll to a new key first'), {
                statusCode: 400,
                code: 'CannotRemoveActiveKey'
            });
        }
        await db.redisWrite.hdel(keysKey(name), target.hid);
        invalidateSigner(name);
        logger.info({ msg: 'Removed DNSSEC key', zone, keyTag });
        return true;
    } finally {
        await releaseLock(lock);
    }
};

const disableZone = async zone => {
    const name = zoneName(zone);

    // Take the same per-zone lock enableZone/removeKey hold so a disable cannot race
    // a concurrent enable into a lost update - which could leave the zone unsigned
    // after the operator already published the DS returned by enable, SERVFAILing
    // the zone at validators.
    const lock = await waitAcquireLock(`dnssec:${name}`, 60 * 1000, 60 * 1000);
    if (!lock || !lock.success) {
        throw new Error('Failed to acquire DNSSEC lock');
    }
    try {
        await db.redisWrite.hset(stateKey(name), 'enabled', '0');
        invalidateSigner(name);
        return true;
    } finally {
        await releaseLock(lock);
    }
};

const getZoneStatus = async zone => {
    const name = zoneName(zone);
    // Read from the master, not a replica: a status check right after enable or a
    // rollover must not return a stale/empty DS due to replication lag, since the
    // operator copies this DS to the registrar.
    const state = await db.redisWrite.hgetall(stateKey(name));
    const keys = await getKeysRaw(name, db.redisWrite);
    return summarize(zone, state, keys);
};

const isZoneSigned = async zone => {
    const name = zoneName(zone);
    // Master read, consistent with getZoneStatus and the lock-held mutators.
    const enabled = await db.redisWrite.hget(stateKey(name), 'enabled');
    return enabled === '1';
};

// Resolve the signing context for a zone (or null when not signed). Returns one
// signing key per distinct algorithm present (the active key within each
// algorithm) so every RRset gets an RRSIG from every algorithm in the DNSKEY
// RRset (RFC 6840 5.11). `zone` is the punycode A-label form - it is the RRSIG
// signer name and the DNSKEY owner, so it must be canonical even for IDN zones.
const buildSigner = async (zone, name) => {
    // state and keys are independent reads; fetch them together to halve the
    // signer-cache-miss latency on the DO query hot path.
    const [state, keys] = await Promise.all([db.redisRead.hgetall(stateKey(name)), getKeysRaw(name)]);
    if (!state || state.enabled !== '1') {
        return null;
    }
    if (!keys.length) {
        return null;
    }

    // One key per algorithm; prefer the active key (by tag, then status) within
    // an algorithm so a same-algorithm key set still picks deterministically.
    const byAlgorithm = new Map();
    for (const key of keys) {
        const alg = Number(key.algorithm);
        const current = byAlgorithm.get(alg);
        if (!current || (isPreferredKey(key, state.activeKeyTag) && !isPreferredKey(current, state.activeKeyTag))) {
            byAlgorithm.set(alg, key);
        }
    }

    const signingKeys = [...byAlgorithm.values()].map(key => ({
        algorithm: Number(key.algorithm),
        keyTag: key.keyTag,
        flags: key.flags,
        protocol: key.protocol,
        publicKeyDnssec: key.publicKeyDnssec,
        privateKeyObj: cachedPrivateKey(key.privateKey)
    }));
    if (!signingKeys.length) {
        return null;
    }

    return {
        zone: punycode.toASCII(zone), // also the RRSIG signer name (canonical A-label form)
        activeKeyTag: state.activeKeyTag,
        keys: signingKeys
    };
};

const getSigner = async zone => {
    const name = zoneName(zone);

    const cached = signerCache.get(name);
    if (cached && cached.expires > Date.now()) {
        lruSet(signerCache, name, cached, SIGNER_CACHE_MAX); // refresh recency
        return cached.signer;
    }

    const signer = await buildSigner(zone, name);

    const ttlSeconds = dnssecConfig().signerCacheTtl;
    const ttl = (typeof ttlSeconds === 'number' ? ttlSeconds : 5) * 1000;
    if (ttl > 0) {
        lruSet(signerCache, name, { signer, expires: Date.now() + ttl }, SIGNER_CACHE_MAX);
    }
    return signer;
};

// Sign one RRset, returning one RRSIG resource (raw type 46) per signing key -
// i.e. one per algorithm in the zone (RFC 6840 5.11). `rrs` are normalized
// answer objects sharing the owner name + numeric type.
//
// `wireOwner` is the on-the-wire owner name the RRSIG is attached to (for a
// wildcard expansion this is the expanded query name). `signingOwner` is the
// name the signature is computed over: the wildcard owner (`*.zone`) for an
// expansion, otherwise the same as `wireOwner`. The RRSIG Labels field is the
// label count of `signingOwner`, so a validator can reconstruct the wildcard
// owner and verify the signature (RFC 4035 5.3.2).
const signRRset = (signer, wireOwner, signingOwner, typeNum, ttl, rrs) => {
    const now = Math.floor(Date.now() / 1000);
    const cfg = dnssecConfig();
    const labels = wire.nameLabelCount(signingOwner);
    // typeof guards so a configured 0 (e.g. no inception backdating) is honored
    // rather than silently reverting to the default. These do not vary per signing
    // key, so compute them once instead of inside the per-key loop below.
    const expiration = now + (typeof cfg.signatureValidity === 'number' ? cfg.signatureValidity : 604800);
    const inception = now - (typeof cfg.inceptionSkew === 'number' ? cfg.inceptionSkew : 3600);

    const sortedRdata = rrs.map(rr => wire.canonicalRdata(typeNum, rr)).sort(wire.compareCanonicalRdata);
    // Remove duplicate RRs from the RRset before signing (RFC 4034 6.3). A
    // validator de-duplicates before verifying, so signing over duplicates - e.g.
    // the same A value stored twice, or one SOA per question in a multi-question
    // NODATA packet - would produce an RRSIG that fails validation.
    const canonical = sortedRdata
        .filter((rdata, i) => i === 0 || !rdata.equals(sortedRdata[i - 1]))
        .map(rdata => wire.canonicalRR(signingOwner, typeNum, 1, ttl, rdata));
    // The canonical RRset bytes are identical for every signing key; concatenate
    // them once and only prepend the per-key RRSIG preimage inside the loop.
    const canonicalRRs = Buffer.concat(canonical);

    return signer.keys.map(key => {
        const fields = {
            typeCovered: typeNum,
            algorithm: key.algorithm,
            labels,
            originalTtl: ttl,
            expiration,
            inception,
            keyTag: key.keyTag,
            signerName: signer.zone
        };
        const signature = wire.ALGS[key.algorithm].sign(Buffer.concat([wire.encodeRRSIGSigningPreimage(fields), canonicalRRs]), key.privateKeyObj);
        return {
            name: wireOwner,
            type: wire.TYPE.RRSIG,
            class: 1,
            ttl,
            data: wire.encodeRRSIGRdata(fields, signature)
        };
    });
};

// DNSKEY RRset for the apex (structured for dns2's native encoder).
const buildDnskeyRecords = signer => {
    const dnskeyTtl = dnssecConfig().dnskeyTtl;
    const ttl = typeof dnskeyTtl === 'number' ? dnskeyTtl : 3600;
    return signer.keys.map(key => ({
        name: signer.zone,
        type: 'DNSKEY',
        class: 1,
        ttl,
        flags: key.flags,
        protocol: key.protocol,
        algorithm: key.algorithm,
        key: key.publicKeyDnssec
    }));
};

module.exports = {
    enableZone,
    disableZone,
    removeKey,
    getZoneStatus,
    isZoneSigned,
    getSigner,
    signRRset,
    buildDnskeyRecords,
    // testing seam
    testables: { zoneName }
};
