'use strict';

const config = require('wild-config');
const dns2 = require('dns2');
const punycode = require('punycode/');
const { zoneStore, tlsaFromValue } = require('./zone-store');
const cachedResolver = require('./cached-resolver');
const ipaddr = require('ipaddr.js');
const logger = require('./logger').child({ component: 'dns-handler' });
const { normalizeDomain } = require('./tools');
const { randomUUID } = require('crypto');
const wire = require('./dnssec-wire');
const dnssec = require('./dnssec');

// Split a TXT value into DNS character-strings (max 255 bytes each).
// Always returns an array, which is what the dns2 packet builder expects.
const formatTXTData = data => {
    data = (data || '').toString();
    if (!data.length) {
        return [''];
    }
    return Array.from(data.match(/.{1,255}/g));
};

// dns2's Packet.TYPE is missing several DNSSEC/DANE types (TLSA, RRSIG, NSEC,
// DS, ...). Merge those in so we can recognize such queries and serialize the
// answers via dns2's raw-RDATA fallback.
const typeToNumber = Object.assign({}, wire.EXTRA_TYPES, dns2.Packet.TYPE);

// Helps to convert DNS type integer into a string (0x01 -> 'A')
const reversedTypes = new Map(Object.keys(typeToNumber).map(key => [typeToNumber[key], key]));

const shuffle = array => {
    let currentIndex = array.length,
        temporaryValue,
        randomIndex;

    // While there remain elements to shuffle...
    while (currentIndex !== 0) {
        // Pick a remaining element...
        randomIndex = Math.floor(Math.random() * currentIndex);
        currentIndex -= 1;

        // And swap it with the current element.
        temporaryValue = array[currentIndex];
        array[currentIndex] = array[randomIndex];
        array[randomIndex] = temporaryValue;
    }

    return array;
};

const filterUnhealthy = list => {
    if (!list || !list.length) {
        return list;
    }

    let hasHealthyEntries = list.some(entry => !entry.health || entry.health.status === true);
    if (!hasHealthyEntries) {
        // has no healthy entries available, return all
        return list;
    }

    // filter unhealthy entries
    return list.filter(entry => !entry.health || entry.health.status === true);
};

// SOA MNAME (primary) - first configured nameserver, with safe fallbacks so an
// empty [[ns]] config cannot throw on the synthesis / signing paths.
const soaPrimary = () => (config.ns && config.ns.length && config.ns[0].domain) || config.soa.admin || 'localhost';

// Single SOA record builder shared by the processQuestion synthesis and the
// DNSSEC authority-section record, so the two cannot drift apart. `extra` lets
// the authority variant set a numeric type/class/ttl; the synthesized answer
// keeps the string type and is normalized later.
const buildSoaRecord = (name, extra) =>
    Object.assign(
        {
            name,
            type: 'SOA',
            primary: soaPrimary(),
            admin: config.soa.admin,
            serial: config.soa.serial,
            refresh: config.soa.refresh,
            retry: config.soa.retry,
            expiration: config.soa.expiration,
            minimum: config.soa.minimum
        },
        extra || {}
    );

const processQuestion = async (response, question, domain, depth) => {
    depth = depth || 0;
    domain = normalizeDomain(domain || question.name);

    let questionTypeStr = reversedTypes.has(question.type) ? reversedTypes.get(question.type) : false;

    if (!questionTypeStr) {
        // nothing to do here
        return;
    }

    let types = new Set([questionTypeStr]);

    if (questionTypeStr === 'ANY') {
        types.add('A');
        types.add('AAAA');
    }

    if (['A', 'ANY', 'AAAA', 'TXT'].includes(questionTypeStr)) {
        types.add('CNAME');
    }

    if (['A', 'AAAA'].includes(questionTypeStr)) {
        types.add('ANAME');
        types.add('URL');
    }

    let dnsEntries = (
        await Promise.all(
            Array.from(types).map(async type => {
                let records = await zoneStore.resolve(domain, type, false);
                if (records && records.length > 1) {
                    switch (type) {
                        case 'A':
                        case 'AAAA':
                            // randomize A/AAAA records
                            records = shuffle(filterUnhealthy(records));
                            break;
                        case 'MX':
                            // order MX records by priority
                            records = records.sort((a, b) => a.value[1] - b.value[1]);
                            break;
                    }
                }
                return records;
            })
        )
    )
        .flatMap(entry => entry)
        .filter(entry => entry);

    if (!dnsEntries || !dnsEntries.length) {
        if (questionTypeStr === 'NS') {
            // Only synthesize fallback NS at the zone apex (or for names outside any
            // served zone, preserving the legacy answer-for-anything behavior). A
            // below-apex NS-without-SOA is the RFC 4034 4.1.3 insecure-delegation
            // signal; served unsigned it makes a DO query bogus, so leave it empty
            // there and let signResponse turn it into a signed NODATA (SOA+NSEC).
            // This intentionally changes the old answer-for-anything behavior for
            // ALL clients (not just DO ones): a record-less below-apex NS query now
            // returns empty NOERROR rather than the configured nameservers. That is
            // the DNSSEC-correct choice and is kept uniform to avoid DO/non-DO skew.
            // resolveDomainZone returns the Unicode form, directly comparable to the
            // already-normalized `domain`. The lookup is only reached on a
            // record-less NS query, so the extra Redis walk is rare.
            let zone = await zoneStore.resolveDomainZone(domain);
            if (!zone || zone === domain) {
                for (let ns of config.ns || []) {
                    let entry = {
                        name: domain,
                        type: 'NS',
                        ns: ns.domain
                    };
                    response.answers.push(entry);
                }
            }
        }

        for (let ns of config.ns || []) {
            if (questionTypeStr === 'A' && domain === ns.domain) {
                let entry = {
                    name: domain,
                    type: 'A',
                    address: ns.ip
                };
                response.answers.push(entry);
            }
        }

        if (questionTypeStr === 'CAA') {
            // If CAA records are not set, use LE
            response.answers.push({
                name: domain,
                type: 'CAA',
                value: 'letsencrypt.org',
                tag: 'issue',
                flags: 0
            });
            response.answers.push({
                name: domain,
                type: 'CAA',
                value: 'letsencrypt.org',
                tag: 'issuewild',
                flags: 0
            });
        }

        if (questionTypeStr === 'SOA') {
            response.answers.push(buildSoaRecord(domain));
        }

        // Chaos responses
        if (
            question.class === dns2.Packet.CLASS.CH &&
            questionTypeStr === 'TXT' &&
            question.class === dns2.Packet.CLASS.CH &&
            config.chaos &&
            domain in config.chaos
        ) {
            for (let entry of [].concat(config.chaos[domain] || [])) {
                response.answers.push({
                    name: domain,
                    type: 'TXT',
                    data: formatTXTData(entry),
                    ttl: 0,
                    class: dns2.Packet.CLASS.CH
                });
            }
            response.authorities.push({
                name: domain,
                type: 'NS',
                ns: domain,
                ttl: 0,
                class: dns2.Packet.CLASS.CH
            });
        }
        return;
    }

    for (let dnsEntry of dnsEntries) {
        if (dnsEntry.type === 'ANAME') {
            let value;
            if (!dnsEntry.value || !dnsEntry.value.length) {
                continue;
            }

            try {
                switch (questionTypeStr) {
                    case 'A':
                    case 'AAAA':
                        value = await cachedResolver(dnsEntry.value[0], questionTypeStr);
                        if (value && value.length > 1) {
                            value = shuffle(value);
                        }
                        break;
                }
            } catch (err) {
                logger.error({
                    msg: 'Failed resolving ANAME',
                    id: response._id,
                    domain: dnsEntry.domain,
                    type: questionTypeStr,
                    err
                });
            }

            [].concat(value || []).forEach(value => {
                dnsEntries.push({
                    type: questionTypeStr,
                    domain: dnsEntry.domain,
                    value: [value]
                });
            });
        }

        if (dnsEntry.type === 'URL') {
            let value;
            if (!dnsEntry.value || !dnsEntry.value.length) {
                continue;
            }

            switch (questionTypeStr) {
                case 'A':
                case 'AAAA':
                    // return fixed list, actual URL record is needed on redirect time
                    value = [].concat(config.public.hosts[questionTypeStr] || []);
                    if (value && value.length > 1) {
                        value = shuffle(value);
                    }
                    break;
            }

            [].concat(value || []).forEach(value => {
                dnsEntries.push({
                    type: questionTypeStr,
                    domain: dnsEntry.domain,
                    value: [value]
                });
            });
        }
    }

    for (let dnsEntry of dnsEntries) {
        let value = dnsEntry.value;
        if (!value || !value.length) {
            continue;
        }

        let entry = {
            name: dnsEntry.domain,
            type: dnsEntry.type
        };

        switch (dnsEntry.type) {
            case 'A':
                entry.address = value[0];
                break;

            case 'AAAA':
                try {
                    entry.address = ipaddr.parse(value[0]).toNormalizedString();
                } catch (err) {
                    // skip just this malformed record, keep processing the rest
                    continue;
                }
                break;

            case 'CNAME':
                entry.domain = value[0];
                if (entry.domain === '@') {
                    entry.domain = dnsEntry.zone;
                }
                try {
                    entry.domain = punycode.toASCII(entry.domain);
                } catch (err) {
                    logger.error({
                        msg: 'Failed to punycode',
                        id: response._id,
                        domain: entry.domain,
                        err
                    });
                }
                break;

            case 'NS':
                entry.ns = value[0];
                try {
                    entry.ns = punycode.toASCII(entry.ns);
                } catch (err) {
                    logger.error({
                        msg: 'Failed to punycode',
                        id: response._id,
                        domain: entry.ns,
                        err
                    });
                }
                break;

            case 'TXT':
                entry.data = formatTXTData(value[0]);
                break;

            case 'MX':
                entry.exchange = value[0];
                entry.priority = value[1];
                if (entry.exchange === '@') {
                    entry.exchange = dnsEntry.zone;
                }
                try {
                    entry.exchange = punycode.toASCII(entry.exchange);
                } catch (err) {
                    logger.error({
                        msg: 'Failed to punycode',
                        id: response._id,
                        domain: entry.exchange,
                        err
                    });
                }
                break;

            case 'CAA':
                entry.value = value[0];
                entry.tag = value[1];
                entry.flags = (value[2] && Number(value[2])) || 0;
                break;

            case 'TLSA':
                // dns2 has no TLSA encoder; emit pre-built raw RDATA (RFC 6698).
                try {
                    entry.data = wire.encodeTLSARdata(tlsaFromValue(value));
                } catch (err) {
                    // skip a malformed stored TLSA record, keep processing the rest
                    logger.error({ msg: 'Skipping malformed TLSA record', id: response._id, domain: dnsEntry.domain, err });
                    continue;
                }
                break;

            default:
                // skip unknown types
                entry = false;
                break;
        }

        if (!entry) {
            continue;
        }

        if (dnsEntry.wildcard) {
            // carried for DNSSEC signing (RRSIG labels); ignored by the dns2 encoder
            entry.wildcard = dnsEntry.wildcard;
        }

        response.answers.push(entry);

        if (depth < 10 && dnsEntry.type === 'CNAME' && questionTypeStr !== 'CNAME') {
            // should try to resolve deeper
            await processQuestion(response, question, value[0], depth + 1);
        }
    }
};

// --- DNSSEC online signing -------------------------------------------------

const numericType = t => (typeof t === 'number' ? t : typeToNumber[t]);

// NSEC type bitmap (numeric types) for a name. `excludeTypeNum` (optional) is the
// numeric type this proof denies and must never be listed (see the final filter).
// The apex additionally serves NS/SOA/DNSKEY; RRSIG+NSEC always cover a signed name.
const bitmapTypeNums = (existing, isApex, excludeTypeNum) => {
    const hosts = (config.public && config.public.hosts) || {};
    const names = new Set();
    for (const type of existing) {
        if (type === 'URL') {
            // A URL record answers A/AAAA only from config.public.hosts. List a
            // family only when it is actually configured (hence answerable):
            // advertising AAAA while public.hosts.AAAA is empty would contradict
            // the NODATA the server returns for AAAA at a URL name and make a
            // validating resolver treat the answer as bogus (SERVFAIL).
            if (hosts.A && hosts.A.length) {
                names.add('A');
            }
            if (hosts.AAAA && hosts.AAAA.length) {
                names.add('AAAA');
            }
        } else if (type === 'ANAME') {
            // ANAME answerable families are dynamic (live resolution of the target),
            // so list both; excludeTypeNum drops whichever one this query proved
            // absent so the proof can never contradict the answer.
            names.add('A');
            names.add('AAAA');
        } else {
            // Stored types pass through, including a real below-apex NS: that is a
            // genuine delegation and is correctly listed. Only the *synthesized*
            // apex NS is added in the isApex block below.
            names.add(type);
        }
    }
    // The server synthesizes CAA and SOA for ANY name, so every signed name
    // effectively has them; list them so aggressive NSEC (RFC 8198) does not
    // synthesize a NODATA that suppresses those answers. SOA alone (without NS)
    // does not imply a zone cut, so it is safe at non-apex names. Synthesized NS is
    // withheld below the apex on purpose: an NS-without-SOA is the RFC 4034 4.1.3
    // insecure-delegation signal and would mislead a validator into treating the
    // name as a delegation point.
    names.add('SOA');
    names.add('CAA');
    names.add('RRSIG');
    names.add('NSEC');
    if (isApex) {
        names.add('NS');
        names.add('DNSKEY');
    }
    // Never list the type this proof denies. In the NODATA branch the queried type
    // produced no answer; in the wildcard branch the answer came from the wildcard
    // owner (the RRSIG Labels field signals the expansion). Listing it at the exact
    // name would make the proof self-contradictory and validators would reject it.
    return [...names].map(numericType).filter(n => typeof n === 'number' && n !== excludeTypeNum);
};

const soaAuthorityRecord = zone => buildSoaRecord(zone, { type: dns2.Packet.TYPE.SOA, class: dns2.Packet.CLASS.IN, ttl: config.soa.minimum });

// Compact "black lie" NSEC: owner = the queried name, next name sorts directly
// after it (\000.<name>) so the record covers only this name and cannot be used
// to deny any other (safe for aggressive NSEC caching).
const nsecRecord = (owner, typeNums, ttl) => ({
    name: owner,
    type: wire.TYPE.NSEC,
    class: dns2.Packet.CLASS.IN,
    ttl,
    data: wire.encodeNSECRdata(`\x00.${owner}`, typeNums)
});

// A question is positively answered when the answer section holds a record of
// the queried type (or a CNAME) AT THE QUERIED NAME. Scoping to `qname` keeps a
// multi-question packet from letting one question's answer mask another's
// missing answer (which would suppress the latter's denial proof).
const hasPositiveAnswer = (response, question, qname) =>
    // For ANY, "positive" means any (non-RRSIG) record exists at the name - there is
    // no record whose type literally equals ANY. With no record present the query is
    // a true NODATA and must still get a signed denial, so do not short-circuit.
    question.type === dns2.Packet.TYPE.ANY
        ? response.answers.some(rr => rr.name === qname && rr.type !== wire.TYPE.RRSIG)
        : response.answers.some(rr => rr.name === qname && (rr.type === question.type || rr.type === dns2.Packet.TYPE.CNAME));

// Sign every in-zone RRset in a section, appending the RRSIG records. Returns
// true if anything was signed.
const signSection = async (section, zoneFor, signerFor) => {
    const groups = new Map();
    for (let rr of section) {
        if (rr.type === wire.TYPE.RRSIG) {
            continue; // never sign RRSIGs
        }
        let key = `${rr.name}\x00${rr.type}`;
        if (!groups.has(key)) {
            groups.set(key, []);
        }
        groups.get(key).push(rr);
    }

    let rrsigs = [];
    for (let rrs of groups.values()) {
        let owner = rrs[0].name;
        let zone = await zoneFor(owner); // A-label form (canonicalized in zoneFor)
        if (!zone) {
            continue;
        }
        // Never sign a delegation NS RRset: an NS below the apex marks a zone cut
        // and is non-authoritative referral data the parent must not sign
        // (RFC 4035 2.2). Apex NS (owner === zone) is authoritative and is signed.
        if (rrs[0].type === wire.TYPE.NS && owner !== zone) {
            continue;
        }
        let signer = await signerFor(zone);
        if (!signer) {
            continue;
        }
        // For a wildcard expansion the signature is computed over the wildcard
        // owner (`*.zone`, canonical A-label form), not the expanded wire name, so
        // a validator can reconstruct it (RFC 4035 5.3.2). signRRset returns one
        // RRSIG per signing key (one per algorithm in the zone).
        let wildcard = rrs.find(rr => rr.wildcard);
        let signingOwner = wildcard ? punycode.toASCII(wildcard.wildcard) : owner;
        rrsigs.push(...dnssec.signRRset(signer, owner, signingOwner, rrs[0].type, rrs[0].ttl, rrs));
    }

    for (let sig of rrsigs) {
        section.push(sig);
    }
    return rrsigs.length > 0;
};

// Add DNSKEY answers, denial-of-existence proofs, and RRSIGs to a response that
// is already normalized. Only invoked when the client set the DO bit.
const signResponse = async (request, response) => {
    // NSEC / negative-cache TTL tracks the SOA MINIMUM so the denial proof and
    // the negative answer expire together in caches (RFC 2308). typeof guard so a
    // configured SOA minimum of 0 is honored rather than falling back to 300.
    const soaMinimum = config.soa && config.soa.minimum;
    const nsecTtl = typeof soaMinimum === 'number' ? soaMinimum : 300;

    // Emit at most one SOA per zone and one NSEC per owner across all questions: a
    // multi-question packet must not produce duplicate - or, in the wildcard case,
    // contradictory - denial records that signSection would then group and sign as
    // one inconsistent RRset. First-wins is correct: an owner has exactly one NSEC
    // RRset, and either question's bitmap is a valid black-lie for that owner (do
    // not merge bitmaps - folding a wildcard-answered type back in would make the
    // wildcard proof bogus).
    //
    // Residual (intentional, do not "fix"): with QDCOUNT >= 2 for the same owner,
    // only the first question's denied type is excluded from the shared NSEC, so a
    // second same-owner NODATA of a different type could leave that type listed.
    // Multi-question packets are effectively never sent in practice, and the
    // single-question path (the norm) is fully covered by the excludeTypeNum below.
    const soaDone = new Set();
    const nsecDone = new Set();
    const addSoaOnce = zone => {
        if (!soaDone.has(zone)) {
            soaDone.add(zone);
            response.authorities.push(soaAuthorityRecord(zone));
        }
    };
    const pushNsec = (owner, types, isApex, excludeTypeNum) => {
        if (nsecDone.has(owner)) {
            return;
        }
        nsecDone.add(owner);
        response.authorities.push(nsecRecord(owner, bitmapTypeNums(types, isApex, excludeTypeNum), nsecTtl));
    };

    // Memoize the two per-zone lookups across the question loop and both
    // signing passes: resolveDomainZone walks the label hierarchy (several
    // Redis round-trips) and getSigner reads + parses the zone keys.
    const zoneCache = new Map();
    const zoneFor = async name => {
        if (!zoneCache.has(name)) {
            let zone = await zoneStore.resolveDomainZone(name);
            // Canonicalize to the A-label form once here. resolveDomainZone returns
            // the Unicode form (lib/certs.js relies on that), but every DNSSEC
            // consumer - the apex test, the SOA/signer name, the signerFor cache
            // key - needs punycode, so normalize at the cache boundary.
            zoneCache.set(name, zone ? punycode.toASCII(zone) : zone);
        }
        return zoneCache.get(name);
    };

    const signerCache = new Map();
    const signerFor = async zone => {
        if (!signerCache.has(zone)) {
            signerCache.set(zone, await dnssec.getSigner(zone));
        }
        return signerCache.get(zone);
    };

    for (let question of request.questions) {
        let qname = punycode.toASCII(normalizeDomain(question.name));
        let zone = await zoneFor(qname); // A-label form (canonicalized in zoneFor)
        if (!zone) {
            continue;
        }
        let signer = await signerFor(zone);
        if (!signer) {
            continue;
        }

        // DNSKEY at the apex: serve and self-sign the key set. Records arrive
        // ready to sign; only the post-normalization fields need finishing.
        // By design DNSKEY answers are produced only here, on the DO path: this is
        // an online signer, so a non-DO client gets the same empty NOERROR it would
        // for any signing-only type (a validator always sets DO before asking).
        if (question.type === wire.TYPE.DNSKEY && qname === zone) {
            for (let rr of dnssec.buildDnskeyRecords(signer)) {
                rr.type = wire.TYPE.DNSKEY;
                rr.name = punycode.toASCII(rr.name);
                response.answers.push(rr);
            }
        }

        let wildcardAnswer = response.answers.find(rr => rr.wildcard && rr.name === qname);

        if (!hasPositiveAnswer(response, question, qname)) {
            // NODATA, always NOERROR ("black lies"). Because the server
            // synthesizes CAA/NS/SOA for every name, no name is truly nonexistent,
            // so NXDOMAIN would be incorrect; prove the absence of the queried
            // type with SOA + a compact NSEC at the queried name. Below the apex,
            // fold in the types a single-level wildcard could answer so an RFC 8198
            // aggressive-NSEC resolver cannot cache this NSEC and synthesize a
            // NODATA that suppresses the wildcard.
            addSoaOnce(zone);
            pushNsec(qname, await zoneStore.existingTypes(qname, qname !== zone), qname === zone, question.type);
        } else if (wildcardAnswer) {
            // Wildcard expansion: prove the exact name had no direct match. This
            // NSEC MUST list only the exact-name types, never the wildcard-supplied
            // type - the RRSIG Labels field signals the expansion, and listing the
            // answered type here would make the wildcard proof bogus. Residual
            // (inherent to compact black-lies online signing): an aggressive-NSEC
            // resolver caching this NSEC may suppress a later same-name/same-type
            // query; the minimally-covering next-name (\x00.<owner>) bounds it to
            // this exact name. Matches Cloudflare/Knot/PowerDNS online signers.
            pushNsec(qname, await zoneStore.existingTypes(qname), false, question.type);
        }
    }

    await signSection(response.answers, zoneFor, signerFor);
    await signSection(response.authorities, zoneFor, signerFor);

    // The AD bit is intentionally not set: it is a validating-resolver signal
    // (RFC 6840 5.7), not something an authoritative server asserts.
};

const dnsHandler = async (request, edns) => {
    edns = edns || { hasOpt: false, doFlag: false };
    let startTime = Date.now();
    const response = new dns2.Packet(request);
    request._id = response._id = randomUUID();

    response.header.qr = 1;
    response.header.aa = 1;

    await Promise.all(
        request.questions.map(question => {
            logger.debug({
                id: request._id,
                msg: 'DNS query',
                action: 'dns_query',
                proto: request.source.type,
                port: request.source.port,
                address: request.source.address,
                question: question.name,
                rr: reversedTypes.get(question.type) || question.type
            });
            return processQuestion(response, question);
        })
    );

    logger.debug({
        id: request._id,
        msg: 'DNS response',
        action: 'dns_response',
        dnsTime: Date.now() - startTime,
        questions: request.questions,
        answers: response.answers
    });

    // normalize answers for the DNS library
    for (let responseType of [response.answers, response.authorities]) {
        responseType.forEach(answer => {
            // numericType (via typeToNumber) also covers TLSA/RRSIG/NSEC/DS, which
            // dns2.Packet.TYPE does not know about and would normalize to undefined.
            answer.type = numericType(answer.type);
            answer.class = typeof answer.class === 'number' ? answer.class : dns2.Packet.CLASS.IN;
            answer.name = punycode.toASCII(answer.name);
            answer.ttl = typeof answer.ttl === 'number' && answer.ttl >= 0 ? answer.ttl : config.dns.ttl;
        });
    }

    // DNSSEC: only when signing is globally enabled, the client signalled
    // support (DO bit), and the zone is signed (the per-zone gate is in
    // getSigner). Clients that do not set DO get unsigned answers. (Non-EDNS UDP
    // responses over 512 bytes are truncated with TC=1 per RFC 1035 - see
    // finalizeResponse in dns-server.js - so they are not byte-identical to the
    // pre-DNSSEC server for large answers.)
    if (edns.doFlag && config.dnssec && config.dnssec.enabled) {
        // Never let a signing failure drop the whole response: dns-server's send
        // error path returns nothing, so an uncaught throw here would time the
        // client out. On error, restore the pre-signing (unsigned but consistent)
        // sections and return them - a validator treats the unsigned reply as
        // bogus/insecure, which is strictly better than no answer at all.
        const savedAnswers = response.answers.slice();
        const savedAuthorities = response.authorities.slice();
        try {
            await signResponse(request, response);
        } catch (err) {
            logger.error({ msg: 'Failed to sign DNS response', id: request._id, err });
            response.answers = savedAnswers;
            response.authorities = savedAuthorities;
        }
    }

    return response;
};

module.exports = dnsHandler;

// Exposed for unit testing
module.exports.testables = { formatTXTData, shuffle, filterUnhealthy, reversedTypes, processQuestion, signResponse, bitmapTypeNums };
