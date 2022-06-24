'use strict';

const config = require('wild-config');
const dns2 = require('dns2');
const punycode = require('punycode/');
const { zoneStore } = require('./zone-store');
const cachedResolver = require('./cached-resolver');
const ipaddr = require('ipaddr.js');
const logger = require('./logger').child({ component: 'dns-handler' });
const { normalizeDomain } = require('./tools');
const { v4: uuidv4 } = require('uuid');

// Split long string values into character chunks
const formatTXTData = data => {
    data = (data || '').toString();
    if (data.length < 128) {
        return data;
    }
    return Array.from(data.match(/.{1,84}/g));
};

// Helps to convert DNS type integer into a string (0x01 -> 'A')
const reversedTypes = new Map(Object.keys(dns2.Packet.TYPE).map(key => [dns2.Packet.TYPE[key], key]));

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
                        case 'AAAAA':
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
            for (let ns of config.ns) {
                let entry = {
                    name: domain,
                    type: 'NS',
                    ns: ns.domain
                };
                response.answers.push(entry);
            }
        }

        for (let ns of config.ns) {
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
            let entry = {
                name: domain,
                type: 'SOA',
                primary: config.ns[0].domain,
                admin: config.soa.admin,
                serial: config.soa.serial,
                refresh: config.soa.refresh,
                retry: config.soa.retry,
                expiration: config.soa.expiration,
                minimum: config.soa.minimum
            };
            response.answers.push(entry);
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
                    return;
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

            default:
                // skip unknown types
                entry = false;
                break;
        }

        if (!entry) {
            continue;
        }

        response.answers.push(entry);

        if (depth < 10 && dnsEntry.type === 'CNAME' && questionTypeStr !== 'CNAME') {
            // should try to resolve deeper
            await processQuestion(response, question, value[0], depth + 1);
        }
    }
};

const dnsHandler = async request => {
    let startTime = Date.now();
    const response = new dns2.Packet(request);
    request._id = response._id = uuidv4();

    response.header.qr = 1;
    response.header.aa = 1;

    await Promise.all(
        request.questions.map(question => {
            logger.info({
                id: request._id,
                msg: 'DNS query',
                type: request.source.type,
                port: request.source.port,
                address: request.source.address,
                question: question.name,
                rr: reversedTypes.get(question.type) || question.type
            });
            return processQuestion(response, question);
        })
    );

    logger.info({
        msg: 'DNS response',
        id: request._id,
        dnsTime: Date.now() - startTime,
        questions: request.questions,
        answers: response.answers
    });

    // normalize answers for the DNS library
    response.answers.forEach(answer => {
        answer.type = dns2.Packet.TYPE[answer.type];
        answer.class = dns2.Packet.CLASS.IN;
        answer.name = punycode.toASCII(answer.name);
        answer.ttl = config.dns.ttl;
    });

    return response;
};

module.exports = dnsHandler;
