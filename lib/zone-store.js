'use strict';

const punycode = require('punycode/');
const { nanoid } = require('nanoid');
const db = require('./db');
const logger = require('./logger').child({ component: 'zone-store' });
const { normalizeDomain } = require('./tools');

const orderList = ['A', 'AAAA', 'ANAME', 'CNAME', 'MX', 'TXT', 'CAA', 'TLSA', 'URL', 'NS'];
const allowedTypes = new Set(orderList);
const allowedTags = new Set(['issue', 'issuewild', 'iodef']);

// TLSA records are stored as a positional value array
// [usage, selector, matchingType, certificate]. These keep that ordering in one
// place so the API, the store, and the DNS handler cannot drift apart.
const tlsaToValue = data => [data.usage, data.selector, data.matchingType, data.certificate];
// TLSA certificate association data must be even-length hex. The API enforces
// this in Joi, but guard the store boundary too so a direct caller cannot store
// a value that Buffer.from(..,'hex') would silently truncate into a corrupt DANE
// association.
const isEvenHex = value => typeof value === 'string' && value.length > 0 && value.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(value);
const tlsaFromValue = value => ({
    usage: Number(value[0]) || 0,
    selector: Number(value[1]) || 0,
    matchingType: Number(value[2]) || 0,
    certificate: value[3]
});

// Single-label wildcard key for a label-reversed name: replace the most-specific
// (trailing) label with '*'. resolve() and existingTypes() both probe this key.
const toWildcardName = name => name.replace(/\.[^.]+$/, '.*');

class ZoneStore {
    constructor(db, options) {
        this.db = db;
        this.options = options;
    }

    getFullId(name, type, hid) {
        return Buffer.from([name, type, hid].join('\x01')).toString('base64').replace(/\//g, '_').replace(/\+/g, '-').replace(/[=]+/g, '');
    }

    parseFullId(raw) {
        try {
            raw = Buffer.from((raw || '').toString().replace(/_/g, '/').replace(/-/g, '+'), 'base64').toString();
            let [name, type, hid] = raw.split('\x01');
            return { name, type, hid };
        } catch (err) {
            logger.error({ msg: 'Failed to parse ID', raw, err });
            return {};
        }
    }

    async resolveZone(name) {
        let parts = name.split('.');
        let main = parts.slice(0, 2).join('.');
        parts.splice(0, 2, main);
        parts = parts.reverse();
        for (let i = 0; i < parts.length; i++) {
            let subName = parts.slice(i).reverse().join('.');
            let zoneExists = await this.db.redisRead.exists(`d:${subName}:z`);
            if (zoneExists) {
                return subName;
            }
        }
        return false;
    }

    getsubdomain(zoneDomain, domain) {
        if (!zoneDomain) {
            return domain;
        }
        if (zoneDomain === domain) {
            return '';
        }

        if (zoneDomain.length < domain.length && domain.substr(-(zoneDomain.length + 1)) === `.${zoneDomain}`) {
            return domain.substr(0, domain.length - (zoneDomain.length + 1));
        }
        return domain;
    }

    async delRaw(zone, name, type, hid) {
        type = (type || '').toString().trim().toUpperCase();

        if (!allowedTypes.has(type) || !name) {
            return false;
        }

        let recordKey = `d:${name}:r:${type}`;
        let res = await this.db.redisWrite.multi().hdel(recordKey, hid).exists(recordKey).exec();

        if (res[res.length - 1] && !res[res.length - 1][0] && !res[res.length - 1][1]) {
            // the record key no longer exists (no entries left), remove it from the zone
            await this.db.redisWrite.srem(`d:${zone}:z`, recordKey);
        }

        return !!(res[0] && !res[0][0] && res[0][1]);
    }

    async getRaw(zone, name, type, hid) {
        let recordKey = `d:${name}:r:${type}`;

        let entry = await this.db.redisRead.hget(recordKey, hid);
        if (!entry) {
            return false;
        }
        return this.parseEntry(zone, name, this.nameToDomain(zone), this.nameToDomain(name), type, false, hid, entry);
    }

    domainToName(domain) {
        let decoded;
        try {
            decoded = punycode.toASCII(domain.toLowerCase().trim());
        } catch (err) {
            logger.error(err);
            // ignore?
        }
        decoded = decoded.toLowerCase().trim();
        return decoded
            .split('.')
            .map(s => s.trim())
            .reverse()
            .join('.');
    }

    nameToDomain(name) {
        let encoded;
        try {
            encoded = punycode.toUnicode(name.toLowerCase().trim());
        } catch (err) {
            logger.error(err);
            // ignore?
        }

        return encoded
            .toLowerCase()
            .trim()
            .split('.')
            .map(s => s.trim())
            .reverse()
            .join('.');
    }

    formatValue(entry) {
        let result = {
            id: entry.id,
            type: entry.type
        };

        if (entry.subdomain) {
            result.subdomain = entry.subdomain;
        }

        switch (entry.type) {
            case 'A':
            case 'AAAA':
                result.address = entry.value[0];
                result.healthCheck = entry.value[1] || false;
                if (entry.health) {
                    result.health = entry.health;
                }
                break;

            case 'ANAME':
            case 'CNAME':
                result.target = entry.value[0];
                if (result.target === '@') {
                    result.target = entry.zone;
                }
                break;

            case 'MX':
                result.exchange = entry.value[0];
                result.priority = entry.value[1];
                if (result.exchange === '@') {
                    result.exchange = entry.zone;
                }
                break;

            case 'CAA':
                result.value = entry.value[0];
                result.tag = entry.value[1];
                result.flags = (entry.value[2] && Number(entry.value[2])) || 0;
                break;

            case 'NS':
                result.ns = entry.value[0];
                break;

            case 'TLSA':
                Object.assign(result, tlsaFromValue(entry.value));
                break;

            case 'TXT':
                result.data = entry.value[0];
                break;

            case 'URL':
                result.url = entry.value[0];
                if (!entry.value[2]) {
                    result.code = entry.value[1];
                }
                result.proxy = entry.value[2] || false;
                break;

            default:
                return false;
        }

        if (entry.wildcard) {
            result.wildcard = entry.wildcard;
        }

        return result;
    }

    parseEntry(zone, name, zoneDomain, domain, type, short, hid, value) {
        try {
            if (short) {
                return {
                    id: this.getFullId(name, type, hid),
                    zone: zoneDomain,
                    domain,
                    type,
                    value: JSON.parse(value)
                };
            }

            return {
                id: this.getFullId(name, type, hid),
                zone: zoneDomain,
                subdomain: this.getsubdomain(zoneDomain, domain),
                domain,
                type,
                value: JSON.parse(value)
            };
        } catch (err) {
            logger.error(err);
            return false;
        }
    }

    parseHashRecord(zone, name, domain, type, short, record) {
        if (!record || typeof record !== 'object') {
            return false;
        }

        let zoneDomain = zone ? this.nameToDomain(zone) : false;

        return Object.keys(record)
            .map(key => [key, record[key]])
            .sort((a, b) => a[1].localeCompare(b[1]))
            .map(entry => {
                let hid = entry[0];
                let value = entry[1];
                return this.parseEntry(zone, name, zoneDomain, domain, type, short, hid, value);
            })
            .filter(entry => entry);
    }

    // Public methods

    /**
     * Resolve Zone for a domain name
     * @param {String} domain Domain name to resolve Zone for
     * @returns {String} Zone domain
     */
    async resolveDomainZone(domain) {
        let zone = await this.resolveZone(this.domainToName(domain));
        return zone ? this.nameToDomain(zone) : false;
    }

    /**
     * List all DNS records for a zone
     * @param {String} zone Zone domain name
     * @returns {Array} Array of records
     */
    async list(zone) {
        zone = this.domainToName(zone);
        let list = [];

        let members = await this.db.redisRead.smembers(`d:${zone}:z`);

        members = members.sort((a, b) => {
            let aData = a.split(':');
            let bData = b.split(':');

            // prefer ordered types
            if (aData[3] !== bData[3]) {
                return orderList.indexOf(aData[3]) - orderList.indexOf(bData[3]);
            }

            // sort by value
            return punycode.toUnicode(aData[1]).localeCompare(punycode.toUnicode(bData[1]));
        });

        let req = this.db.redisRead.multi();
        for (let member of members) {
            req = req.hgetall(member);
        }
        let result = await req.exec();

        let removed = [];
        members.forEach((member, i) => {
            let memberData = member.split(':');
            let name = memberData[1];
            let domain = this.nameToDomain(name);
            let type = memberData[3];

            if (result[i] && result[i][1]) {
                this.parseHashRecord(zone, name, domain, type, false, result[i][1]).forEach(entry => {
                    list.push(entry);
                });
            } else if (result[i] && !result[i][1]) {
                removed.push(member);
            }
        });

        // clean up entries that do not exist anymore for whatever reason
        if (removed.length) {
            let req = this.db.redisWrite.multi();
            removed.forEach(member => {
                req = req.srem(`d:${zone}:z`, member);
            });
            await req.exec();
        }

        list = list.filter(entry => entry);
        for (let entry of list) {
            if (['AAAA', 'A'].includes(entry.type) && entry.value && entry.value[1]) {
                // health check is enabled, see the result
                let healthKey = `${zone}:${entry.id}`;
                // queue helath check
                try {
                    let checkStatus = await this.db.redisRead.hget(`d:health:r`, healthKey);
                    if (checkStatus) {
                        entry.health = JSON.parse(checkStatus);
                    }
                } catch (err) {
                    logger.error({ msg: 'Failed to check health data', entry, err });
                }
            }
        }

        return list;
    }

    /**
     * List record types that exist at an exact name, optionally also folding in
     * the types a single-level wildcard could answer at that name (probed in the
     * same pipeline). Used to build DNSSEC NSEC type bitmaps: listing the
     * wildcard-answerable types keeps an RFC 8198 aggressive-NSEC resolver from
     * synthesizing a NODATA that suppresses the wildcard answer.
     * @param {String} domain Exact domain name
     * @param {Boolean} includeWildcard Also probe the single-level wildcard key
     * @returns {Array} Array of record type strings present at the name
     */
    async existingTypes(domain, includeWildcard) {
        let name = this.domainToName(domain);
        if (!name) {
            return [];
        }

        // Same single-level wildcard key construction resolve() uses: replace the
        // most-specific label with '*'.
        let wildcardName = includeWildcard && name.includes('.') ? toWildcardName(name) : null;
        let names = wildcardName && wildcardName !== name ? [name, wildcardName] : [name];

        let req = this.db.redisRead.multi();
        for (let probe of names) {
            for (let type of orderList) {
                req = req.exists(`d:${probe}:r:${type}`);
            }
        }
        let res = await req.exec();

        let types = new Set();
        names.forEach((probe, n) => {
            // Each probe contributed one EXISTS per orderList type, in order; take
            // that probe's contiguous slice of the flat pipeline result.
            let probeRes = res.slice(n * orderList.length, (n + 1) * orderList.length);
            orderList.forEach((type, i) => {
                if (probeRes[i] && probeRes[i][1]) {
                    types.add(type);
                }
            });
        });
        return [...types];
    }

    /**
     * Add new resource record to Zone
     * @param {String} zone Zone domain
     * @param {String} subdomain Subdomain to add (or empty for apex records)
     * @param {String} type Record type
     * @param {Array} value Record specific value
     * @returns {String} Record ID
     */
    async add(zone, subdomain, type, value, options) {
        options = options || {};
        let domain = normalizeDomain(
            []
                .concat(subdomain || [])
                .concat(zone || [])
                .join('.')
        );

        let name = this.domainToName(domain);
        zone = this.domainToName(zone);
        type = (type || '').toString().trim().toUpperCase();

        if (!Array.isArray(value)) {
            value = [].concat(value || []);
        }

        if (!value.length) {
            return false;
        }

        if (!allowedTypes.has(type) || !name) {
            return false;
        }

        // Reject TLSA records whose certificate data is not even-length hex; the
        // wire encoder would otherwise silently truncate it (RFC 6698 RDATA).
        if (type === 'TLSA' && !isEvenHex(value[3])) {
            return false;
        }

        let recordKey = `d:${name}:r:${type}`;
        let hid = nanoid();

        let id = this.getFullId(name, type, hid);

        let req = this.db.redisWrite
            .multi()
            .hsetnx(recordKey, hid, JSON.stringify(value || ''))
            .sadd(`d:${zone}:z`, recordKey);

        if (['AAAA', 'A'].includes(type)) {
            let healthKey = `${zone}:${id}`;
            if (value[1]) {
                // queue helath check
                req = req.zadd(`d:health:z`, Date.now(), healthKey);
            } else {
                // delete health check entry and result
                req = req.zrem(`d:health:z`, healthKey).hdel(`d:health:r`, healthKey);
            }
        }

        if (options.expire) {
            req = req.expire(recordKey, options.expire);
        }

        let res = await req.exec();

        if (res[0] && !res[0][0] && res[0][1]) {
            return id;
        }

        return false;
    }

    /**
     * Update value for an existing resource resource record
     * @param {String} id Record ID
     * @param {Array} value Record specific value
     * @returns {String} Record ID
     */
    async update(zone, id, updatedSubdomain, updatedType, value) {
        let updatedDomain = normalizeDomain(
            []
                .concat(updatedSubdomain || [])
                .concat(zone || [])
                .join('.')
        );

        zone = this.domainToName(zone);
        const { name, type, hid } = this.parseFullId(id);

        if (!hid) {
            return false;
        }

        let originalDomain = this.nameToDomain(name);
        if (updatedDomain !== originalDomain || updatedType !== type) {
            // domain name or type changed, delete old, add new

            let deleted = await this.del(zone, id);
            if (!deleted) {
                return false;
            }
            return await this.add(this.nameToDomain(zone), updatedSubdomain, updatedType, value);
        }

        // Same TLSA even-length-hex guard add() applies: the changed-name/type path
        // above routes through add(), but this unchanged path writes directly and
        // would otherwise let a corrupt cert through that the wire encoder truncates.
        if (type === 'TLSA' && !isEvenHex(Array.isArray(value) ? value[3] : null)) {
            return false;
        }

        let updatedId = this.getFullId(name, type, hid);

        let recordKey = `d:${name}:r:${type}`;
        let req = this.db.redisWrite
            .multi()
            .hset(recordKey, hid, JSON.stringify(value || ''))
            .sadd(`d:${zone}:z`, recordKey);

        if (['AAAA', 'A'].includes(type)) {
            let healthKey = `${zone}:${id}`;
            if (value[1]) {
                // queue helath check
                req = req.zadd(`d:health:z`, Date.now(), healthKey);
            } else {
                // delete health check entry and result
                req = req.zrem(`d:health:z`, healthKey).hdel(`d:health:r`, healthKey);
            }
        }

        let res = await req.exec();

        if (res[0] && !res[0][0]) {
            return updatedId;
        }

        return false;
    }

    /**
     * Retrieves resource record from base
     * @param {String} domain Domain name to look for
     * @param {String} type Record type to look for
     * @param {Boolean} fast If true then skips additional steps like resolving Zone for the domain etc.
     * @returns {Object} Resource record
     */
    async resolve(domain, type, short) {
        type = (type || '').toString().trim().toUpperCase();

        let name = this.domainToName(domain);
        if (!allowedTypes.has(type) || !name) {
            return false;
        }

        let zone = !short ? await this.resolveZone(name) : false;

        let recordKey = `d:${name}:r:${type}`;

        let exactRecord = await this.db.redisRead.hgetall(recordKey);
        let exactRes = this.parseHashRecord(zone, name, domain, type, short, exactRecord);

        let checkHealthStatus = async list => {
            for (let entry of list) {
                if (['AAAA', 'A'].includes(entry.type) && entry.value && entry.value[1]) {
                    try {
                        if (!zone) {
                            zone = await this.resolveZone(name);
                        }
                        let healthKey = `${zone}:${entry.id}`;
                        let checkStatus = await this.db.redisRead.hget(`d:health:r`, healthKey);
                        if (checkStatus) {
                            entry.health = JSON.parse(checkStatus);
                        }
                    } catch (err) {
                        logger.error({ msg: 'Failed to check health data', entry, err });
                    }
                }
            }
            return list;
        };

        if (exactRes && exactRes.length) {
            return await checkHealthStatus(exactRes);
        }

        let wildcardName = toWildcardName(name);
        let wildcardDomain = this.nameToDomain(wildcardName);
        let wildcardRecordKey = `d:${wildcardName}:r:${type}`;

        let wildcardRecord = await this.db.redisRead.hgetall(wildcardRecordKey);
        let wildRes = this.parseHashRecord(zone, wildcardName, domain, type, short, wildcardRecord);

        if (wildRes && wildRes.length) {
            return await checkHealthStatus(
                wildRes.map(entry => {
                    entry.wildcard = wildcardDomain;
                    return entry;
                })
            );
        }

        return false;
    }

    /**
     * Deletes records by query
     * @param {String} domain Domain name to look for (no wildcard match)
     * @param {String} type Record type to look for
     * @returns {Number} Count of deleted records that macthed query
     */
    async deleteDomain(domain, type, value) {
        type = (type || '').toString().trim().toUpperCase();

        let name = this.domainToName(domain);
        if (!allowedTypes.has(type) || !name) {
            return false;
        }

        let zone = await this.resolveZone(name);

        let recordKey = `d:${name}:r:${type}`;

        let exactRecord = await this.db.redisRead.hgetall(recordKey);
        let list = this.parseHashRecord(zone, name, domain, type, false, exactRecord);

        let valueMatch = value ? JSON.stringify(value) : false;

        let deleted = 0;
        if (list && list.length) {
            for (let entry of list) {
                const { name, type, hid } = this.parseFullId(entry.id);
                if (valueMatch && JSON.stringify(entry.value) !== valueMatch) {
                    continue;
                }
                if (await this.delRaw(zone, name, type, hid)) {
                    deleted++;
                }
            }
        }

        return deleted;
    }

    /**
     * Delete a record from base
     * @param {String} id Record ID to delete
     * @returns {Boolean} was the record deleted or not
     */
    async del(zone, id) {
        zone = this.domainToName(zone);
        const { name, type, hid } = this.parseFullId(id);
        if (!hid) {
            return false;
        }

        try {
            return !!(await this.delRaw(zone, name, type, hid));
        } catch (err) {
            logger.error(err);
            return false;
        }
    }
}

module.exports.ZoneStore = ZoneStore;
module.exports.zoneStore = new ZoneStore(db);
module.exports.allowedTypes = [...allowedTypes];
module.exports.allowedTags = [...allowedTags];
module.exports.tlsaToValue = tlsaToValue;
module.exports.tlsaFromValue = tlsaFromValue;
module.exports.isEvenHex = isEvenHex;
