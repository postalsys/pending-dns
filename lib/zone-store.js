'use strict';

const punycode = require('punycode');
const shortid = require('shortid');
const db = require('./db');
const logger = require('./logger');
const { normalizeDomain } = require('./tools');

const orderList = ['A', 'AAAA', 'ANAME', 'CNAME', 'MX', 'TXT', 'CAA', 'URL', 'NS'];
const allowedTypes = new Set(orderList);
const allowedTags = new Set(['issue', 'issuewild', 'iodef']);

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

        if (res[res.length - 1] && !res[res.length - 1][0] && !res[res.length - 1][0]) {
            // key was deleted, update zone
            await this.db.redisWrite.srem(`d:${zone}:z`, recordKey);
        }

        return !!(res[0] && !res[0][0] && res[0][1]);
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

            case 'TXT':
                result.data = entry.value[0];
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
            .sort((a, b) => {
                return a[1].localeCompare(b[1]);
            })
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

        return list.filter(entry => entry);
    }

    /**
     * Add new resource record to Zone
     * @param {String} zone Zone domain
     * @param {String} subdomain Subdomain to add (or empty for apex records)
     * @param {String} type Record type
     * @param {Array} value Record specific value
     * @returns {String} Record ID
     */
    async add(zone, subdomain, type, value) {
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

        let recordKey = `d:${name}:r:${type}`;
        let hid = shortid.generate();
        let res = await this.db.redisWrite
            .multi()
            .hsetnx(recordKey, hid, JSON.stringify(value || ''))
            .sadd(`d:${zone}:z`, recordKey)
            .exec();

        if (res[0] && !res[0][0] && res[0][1]) {
            return this.getFullId(name, type, hid);
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

        let recordKey = `d:${name}:r:${type}`;
        let res = await this.db.redisWrite
            .multi()
            .hset(recordKey, hid, JSON.stringify(value || ''))
            .sadd(`d:${zone}:z`, recordKey)
            .exec();

        if (res[0] && !res[0][0]) {
            return this.getFullId(name, type, hid);
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
        if (exactRes && exactRes.length) {
            return exactRes;
        }

        let wildcardName = name.replace(/\.[^.]+$/, '.*');
        let wildcardDomain = this.nameToDomain(wildcardName);
        let wildcardRecordKey = `d:${name.replace(/\.[^.]+$/, '.*')}:r:${type}`;

        let wildcardRecord = await this.db.redisRead.hgetall(wildcardRecordKey);
        let wildRes = this.parseHashRecord(zone, wildcardName, domain, type, short, wildcardRecord);
        if (wildRes && wildRes.length) {
            return wildRes.map(entry => {
                entry.wildcard = wildcardDomain;
                return entry;
            });
        }

        return false;
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
