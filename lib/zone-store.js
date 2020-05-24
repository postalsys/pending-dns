'use strict';

const punycode = require('punycode');
const db = require('./db');
const logger = require('./logger');

const orderList = ['A', 'AAAA', 'ANAME', 'CNAME', 'TXT', 'CAA', 'URL', 'NS'];

class ZoneStore {
    constructor(db, options) {
        this.db = db;
        this.options = options;
    }

    getId(zone, sub, type, value) {
        return Buffer.from(JSON.stringify([zone, sub, type, value]))
            .toString('base64')
            .replace(/\//g, '_')
            .replace(/\+/g, '-')
            .replace(/[=]+/g, '');
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

    getSub(zoneDomain, domain) {
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

    async delRaw(zone, name, type, value) {
        type = (type || '').trim().toUpperCase();

        value = typeof value === 'string' ? value : JSON.stringify(value || '');

        if (!type || !name) {
            return false;
        }

        let recordKey = `d:${name}:r:${type}`;
        let res = await this.db.redisWrite.multi().srem(recordKey, value).exists(`d:${zone}:z`, recordKey).exec();

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
        let zoneDomain = zone;
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
            req = req.smembers(member);
        }
        let result = await req.exec();

        let removed = [];
        members.forEach((member, i) => {
            let memberData = member.split(':');
            let domain = this.nameToDomain(memberData[1]);
            let type = memberData[3];

            if (result[i] && result[i][1]) {
                []
                    .concat(result[i][1] || [])
                    .sort((a, b) => {
                        return a.localeCompare(b);
                    })
                    .forEach(value => {
                        try {
                            list.push({
                                id: this.getId(zone, memberData[1], type, value),
                                zone: zoneDomain,
                                sub: this.getSub(zoneDomain, domain),
                                domain,
                                type,
                                value: JSON.parse(value)
                            });
                        } catch (err) {
                            logger.error(err);
                            // ignore
                        }
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

        return list;
    }

    /**
     * Add new resource record to Zone
     * @param {String} zone Zone domain
     * @param {String} sub Subdomain to add (or empty for apex records)
     * @param {String} type Record type
     * @param {Array} value Record specific value
     * @returns {String} Record ID
     */
    async set(zone, sub, type, value) {
        let domain = []
            .concat(sub || [])
            .concat(zone || [])
            .join('.');

        let name = this.domainToName(domain);
        zone = this.domainToName(zone);
        type = (type || '').trim().toUpperCase();

        value = JSON.stringify(value || '');

        if (!type || !name) {
            return false;
        }

        let recordKey = `d:${name}:r:${type}`;
        let res = await this.db.redisWrite.multi().sadd(recordKey, value).sadd(`d:${zone}:z`, recordKey).exec();

        if (res[0] && !res[0][0] && res[0][1]) {
            return this.getId(zone, name, type, value);
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
    async get(domain, type, fast) {
        type = (type || '').trim().toUpperCase();

        let name = this.domainToName(domain);
        if (!name || !type) {
            return false;
        }

        let zone = !fast ? await this.resolveZone(name) : false;
        let zoneDomain = zone ? this.nameToDomain(zone) : false;

        let getValues = (r, name) => {
            return (
                r &&
                r
                    .sort((a, b) => {
                        return a.localeCompare(b);
                    })
                    .map(value => {
                        try {
                            if (fast) {
                                return {
                                    domain,
                                    type,
                                    value: JSON.parse(value)
                                };
                            }

                            return {
                                id: this.getId(zone, name, type, value),
                                zone: zoneDomain,
                                sub: this.getSub(zoneDomain, domain),
                                domain,
                                type,
                                value: JSON.parse(value)
                            };
                        } catch (err) {
                            logger.error(err);
                            return false;
                        }
                    })
                    .filter(value => value)
            );
        };

        let recordKey = `d:${name}:r:${type}`;
        let wildCardName = name.replace(/\.[^.]+$/, '.*');
        let wildcardRecordKey = `d:${name.replace(/\.[^.]+$/, '.*')}:r:${type}`;

        let res = await this.db.redisRead.smembers(recordKey);
        let exactRes = getValues(res, name);
        if (exactRes && exactRes.length) {
            return exactRes;
        }

        res = await this.db.redisRead.smembers(wildcardRecordKey);
        return getValues(res, wildCardName);
    }

    /**
     * Delete a record from base
     * @param {String} id Record ID to delete
     * @returns {Boolean} was the record deleted or not
     */
    async del(id) {
        let raw = Buffer.from(id.replace(/_/g, '/').replace(/-/g, '+'), 'base64').toString();

        try {
            let [zone, sub, type, value] = JSON.parse(raw);
            return !!(await this.delRaw(zone, sub, type, value));
        } catch (err) {
            logger.error(err);
            return false;
        }
    }
}

module.exports.ZoneStore = ZoneStore;
module.exports.zoneStore = new ZoneStore(db);

/*
let main = async () => {
    let zone = module.exports.zoneStore;

    let r;

    r = await zone.set('neti.ee', false, 'A', ['1.2.3.4']);
    logger.info(r);

    r = await zone.set('neti.ee', 'xxx', 'A', ['1.2.3.6']);
    logger.info(r);

    r = await zone.set('neti.ee', false, 'A', ['1.2.3.5']);
    logger.info(r);

    r = await zone.set('neti.ee', 'www', 'CNAME', ['neti.ee']);
    logger.info(r);

    r = await zone.set('neti.ee', 'jõgeva', 'CNAME', ['jõgeva.ee']);
    logger.info(r);

    r = await zone.set('neti.ee', '*.test', 'CNAME', ['neti.ee']);
    logger.info(r);

    r = await zone.set('neti.ee', 'test', 'CNAME', ['neti.ee']);
    logger.info(r);

    r = await zone.set('neti.ee', 'peeter', 'ANAME', ['github.io']);
    logger.info(r);

    r = await zone.set('neti.ee', 'delfi.test', 'CNAME', ['delfi.neti.ee']);
    logger.info(r);

    let list = await zone.list('neti.ee');
    logger.info(list);

    r = await zone.get('neti.ee', 'A');
    logger.info(r);

    r = await zone.get('www.neti.ee', 'CNAME');
    logger.info(r);

    r = await zone.get('www.neti.ee', 'CNAME', true);
    logger.info(r);

    r = await zone.get('supikas.test.neti.ee', 'CNAME');
    logger.info(r);

    r = await zone.get('supikas.test.neti.ee', 'CNAME', true);
    logger.info(r);

    r = await zone.get('delfi.test.neti.ee', 'CNAME');
    logger.info(r);

    r = await zone.get('delfi.test.neti.ee', 'CNAME', true);
    logger.info(r);

    r = await zone.get('supikas.neti.ee', 'CNAME');
    logger.info(r);

    r = await zone.get('supikas.neti.ee', 'CNAME', true);
    logger.info(r);

    r = await zone.resolveDomainZone('supikas.neti.ee');
    logger.info('Zone: ', r);

    for (let entry of list) {
        //r = await zone.del(entry.id);
        //logger.info(r);
    }

    r = await zone.list('neti.ee');
    logger.info(r);
};

main()
    .then(() => {
        logger.info('DONE');
        process.exit();
    })
    .catch(err => {
        logger.error(err);
        process.exit(1);
    });
*/
