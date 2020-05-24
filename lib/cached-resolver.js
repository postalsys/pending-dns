'use strict';

const config = require('wild-config');
const db = require('./db');
const punycode = require('punycode');
const { Resolver } = require('dns').promises;
const resolver = new Resolver();
const logger = require('./logger');

if (config.resolver.ns) {
    resolver.setServers([].concat(config.resolver.ns || []));
}

module.exports = async (target, type) => {
    try {
        target = punycode.toASCII(target.trim().toLowerCase().trim().toLowerCase());
    } catch (err) {
        return false;
    }

    type = (type || 'A').toString().toUpperCase().trim();
    const cacheKey = ['dns', target, type].join(':');

    let record = false;

    let cached = await db.redisRead.get(cacheKey);
    if (cached) {
        try {
            record = JSON.parse(cached);
        } catch (err) {
            // ignore
        }
    }

    if (record && record.expires > Date.now()) {
        return record.data;
    }

    try {
        let resolved = await resolver[`resolve${type === 'AAAA' ? '6' : '4'}`](target);
        if ((!resolved || !resolved.length) && record) {
            return record.data;
        }
        await db.redisWrite
            .multi()
            .set(
                cacheKey,
                JSON.stringify({
                    expires: Date.now() + 10 * 60 * 1000,
                    data: resolved || false
                })
            )
            .expire(cacheKey, 8 * 3600 * 1000)
            .exec();
        return resolved || false;
    } catch (err) {
        logger.warn({ msg: 'Failed to resolve ANAME', target, type, err });
        if (record) {
            // keep using the cached data
            return record.data;
        }
        // cache error for a short time
        await db.redisWrite
            .multi()
            .set(
                cacheKey,
                JSON.stringify({
                    expires: Date.now() + 60 * 1000,
                    data: false,
                    error: err.message,
                    code: err.code || err.errno
                })
            )
            .expire(cacheKey, 1 * 3600 * 1000)
            .exec();
        return false;
    }
};
