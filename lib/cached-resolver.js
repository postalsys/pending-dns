'use strict';

const config = require('wild-config');
const db = require('./db');
const punycode = require('punycode/');
const { Resolver } = require('dns').promises;
const resolver = new Resolver();
const logger = require('./logger').child({ component: 'cached-resolver' });

if (config.resolver.ns) {
    resolver.setServers([].concat(config.resolver.ns || []));
}

function formatResult(record) {
    if (!record) {
        return false;
    }
    if (record.error) {
        let err = new Error(record.error);
        if (record.code) {
            err.code = record.code;
        }
        throw err;
    }
    return record.data;
}

/**
 * Resolves and caches DNS queries.
 * @param {String} target Domain name to resolve
 * @param {String} [type=A] Query type (A, AAAA, MX, etc.)
 * @param {Object} [options]
 * @param {Number} [options.minTtl=10min] Cache timeout for successful resolving operations. If cached response is older than this value then resolving is retried. If resolving fails then cached value is used.
 * @param {Number} [options.maxTtl=8h] Time after cached data of a successful resolving is permanently deleted
 * @param {Number} [options.errorTtl=1min] Cache timeout for errored resolving operations. If cached response is older than this value then resolving is retried
 * @returns {Array|Boolean} Resolve response or `false` if query failed for whatever reason
 */
const cachedResolver = async (target, type, options) => {
    try {
        target = punycode.toASCII(target.trim().toLowerCase().trim().toLowerCase());
    } catch (err) {
        return false;
    }

    options = Object.assign(
        {
            minTtl: 10 * 60 * 1000,
            maxTtl: 8 * 3600 * 1000,
            errorMinTtl: 1 * 60 * 1000,
            errorMaxTtl: 1 * 3600 * 1000
        },
        options || {}
    );

    type = (type || 'A').toString().toUpperCase().trim();
    const cacheKey = ['d', 'cache', target, type].join(':');

    let record = false;

    let cached = await db.redisRead.get(cacheKey);
    if (cached) {
        try {
            record = JSON.parse(cached);
        } catch (err) {
            // ignore
        }
    }

    if (record && record.expires && record.expires > Date.now()) {
        return formatResult(record);
    }

    try {
        let queryHandler;
        switch (type) {
            case 'A':
                queryHandler = 'resolve4';
                break;
            case 'AAAA':
                queryHandler = 'resolve6';
                break;
            case 'PTR':
                queryHandler = 'reverse';
                break;
            default:
                queryHandler = `resolve${type.toLowerCase().replace(/^./, c => c.toUpperCase())}`;
        }

        if (typeof resolver[queryHandler] !== 'function') {
            throw new Error('Unknown query type ' + type);
        }

        let resolved = await resolver[queryHandler](target);

        if (!resolved && record) {
            return formatResult(record);
        }

        await db.redisWrite
            .multi()
            .set(
                cacheKey,
                JSON.stringify({
                    expires: Date.now() + options.minTtl,
                    data: resolved || false
                })
            )
            .expire(cacheKey, Math.round(options.maxTtl / 1000))
            .exec();
        return resolved || false;
    } catch (err) {
        logger.warn({ msg: 'Failed to resolve query', target, type, err });
        if (record) {
            // keep using the cached data
            return formatResult(record);
        }
        // cache error for a short time
        await db.redisWrite
            .multi()
            .set(
                cacheKey,
                JSON.stringify({
                    data: false,
                    error: err.message,
                    code: err.code || err.errno
                })
            )
            .expire(cacheKey, Math.round(options.errorTtl / 1000))
            .exec();
        throw err;
    }
};

module.exports = cachedResolver;
