'use strict';

const cachedResolver = require('./cached-resolver');
const punycode = require('punycode/');
const Joi = require('@hapi/joi');

const emailSchema = Joi.string().email({}).required();

const isemail = email => {
    try {
        let result = emailSchema.validate(email);
        if (result.error) {
            return false;
        }
        return true;
    } catch (err) {
        return false;
    }
};

const normalizeDomain = domain => {
    domain = (domain || '').toLowerCase().trim();
    try {
        if (/^xn--/.test(domain)) {
            domain = punycode.toUnicode(domain).normalize('NFC').toLowerCase().trim();
        }
    } catch (E) {
        // ignore
    }

    return domain;
};

const checkNSStatus = async (domain, expected) => {
    let result = {
        domain
    };
    let expectedList = expected.map(ns => normalizeDomain(ns.domain)).sort((a, b) => a.localeCompare(b));

    try {
        let list = await cachedResolver(punycode.toASCII(domain), 'NS');
        let sortedList = list.map(normalizeDomain).sort((a, b) => a.localeCompare(b));
        let hasInvalidEntry = sortedList.find(ns => !expectedList.includes(ns));

        if (sortedList.length && !hasInvalidEntry) {
            // We have at least one valid NS record and 0 invalid records
            result.status = 'valid';
        } else {
            // No NS records or at least one invalid record
            result.status = 'invalid';
        }

        result.ns = sortedList;
        result.expected = expectedList;
    } catch (err) {
        switch (err.code) {
            case 'ENOTFOUND':
                result.status = 'missing';
                break;

            default:
                result.status = 'error';
                result.error = err.message;
                if (err.code) {
                    result.errorCode = err.code;
                }
                break;
        }
        result.expected = expectedList;
    }
    return result;
};

module.exports = { normalizeDomain, checkNSStatus, isemail };
