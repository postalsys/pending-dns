'use strict';

const punycode = require('punycode');

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

module.exports = { normalizeDomain };
