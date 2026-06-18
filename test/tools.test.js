'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { isemail, normalizeDomain } = require('../lib/tools');
const { closeDb } = require('./helpers');

// lib/tools transitively opens Redis connections (via cached-resolver); close
// them so the test process exits cleanly.
test.after(async () => {
    await closeDb();
});

test('isemail accepts valid addresses', () => {
    assert.equal(isemail('user@example.com'), true);
    assert.equal(isemail('first.last+tag@sub.example.org'), true);
});

test('isemail rejects invalid addresses', () => {
    assert.equal(isemail(''), false);
    assert.equal(isemail('not-an-email'), false);
    assert.equal(isemail('foo@'), false);
    assert.equal(isemail('@example.com'), false);
    assert.equal(isemail(null), false);
    assert.equal(isemail(undefined), false);
});

test('normalizeDomain lowercases and trims', () => {
    assert.equal(normalizeDomain('  Example.COM '), 'example.com');
    assert.equal(normalizeDomain('WWW.Example.Com'), 'www.example.com');
});

test('normalizeDomain decodes punycode (xn--) to unicode', () => {
    // xn--nxasmq6b is the punycode for a Greek/test label; use a well-known one
    // "münchen.de" -> xn--mnchen-3ya.de
    assert.equal(normalizeDomain('xn--mnchen-3ya.de'), 'münchen.de');
});

test('normalizeDomain is idempotent on already-unicode input', () => {
    assert.equal(normalizeDomain('münchen.de'), 'münchen.de');
});

test('normalizeDomain handles empty / nullish input', () => {
    assert.equal(normalizeDomain(''), '');
    assert.equal(normalizeDomain(null), '');
    assert.equal(normalizeDomain(undefined), '');
});
