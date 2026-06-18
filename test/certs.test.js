'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { pem2jwk } = require('pem-jwk');
const certs = require('../lib/certs');
const { closeDb } = require('./helpers');

const { generateKey } = certs.testables;

test.after(async () => {
    await closeDb();
});

test('generateKey returns a PKCS#1 RSA private key PEM', async () => {
    const pem = await generateKey(2048);
    assert.match(pem, /^-----BEGIN RSA PRIVATE KEY-----/);
    assert.match(pem, /-----END RSA PRIVATE KEY-----\s*$/);

    // the key must be loadable by Node's crypto
    const keyObject = crypto.createPrivateKey(pem);
    assert.equal(keyObject.asymmetricKeyType, 'rsa');
    assert.equal(keyObject.asymmetricKeyDetails.modulusLength, 2048);
});

test('generated key converts to a JWK via pem-jwk (as the ACME flow needs)', async () => {
    const pem = await generateKey(2048);
    const jwk = pem2jwk(pem);
    assert.equal(jwk.kty, 'RSA');
    assert.ok(jwk.n, 'modulus present');
    assert.ok(jwk.d, 'private exponent present');
});
