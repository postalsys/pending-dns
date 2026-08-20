'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const pathlib = require('node:path');

// A child process, because the assertion is about what actually reaches stdout.
const logInChild = body =>
    new Promise(resolve => {
        const script = `
            const logger = require('./lib/logger.js');
            ${body}
        `;
        execFile(
            process.execPath,
            ['-e', script],
            // config/test.toml silences the logger, so turn it back up here
            { cwd: pathlib.join(__dirname, '..'), env: Object.assign({}, process.env, { NODE_ENV: 'test', appconf_log_level: 'trace' }) },
            (_err, stdout) => resolve(stdout)
        );
    });

// ioredis puts the command it was running on its reply errors. On a failed
// handshake that command is HELLO/AUTH, so the default pino error serializer -
// which copies every enumerable property - would put the Redis password in the
// log. lib/db.js, lib/close-process.js and lib/public-server.js all log such an
// error, so the censoring lives in the logger.
const redisAuthError = `
    const err = new Error('WRONGPASS invalid username-password pair or user is disabled.');
    err.command = { name: 'hello', args: ['3', 'AUTH', 'default', 'aSecretRedisPassword'] };
`;

test('a redis reply error never carries its command arguments into the log', async () => {
    const stdout = await logInChild(`${redisAuthError} logger.error({ msg: 'Redis connection error', role: 'read', err });`);

    assert.ok(!stdout.includes('aSecretRedisPassword'), 'the password reached the log');
    assert.ok(stdout.includes('[redacted]'), 'the arguments were not censored');
    // the rest of the error is still useful
    assert.ok(stdout.includes('WRONGPASS'));
});

test('child loggers censor it too', async () => {
    // every lib/ module logs through logger.child({ component })
    const stdout = await logInChild(`${redisAuthError} logger.child({ component: 'db' }).fatal({ msg: 'unhandledRejection', err });`);

    assert.ok(!stdout.includes('aSecretRedisPassword'), 'the password reached the log');
    assert.ok(stdout.includes('[redacted]'));
});
