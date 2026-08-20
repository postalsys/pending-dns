'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const Redis = require('ioredis');

const { config, db, closeDb } = require('./helpers');

test.after(async () => {
    await closeDb();
});

// Find a port nothing is listening on, so connecting to it keeps failing.
const findClosedPort = () =>
    new Promise((resolve, reject) => {
        const probe = net.createServer();
        probe.once('error', reject);
        probe.listen(0, '127.0.0.1', () => {
            const { port } = probe.address();
            probe.close(() => resolve(port));
        });
    });

// A TCP proxy in front of the test Redis, so a test can take the connection
// away and hand it back without touching the Redis server itself.
const startProxy = port => {
    const upstream = new URL(config.dbs.redis);
    const sockets = new Set();

    const track = socket => {
        sockets.add(socket);
        socket.on('error', () => false);
        socket.on('close', () => sockets.delete(socket));
    };

    const server = net.createServer(client => {
        track(client);
        const target = net.connect(Number(upstream.port) || 6379, upstream.hostname);
        track(target);
        client.pipe(target).pipe(client);
    });

    const stop = () =>
        new Promise(resolve => {
            for (const socket of sockets) {
                socket.destroy();
            }
            sockets.clear();
            server.close(() => resolve());
        });

    return new Promise(resolve => {
        server.listen(port, '127.0.0.1', () => resolve({ stop }));
    });
};

// Reconnect fast so the retry counter passes ioredis' default limit of 20
// within the test, instead of the ~13 seconds the default backoff would take.
const fastRetry = () => 10;

// Wait for enough reconnect attempts that the default limit would have tripped,
// rather than sleeping for a fixed stretch and hoping.
const afterRetryLimitWouldTrip = client =>
    new Promise(resolve => {
        let attempts = 0;
        const onReconnecting = () => {
            if (++attempts <= 25) {
                return;
            }
            client.off('reconnecting', onReconnecting);
            resolve();
        };
        client.on('reconnecting', onReconnecting);
    });

const settledState = promise => {
    let state = 'pending';
    promise.then(
        () => (state = 'resolved'),
        () => (state = 'rejected')
    );
    return () => state;
};

test('both clients keep commands queued instead of flushing them on a retry limit', () => {
    // ioredfour issues SUBSCRIBE from its constructor and ioredis re-issues
    // SELECT/SUBSCRIBE on reconnect, neither with a rejection handler. A queue
    // flush would reject those and kill the worker through the global
    // unhandledRejection handler, so nothing may set a retry limit here.
    assert.equal(db.redisRead.options.maxRetriesPerRequest, null);
    assert.equal(db.redisWrite.options.maxRetriesPerRequest, null);
});

test('a duplicated connection inherits the setting', () => {
    // This is the connection ioredfour builds for the lock release channel.
    const subscriber = db.redisWrite.duplicate();
    try {
        assert.equal(subscriber.options.maxRetriesPerRequest, null);
    } finally {
        subscriber.disconnect();
    }
});

test('a command issued during an outage survives it instead of being rejected', async () => {
    const port = await findClosedPort();
    let proxy = await startProxy(port);
    const client = db.redisRead.duplicate({ host: '127.0.0.1', port, retryStrategy: fastRetry });
    client.on('error', () => false);

    try {
        await client.ping();
        await proxy.stop();

        const command = client.get('d:no-such-key');
        const state = settledState(command);

        await afterRetryLimitWouldTrip(client);
        assert.equal(state(), 'pending');

        proxy = await startProxy(port);
        assert.equal(await command, null);
    } finally {
        client.disconnect();
        await proxy.stop();
    }
});

test('the ioredis default would have rejected it', async () => {
    // Guards the reasoning above: without the override the same outage flushes
    // the queue with a MaxRetriesPerRequestError.
    const port = await findClosedPort();
    const client = new Redis({ host: '127.0.0.1', port, retryStrategy: fastRetry });
    client.on('error', () => false);

    try {
        await assert.rejects(client.get('d:no-such-key'), /max retries per request/);
    } finally {
        client.disconnect();
    }
});
