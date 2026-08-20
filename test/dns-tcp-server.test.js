'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const v8 = require('node:v8');
const vm = require('node:vm');

const { Packet } = require('dns2');
const { createDNSTcpServer } = require('../lib/dns-tcp-server');

// Frame a DNS query the way RFC 7766 wants it: a 2-byte length prefix followed
// by the message.
const framedQuery = name => {
    const packet = new Packet({});
    packet.header.id = 1234;
    packet.header.rd = 1;
    packet.questions.push({ name, type: Packet.TYPE.A, class: Packet.CLASS.IN });
    const message = packet.toBuffer();
    const length = Buffer.alloc(2);
    length.writeUInt16BE(message.length);
    return Buffer.concat([length, message]);
};

const listen = server =>
    new Promise(resolve => {
        server.listen(0, '127.0.0.1', () => resolve(server.server.address().port));
    });

const closeServer = server => new Promise(resolve => server.close(resolve));

const connect = port =>
    new Promise((resolve, reject) => {
        const socket = net.connect(port, '127.0.0.1', () => resolve(socket));
        socket.once('error', reject);
    });

const deferred = () => {
    let resolve;
    const promise = new Promise(done => {
        resolve = done;
    });
    return { promise, resolve };
};

// process.memoryUsage() reports what is allocated, not what is still reachable,
// so the buffer measurement below needs a collection first. Reach for gc()
// without requiring the whole suite to run under --expose-gc.
v8.setFlagsFromString('--expose-gc');
const gc = vm.runInNewContext('gc');
v8.setFlagsFromString('--no-expose-gc');

test('answers a query and closes the connection', async () => {
    const requests = [];
    const server = createDNSTcpServer((request, send) => {
        requests.push(request);
        send(Packet.createResponseFromRequest(request));
    });
    const port = await listen(server);

    try {
        const socket = await connect(port);
        const received = await new Promise((resolve, reject) => {
            const chunks = [];
            socket.on('data', chunk => chunks.push(chunk));
            socket.on('error', reject);
            socket.on('close', () => resolve(Buffer.concat(chunks)));
            socket.write(framedQuery('example.com'));
        });

        assert.equal(requests.length, 1);
        assert.equal(requests[0].questions[0].name, 'example.com');
        // length prefix plus a parseable answer
        assert.ok(received.length > 2);
        assert.equal(Packet.parse(received.subarray(2)).header.id, 1234);
    } finally {
        await closeServer(server);
    }
});

test('stops reading once a query is in flight, instead of buffering the rest', async () => {
    const requested = deferred();
    const answer = deferred();

    const server = createDNSTcpServer((request, send) => {
        // Hold the answer back, the way a Redis lookup stalled on an unreachable
        // server would, and let the client flood the connection meanwhile.
        requested.resolve();
        answer.promise.then(() => send(Packet.createResponseFromRequest(request)));
    });
    server.on('error', () => false);
    const port = await listen(server);

    const junk = Buffer.alloc(1024 * 1024, 0x41);
    const megabytes = 16;

    const socket = await connect(port);
    socket.on('error', () => false);
    // Read the answer away, otherwise the paused socket never ends.
    socket.resume();

    try {
        socket.write(framedQuery('example.com'));
        await requested.promise;

        // Buffers live outside the V8 heap, so this is the number that moves if
        // the server holds on to what it reads.
        gc();
        const before = process.memoryUsage().arrayBuffers;

        for (let i = 0; i < megabytes; i++) {
            if (socket.write(junk)) {
                continue;
            }
            // A server that stopped reading closes its receive window, so the
            // drain never comes - that is the outcome under test, not a failure.
            const drained = await Promise.race([
                new Promise(resolve => socket.once('drain', () => resolve(true))),
                new Promise(resolve => setTimeout(() => resolve(false), 500))
            ]);
            if (!drained) {
                break;
            }
        }

        gc();
        const grew = process.memoryUsage().arrayBuffers - before;
        assert.ok(
            grew < (megabytes / 2) * 1024 * 1024,
            `buffers grew by ${Math.round(grew / 1024 / 1024)}MB while the server should have been holding none of it`
        );
    } finally {
        answer.resolve();
        socket.destroy();
        await closeServer(server);
    }
});

test('a malformed query is dropped and the connection closed', async () => {
    const server = createDNSTcpServer(() => {
        throw new Error('a malformed packet must never reach the handler');
    });
    server.on('error', () => false);
    const port = await listen(server);

    const socket = await connect(port);
    socket.on('error', () => false);

    try {
        // a length prefix followed by fewer bytes than a DNS header needs
        const body = Buffer.from([0x01, 0x02, 0x03]);
        const length = Buffer.alloc(2);
        length.writeUInt16BE(body.length);

        const answered = await new Promise(resolve => {
            const chunks = [];
            socket.on('data', chunk => chunks.push(chunk));
            socket.on('close', () => resolve(Buffer.concat(chunks)));
            socket.write(Buffer.concat([length, body]));
        });

        assert.equal(answered.length, 0, 'nothing should be written back');
    } finally {
        socket.destroy();
        await closeServer(server);
    }
});
