'use strict';

const net = require('net');
const EventEmitter = require('events');
const Packet = require('dns2/packet');
const logger = require('./logger').child({ component: 'dns-tcp-server' });

class DNSTcpServer extends EventEmitter {
    constructor(options, callback) {
        super();
        if (typeof options === 'function') {
            callback = options;
            options = {};
            this.on('request', callback);
        }

        this.server = net.createServer(socket => {
            let chunks = [];
            let chunklen = 0;
            let received = false;
            let expected = false;

            socket.setTimeout(10 * 1000);
            socket.on('timeout', () => {
                try {
                    socket.end();
                } catch (err) {
                    // ignore
                }
            });

            let processMessage = () => {
                if (received) {
                    return;
                }
                received = true;

                let buffer = Buffer.concat(chunks, chunklen);
                let request;
                try {
                    request = Packet.parse(buffer.slice(2));
                } catch (err) {
                    logger.error({ msg: 'Failed to parse DNS package', type: 'tcp', err, buffer, port: socket.remotePort, address: socket.remoteAddress });
                    try {
                        socket.end();
                    } catch (err) {
                        // ignore
                    }
                }
                request.source = {
                    type: 'tcp',
                    port: socket.remotePort,
                    address: socket.remoteAddress
                };
                this.emit('request', request, message => this.send(socket, message));
            };

            socket.on('readable', () => {
                let chunk;
                while ((chunk = socket.read()) !== null) {
                    chunks.push(chunk);
                    chunklen += chunk.length;
                }
                if (!expected && chunklen >= 2) {
                    if (chunks.length > 1) {
                        chunks = [Buffer.concat(chunks, chunklen)];
                    }
                    expected = chunks[0].readUInt16BE(0);
                }

                if (chunklen >= 2 + expected) {
                    processMessage();
                }
            });

            socket.on('error', err => {
                this.emit('error', err);
            });

            socket.on('end', () => {
                processMessage();
            });
        });

        this.server.on('error', err => {
            this.emit('error', err);
        });
    }

    send(socket, message) {
        if (message instanceof Packet) message = message.toBuffer();
        return new Promise(resolve => {
            try {
                let len = Buffer.alloc(2);
                len.writeUInt16BE(message.length);
                socket.end(Buffer.concat([len, message]));
            } catch (err) {
                // ignore
            }
            resolve(message);
        });
    }

    listen(port, address, callback) {
        this.server.listen(port, address, callback);
        return this;
    }
    close(cb) {
        this.server.close(cb);
        return this;
    }
}

const createDNSTcpServer = function (options) {
    return new DNSTcpServer(options);
};

module.exports = { DNSTcpServer, createDNSTcpServer };
