'use strict';

const udp = require('dgram');
const EventEmitter = require('events');
const Packet = require('dns2/packet');
const logger = require('./logger').child({ component: 'dns-udp-server' });

/**
 * [Server description]
 * @docs https://tools.ietf.org/html/rfc1034
 * @docs https://tools.ietf.org/html/rfc1035
 */
class DNSUdpServer extends EventEmitter {
    constructor(options, callback) {
        super();
        if (typeof options === 'function') {
            callback = options;
            options = {};
            this.on('request', callback);
        }
        this.socket = udp.createSocket('udp4');
        this.socket.on('message', this.parse.bind(this));
    }
    parse(buffer, rinfo) {
        let request;
        try {
            request = Packet.parse(buffer);
        } catch (err) {
            logger.trace({ msg: 'Failed to parse DNS package', proto: 'udp', err, buffer, port: rinfo.port, address: rinfo.address });
            return;
        }

        request.source = {
            proto: 'udp',
            port: rinfo.port,
            address: rinfo.address
        };

        this.emit('request', request, this.send.bind(this, rinfo), rinfo);
    }
    send(rinfo, message) {
        if (message instanceof Packet) {
            message = message.toBuffer();
        }
        return new Promise((resolve, reject) => {
            this.socket.send(message, rinfo.port, rinfo.address, err => {
                if (err) return reject(err);
                resolve(message);
            });
        });
    }
    listen(port, address, callback) {
        this.socket.bind(port, address, callback);
        return this;
    }
    close() {
        this.socket.close();
        this.socket = null;
        return this;
    }
}

const createDNSUdpServer = function (options) {
    return new DNSUdpServer(options);
};

module.exports = { DNSUdpServer, createDNSUdpServer };
