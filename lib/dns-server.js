'use strict';

const dns2 = require('dns2');
const config = require('wild-config');
const dnsHandler = require('./dns-handler');
const logger = require('./logger').child({ component: 'dns-server' });
const { createDNSTcpServer } = require('./dns-tcp-server');
const { createDNSUdpServer } = require('./dns-udp-server');

const SUPPORTED_TYPES = new Set(
    Object.keys(dns2.Packet.TYPE)
        .map(key => dns2.Packet.TYPE[key])
        .filter(val => typeof val === 'number')
);

const init = async () => {
    // create UDP server
    createDNSUdpServer((request, send) => {
        // filter out unsupported requests (eg. EDNS)
        if (request.additionals && request.additionals.length) {
            request.additionals = request.additionals.filter(additional => SUPPORTED_TYPES.has(additional.type));
        }

        dnsHandler(request)
            .then(send)
            .catch(err => {
                if (err.code === 'EMSGSIZE') {
                    //too large response, send empty response instead
                    const response = new dns2.Packet(request);
                    response.header.qr = 1;
                    response.header.aa = 1;
                    send(response).catch(err => logger.error({ msg: 'Failed to send empty response', err }));
                    return;
                }
                logger.error({ msg: 'Failed to send DNS response', protocol: 'udp', err });
            });
    })
        .listen(config.dns.port, config.dns.host, () => {
            logger.info({ msg: 'DNS server listening', protocol: 'udp', host: config.dns.host, port: config.dns.port });
        })
        .on('error', err => {
            logger.error({ msg: 'DNS server error', protocol: 'udp', err });
        });

    // create TCP server
    createDNSTcpServer((request, send) => {
        // filter out unsupported requests (eg. EDNS)
        if (request.additionals && request.additionals.length) {
            request.additionals = request.additionals.filter(additional => SUPPORTED_TYPES.has(additional.type));
        }

        dnsHandler(request)
            .then(send)
            .catch(err => {
                logger.error({ msg: 'Failed to send DNS response', protocol: 'tcp', err });
            });
    })
        .listen(config.dns.port, config.dns.host, () => {
            logger.info({ msg: 'DNS server listening', protocol: 'tcp', host: config.dns.host, port: config.dns.port });
        })
        .on('error', err => {
            let method = 'error';
            if (err && ['ECONNRESET'].includes(err.code)) {
                method = 'trace';
            }
            logger[method]({ msg: 'DNS server error', protocol: 'tcp', err });
        });
};

module.exports = init;
