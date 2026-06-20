'use strict';

const dns2 = require('dns2');
const config = require('wild-config');
const dnsHandler = require('./dns-handler');
const logger = require('./logger').child({ component: 'dns-server' });
const { createDNSTcpServer } = require('./dns-tcp-server');
const { createDNSUdpServer } = require('./dns-udp-server');

const EDNS = dns2.Packet.TYPE.EDNS; // 0x29 / 41

// EDNS UDP payload size bounds. Anything a requestor advertises is clamped into
// this range; the floor is the pre-EDNS 512 minimum.
const MIN_UDP_PAYLOAD = 512;
const MAX_UDP_PAYLOAD = 4096;

const ourUdpPayloadSize = () => (config.dnssec && config.dnssec.udpPayloadSize) || 1232;

// Extract the EDNS context from a request: whether an OPT was present, the DO
// (DNSSEC OK) bit, and the requestor's advertised UDP payload size. dns2 has
// already decoded doFlag and stored the payload size in `class`.
const parseEdns = request => {
    const opt = request.additionals && request.additionals.find(record => record && record.type === EDNS);
    return {
        hasOpt: !!opt,
        doFlag: !!(opt && opt.doFlag),
        udpPayloadSize: opt ? opt.class : MIN_UDP_PAYLOAD
    };
};

const buildOpt = doFlag =>
    // eslint-disable-next-line new-cap
    dns2.Packet.Resource.EDNS([], {
        udpPayloadSize: ourUdpPayloadSize(),
        doFlag,
        version: 0
    });

// The additional section we emit: our own OPT for EDNS queries, nothing
// otherwise (responses to EDNS queries must carry an OPT - RFC 6891).
const optSection = edns => (edns.hasOpt ? [buildOpt(edns.doFlag)] : []);

// Strip a packet to header + question + OPT and set TC, so the resolver retries
// over TCP. A partial answer would be a protocol error.
const truncate = (packet, edns) => {
    packet.header.tc = 1;
    packet.answers = [];
    packet.authorities = [];
    packet.additionals = optSection(edns);
    return packet;
};

// Finalize a response before sending: replace the additional section with our
// own OPT, and for UDP truncate to the negotiated size. Returns a Buffer
// (already serialized) or a Packet; both are accepted by send.
const finalizeResponse = (response, edns, proto) => {
    // The response object is the same instance as the request (dns2.Packet
    // returns its argument), so the inbound OPT and any request additionals
    // leak in here - replace the section outright rather than appending.
    response.additionals = optSection(edns);

    if (proto !== 'udp') {
        // TCP carries arbitrarily large messages; never truncate.
        return response;
    }

    // Cap the datagram at the smaller of (the requestor's advertised size, clamped
    // to [512, 4096]) and our own configured size (default 1232, chosen to avoid IP
    // fragmentation). Honoring our cap regardless of what the resolver advertises is
    // the point: a 4096-advertising resolver must still get TC=1 above 1232 rather
    // than a fragmenting datagram that middleboxes drop.
    const requestorMax = Math.min(Math.max(edns.udpPayloadSize || MIN_UDP_PAYLOAD, MIN_UDP_PAYLOAD), MAX_UDP_PAYLOAD);
    const negotiated = Math.min(requestorMax, ourUdpPayloadSize());
    const buffer = response.toBuffer();
    if (buffer.length <= negotiated) {
        return buffer;
    }
    // Too large for UDP: truncate to header+question+OPT (TC=1) and serialize the
    // small packet here, so the UDP path always returns a ready Buffer and send
    // never re-serializes.
    return truncate(response, edns).toBuffer();
};

// Last-resort truncation if the socket itself rejects an oversized datagram.
const truncatedResponse = (request, edns) => {
    request.header.qr = 1;
    request.header.aa = 1;
    return truncate(request, edns);
};

const init = async () => {
    // create UDP server
    const udpServer = createDNSUdpServer((request, send) => {
        const edns = parseEdns(request);

        dnsHandler(request, edns)
            .then(response => send(finalizeResponse(response, edns, 'udp')))
            .catch(err => {
                if (err.code === 'EMSGSIZE') {
                    // too large response, fall back to a truncated reply
                    send(truncatedResponse(request, edns)).catch(err => logger.error({ msg: 'Failed to send truncated response', err }));
                    return;
                }
                logger.error({ msg: 'Failed to send DNS response', protocol: 'udp', err });
            });
    });

    udpServer.on('error', err => {
        logger.error({ msg: 'DNS server error', protocol: 'udp', err });
    });

    // create TCP server
    const tcpServer = createDNSTcpServer((request, send) => {
        const edns = parseEdns(request);

        dnsHandler(request, edns)
            .then(response => send(finalizeResponse(response, edns, 'tcp')))
            .catch(err => {
                logger.error({ msg: 'Failed to send DNS response', protocol: 'tcp', err });
            });
    });

    tcpServer.on('error', err => {
        let method = 'error';
        if (err && ['ECONNRESET'].includes(err.code)) {
            method = 'trace';
        }
        logger[method]({ msg: 'DNS server error', protocol: 'tcp', err });
    });

    await new Promise(resolve => {
        udpServer.listen(config.dns.port, config.dns.host, () => {
            logger.info({ msg: 'DNS server listening', protocol: 'udp', host: config.dns.host, port: config.dns.port });
            resolve();
        });
    });

    await new Promise(resolve => {
        tcpServer.listen(config.dns.port, config.dns.host, () => {
            logger.info({ msg: 'DNS server listening', protocol: 'tcp', host: config.dns.host, port: config.dns.port });
            resolve();
        });
    });

    return { udpServer, tcpServer };
};

module.exports = init;

// Exposed for unit testing
module.exports.testables = { parseEdns, finalizeResponse };
