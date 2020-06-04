'use strict';

const config = require('wild-config');
const db = require('./db');
const { zoneStore } = require('./zone-store');
const logger = require('./logger').child({ component: 'health' });

const net = require('net');
const tls = require('tls');
const http = require('http');
const https = require('https');

const tcpHealthCheck = async url => {
    return new Promise((resolve, reject) => {
        let connectTimeout;

        let conn;
        switch (url.protocol) {
            case 'tcp:':
                conn = net.createConnection.bind(net);
                break;
            case 'tcps:':
                conn = tls.connect.bind(tls);
                break;
        }

        const client = conn({ port: url.port, host: url.hostname, tls: { rejectUnauthorized: false } }, () => {
            clearTimeout(connectTimeout);
            try {
                client.end();
            } catch (err) {
                // ignore
            }
            resolve(true);
        });

        const onTimeout = () => {
            let err = new Error('Timeout when connecting to socket');
            err.code = 'ETIMEOUT';
            try {
                client.destroy(err);
            } catch (err) {
                // ignore
            }
            reject(err);
        };

        connectTimeout = setTimeout(onTimeout, config.health.ttl);

        client.on('readable', () => {});
        client.on('end', () => {});
        client.on('error', err => {
            clearTimeout(connectTimeout);
            reject(err);
        });

        client.on('timeout', onTimeout);
        client.setTimeout(config.health.ttl);
    });
};

const httpHealthCheck = async url => {
    return new Promise((resolve, reject) => {
        let connectTimeout;

        let conn;
        switch (url.protocol) {
            case 'http:':
                conn = http.get.bind(http);
                break;
            case 'https:':
                conn = https.get.bind(https);
                break;
        }

        const client = conn(url.href, { tls: { rejectUnauthorized: false } }, res => {
            clearTimeout(connectTimeout);
            try {
                client.end();
            } catch (err) {
                // ignore
            }
            if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                resolve(true);
            }
            let err = new Error('Invalid response status code ' + res.statusCode);
            err.code = 'ESTATUSCODE';
            reject(err);
        });

        const onTimeout = () => {
            let err = new Error('Timeout when connecting to server');
            err.code = 'ETIMEOUT';
            try {
                client.destroy(err);
            } catch (err) {
                // ignore
            }
            reject(err);
        };

        connectTimeout = setTimeout(onTimeout, config.health.ttl);

        client.on('readable', () => {});
        client.on('end', () => {});
        client.on('error', err => {
            clearTimeout(connectTimeout);
            reject(err);
        });

        client.on('timeout', onTimeout);
        client.setTimeout(config.health.ttl);
    });
};

const healthCheck = async target => {
    try {
        let url = new URL(target);

        switch (url.protocol) {
            case 'tcp:':
            case 'tcps:':
                return {
                    status: await tcpHealthCheck(url)
                };
            case 'http:':
            case 'https:':
                return {
                    status: await httpHealthCheck(url)
                };
            default:
                throw new Error('Unknown protocol for URI: ' + target);
        }
    } catch (err) {
        return {
            status: false,
            error: err.message,
            code: err.code
        };
    }
};

const runHealthLoop = async () => {
    let canRun = true;
    while (canRun) {
        let nextId = await db.redisWrite.nextHealth(`d:health:z`, Date.now(), Date.now() + config.health.delay);
        if (!nextId) {
            break;
        }
        let parts = nextId.split(':');

        let id = parts.pop();
        let zone = parts.join(':');
        let { name, type, hid } = zoneStore.parseFullId(id);
        let record = await zoneStore.getRaw(zone, name, type, hid);
        if (record && record.value && record.value[1]) {
            let startTime = Date.now();
            let checkResult = await healthCheck(record.value[1]);
            let checkTime = Date.now() - startTime;
            let prevResult = await db.redisRead.hget(`d:health:r`, nextId);
            try {
                if (prevResult) {
                    prevResult = JSON.parse(prevResult);
                }
            } catch (err) {
                prevResult = false;
            }
            if (!prevResult || prevResult.status !== checkResult.status) {
                logger.info({ msg: 'Status changed', checkTime, record, current: checkResult, previous: prevResult });
                // update result
                await db.redisWrite.hset(`d:health:r`, nextId, JSON.stringify(checkResult));
            } else {
                logger.info({ msg: 'Status checked, no changes', checkTime, record, current: checkResult });
            }
        }
    }
};

const startHealthLoop = () => {
    runHealthLoop()
        .then(() => {
            setTimeout(() => startHealthLoop(), 10 * 1000);
        })
        .catch(err => {
            logger.error({ msg: 'Health loop failed', err });
            setTimeout(() => startHealthLoop(), 30 * 1000);
        });
};

const init = async () => {
    setImmediate(() => {
        for (let i = 0; i < config.health.handlers; i++) {
            startHealthLoop();
        }
    });
};

module.exports = init;
