'use strict';

const config = require('wild-config');
const http = require('http');
const http2 = require('http2');
const { normalizeDomain } = require('./tools');
const logger = require('./logger').child({ component: 'public-server' });
const { loadCertificate } = require('./certs');
const tls = require('tls');
const fs = require('fs');
const pathlib = require('path');
const zlib = require('zlib');
const db = require('./db');
const Handlebars = require('handlebars');
const { zoneStore } = require('./zone-store');
const httpProxy = require('http-proxy');

const proxyServer = httpProxy.createProxyServer({});

proxyServer.on('proxyReq', function (proxyReq, req /*, res, options*/) {
    proxyReq.setHeader('X-Forwarded-Proto', req.proto);
    proxyReq.setHeader('X-Connecting-IP', req.ip);
});

const errors = {};
Object.keys(config.public.errors).forEach(key => {
    errors[key] = Handlebars.compile(fs.readFileSync(config.public.errors[key], 'utf-8'));
});

let defaultKey, defaultCert, dhparam;
if (config.public.https.key) {
    defaultKey = fs.readFileSync(config.public.https.key, 'utf-8');
} else {
    defaultKey = fs.readFileSync(pathlib.join(__dirname, '..', 'config', 'default-privkey.pem'), 'utf-8');
}

if (config.public.https.cert) {
    defaultCert = fs.readFileSync(config.public.https.cert, 'utf-8');
} else {
    defaultCert = fs.readFileSync(pathlib.join(__dirname, '..', 'config', 'default-cert.pem'), 'utf-8');
}

if (config.public.https.dhParam) {
    dhparam = fs.readFileSync(config.public.https.dhParam, 'utf-8');
}

const movedTemplate = `<html>
<head><title>301 Moved Permanently</title></head>
<body bgcolor="white">
<center><h1>301 Moved Permanently</h1></center>
<hr><center>Project Pending</center>
</body>
</html>`;

const sessionIdContext = 'pendingdns';

const defaultCtx = tls.createSecureContext({
    key: defaultKey,
    cert: defaultCert,
    dhparam,
    sessionIdContext
});

const getHostname = req => {
    let host =
        []
            .concat(req.headers.host || [])
            .concat(req.authority || [])
            .shift() || '';

    host = host.replace(/^\[|\]?:\d+$/g, '');
    if (!host) {
        host = req.ip || '';
    }

    if (host) {
        host = normalizeDomain(host);
    }

    return host;
};

const ctxCache = new Map();
const getSNIContext = async servername => {
    const domain = normalizeDomain(servername.split(':').shift());

    try {
        let records = await zoneStore.resolve(domain, 'URL', true);
        if (!records || !records.length) {
            // nothing found, so no redirect needed
            return defaultCtx;
        }

        const cert = await loadCertificate(domain);
        if (!cert || !cert.cert) {
            return defaultCtx;
        }

        if (ctxCache.has(domain)) {
            let { expires, ctx } = ctxCache.get(domain);
            if (expires === cert.expires.getTime()) {
                return ctx;
            }
            ctxCache.delete(domain);
        }

        const ctxOpts = {
            key: cert.key,
            cert: []
                .concat(cert.cert || [])
                .concat(cert.chain || [])
                .join('\n\n'),
            dhparam,
            sessionIdContext
        };

        if (config.public.https.ciphers) {
            ctxOpts.ciphers = config.public.https.ciphers;
        }

        const ctx = tls.createSecureContext(ctxOpts);

        ctxCache.set(domain, {
            expires: cert.expires.getTime(),
            ctx
        });

        return ctx;
    } catch (err) {
        return defaultCtx;
    }
};

const middleware = (req, res) => {
    req.ip = res.socket.remoteAddress;
    req.url = req.url || req.headers[':path'];

    res.setHeader('Server', config.public.server);
    res.setHeader('Vary', 'Accept-Encoding');

    res.send = buf => {
        if (typeof buf === 'string') {
            buf = Buffer.from(buf);
        }

        const acceptEncoding = (req.headers['accept-encoding'] || '').toString();

        let zip;
        if (acceptEncoding.match(/\bgzip\b/)) {
            res.setHeader('Content-Encoding', 'gzip');
            zip = zlib.createGzip();
            zip.pipe(res);
        } else if (acceptEncoding.match(/\bdeflate\b/)) {
            res.setHeader('Content-Encoding', 'deflate');
            zip = zlib.createDeflate();
            zip.pipe(res);
        } else {
            zip = res;
        }

        if (!res.statusCode) {
            res.statusCode = 200;
        }
        zip.end(buf);
    };
};

const handler = async (req, res) => {
    const domain = getHostname(req);
    let records = await zoneStore.resolve(domain, 'URL', true);

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader(`Strict-Transport-Security`, `max-age=${180 * 24 * 3600}; includeSubDomains; preload`);
    res.setHeader('X-CDN-Loop', 'PostalDNS');

    if (/PostalDNS/.test(req.headers['x-cdn-loop'])) {
        throw new Error('CDN loop detected');
    }

    const url = new URL(req.url, `${req.proto}://${domain}/`);
    const route = url.pathname;

    const target =
        records &&
        records.find(rr => {
            return rr && rr.type === 'URL' && rr.value && rr.value.length;
        });

    if (target) {
        // redirect to target URL
        res.statusCode = target.value[1] || 301;
        res.setHeader('Content-Type', 'text/html');

        let redirectUrl = target.value[0];
        let rUrl = new URL(redirectUrl);

        let proxy = target.value[2];
        if (proxy) {
            // proxy request instead of redirecting

            logger.info({ msg: 'Proxying URL record', url: url.href, target: rUrl.origin });

            console.log('PREPROCESS');
            console.log(req.url);

            const headers = Object.assign({}, req.headers);

            // remove http2 pseudo headers from request object
            // otherwise node.http tries to add these to the proxied request
            Object.keys(headers).forEach(key => {
                if (key.charAt(0) !== ':') {
                    return;
                }

                console.log(key, headers[key]);

                switch (key) {
                    case ':path':
                        if (headers[key]) {
                            let url = headers[key];
                            delete headers[key];
                            req.url = url;
                            return;
                        }
                        break;
                    case ':method':
                        if (req.headers[key]) {
                            let method = headers[key];
                            delete headers[key];
                            req.method = method;
                        }
                        break;
                    case ':authority':
                        if (req.headers[key]) {
                            let host = headers[key];
                            delete headers[key];
                            headers.host = host;
                        }
                        break;
                }

                delete headers[key];
            });

            req.headers = headers;

            console.log('PROXYING');
            console.log(req.url);
            console.log(req.headers);

            return proxyServer.web(req, res, {
                target: rUrl.origin,
                changeOrigin: true,
                xfwd: true,
                secure: false,
                prependPath: true,
                hostRewrite: true,
                autoRewrite: true
            });
        }

        // If target url as only root path set, then treat as alias,
        // otherwise redirect to provided URL
        if (rUrl.pathname === '/' && !rUrl.search) {
            rUrl.pathname = url.pathname;
            rUrl.search = url.search;
            redirectUrl = rUrl.toString();
        }

        res.setHeader('Location', redirectUrl);

        logger.info({ msg: 'Redirect URL record', url: url.href, redirectUrl, code: res.statusCode });

        return res.end(movedTemplate);
    }

    logger.trace({ msg: 'Page not found', url: url.href });

    res.statusCode = 404;
    res.setHeader('Content-Type', 'text/html');
    return res.send(
        errors.error404({
            domain,
            route
        })
    );
};

const setupHttps = () => {
    return new Promise((resolve, reject) => {
        const server = http2.createSecureServer(
            {
                key: defaultKey,
                cert: defaultCert,
                dhparam,
                sessionIdContext,
                allowHTTP1: true,
                SNICallback(servername, cb) {
                    getSNIContext(servername)
                        .then(ctx => {
                            return cb(null, ctx || defaultCtx);
                        })
                        .catch(err => {
                            logger.error({ msg: 'SNI failed', servername, err });
                            return cb(null, defaultCtx);
                        });
                }
            },
            (req, res) => {
                req.proto = 'https';
                middleware(req, res);
                handler(req, res).catch(err => {
                    res.statusCode = 500;
                    res.setHeader('Content-Type', 'text/html');

                    const hostname = getHostname(req).replace(/^www\./, '');

                    logger.error({ msg: 'Failed to serve redirect page', err, hostname });

                    const url = new URL(req.url, `https://${hostname}/`);
                    const route = url.pathname;

                    res.send(
                        errors.error500({
                            domain: hostname,
                            route
                        })
                    );
                });
            }
        );

        server.on('newSession', (id, data, cb) => {
            const sessionKey = `d:tls:${id.toString('hex')}`;
            db.redisWrite
                .multi()
                .set(sessionKey, data)
                .expire(sessionKey, 30 * 60)
                .exec()
                .then(() => {
                    cb();
                })
                .catch(err => {
                    logger.error({ msg: 'Failed to store TLS ticket', ticket: id.toString('hex'), err });
                    cb();
                });
        });

        server.on('resumeSession', (id, cb) => {
            const sessionKey = `d:tls:${id.toString('hex')}`;
            db.redisRead
                .multi()
                .getBuffer(sessionKey)
                // extend ticket
                .expire(sessionKey, 300)
                .exec()
                .then(result => {
                    cb(null, (result && result[0] && result[0][1]) || null);
                })
                .catch(err => {
                    logger.error({ msg: 'Failed to retrieve TLS ticket', ticket: id.toString('hex'), err });
                    cb(null);
                });
        });

        server.listen(config.public.https.port, config.public.https.host, () => {
            logger.info({ msg: 'Public HTTPS server listening', protocol: 'https', host: config.public.https.host, port: config.public.https.port });
            resolve();
        });

        server.once('error', err => {
            logger.error({ msg: 'Public HTTPS server error', protocol: 'https', host: config.public.https.host, port: config.public.https.port, err });
            reject(err);
        });
    });
};

const setupHttp = () => {
    return new Promise((resolve, reject) => {
        const server = http.createServer((req, res) => {
            req.proto = 'http';
            middleware(req, res);
            handler(req, res).catch(err => {
                res.statusCode = 500;
                res.setHeader('Content-Type', 'text/html');

                const hostname = getHostname(req).replace(/^www\./, '');

                logger.error({ msg: 'Failed to serve redirect page', err, hostname });

                const url = new URL(req.url, `https://${hostname}/`);
                const route = url.pathname;

                res.send(
                    errors.error500({
                        domain: hostname,
                        route
                    })
                );
            });
        });

        server.listen(config.public.http.port, config.public.http.host, () => {
            logger.info({ msg: 'Public HTTP server listening', protocol: 'http', host: config.public.http.host, port: config.public.http.port });
            resolve();
        });

        server.once('error', err => {
            logger.error({ msg: 'Public HTTP server error', protocol: 'http', host: config.public.http.host, port: config.public.http.port, err });
            reject(err);
        });
    });
};

const init = async () => {
    await Promise.all([setupHttps(), setupHttp()]);
};

module.exports = init;
