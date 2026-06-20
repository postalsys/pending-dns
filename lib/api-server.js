'use strict';

const config = require('wild-config');
const Hapi = require('@hapi/hapi');
const Boom = require('@hapi/boom');
const hapiPino = require('hapi-pino');
const Inert = require('@hapi/inert');
const Vision = require('@hapi/vision');
const HapiSwagger = require('hapi-swagger');
const packageData = require('../package.json');
const Joi = require('joi');
const logger = require('./logger').child({ component: 'api-server' });
const { zoneStore, allowedTypes, allowedTags, tlsaToValue, isEvenHex } = require('./zone-store');
const { getCertificate } = require('./certs');
const dnssec = require('./dnssec');

// Normalize a thrown error into a Boom response: pass Boom errors through,
// otherwise wrap while preserving any statusCode and decorating with err.code.
const toBoom = err => (Boom.isBoom(err) ? err : Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } }));

const hostnameSchema = Joi.string().hostname({
    allowUnicode: true,
    minDomainSegments: 1
});

const subdomainValidator = opts => (value, helpers) => {
    if (!value) {
        return value;
    }

    let valueToCheck = value;
    if (opts.allowUnderscore) {
        valueToCheck = valueToCheck.replace(/\b_/g, 'x');
    }

    if (opts.allowWildcard) {
        valueToCheck = valueToCheck.replace(/^\*\./, 'x.');
    }

    let result = hostnameSchema.validate(valueToCheck);
    if (result.error) {
        return helpers.error('any.invalid');
    }

    return value;
};

// All TLSA-specific fields share the same conditional shape: required when the
// record type is TLSA, forbidden otherwise. Keep the wrapper in one place so the
// four fields cannot drift apart.
const tlsaField = (inner, { example, description, label }) =>
    Joi.any()
        .example(example)
        .when('type', {
            is: 'TLSA',
            then: inner.required(),
            otherwise: Joi.any().forbidden()
        })
        .description(description)
        .label(label);

const recordScheme = Joi.object({
    subdomain: Joi.string()
        .replace(/[\s.@]+$/gi, '')
        .allow('')
        .default('')
        .when('type', {
            switch: [
                {
                    is: 'CNAME',
                    then: Joi.custom(
                        subdomainValidator({
                            allowUnderscore: true,
                            allowWildcard: true
                        }),
                        'subdomain validation'
                    )
                },
                {
                    is: 'TXT',
                    then: Joi.custom(
                        subdomainValidator({
                            allowUnderscore: true,
                            allowWildcard: true
                        }),
                        'subdomain validation'
                    )
                },
                {
                    is: 'TLSA',
                    then: Joi.custom(
                        subdomainValidator({
                            allowUnderscore: true,
                            allowWildcard: false
                        }),
                        'subdomain validation'
                    )
                }
            ],
            otherwise: Joi.custom(
                subdomainValidator({
                    allowUnderscore: false,
                    allowWildcard: true
                }),
                'subdomain validation'
            )
        })
        .example('www')
        .description('Subdomain for zone')
        .label('Subdomain'),

    type: Joi.string()
        .trim()
        .uppercase()
        .valid(...allowedTypes)
        .required()
        .example('A')
        .description('Record type')
        .label('RecordType'),

    address: Joi.any()
        .example('1.2.3.4')
        .when('type', {
            is: 'A',
            then: Joi.string()
                .ip({
                    version: ['ipv4'],
                    cidr: 'forbidden'
                })
                .required()
        })
        .when('type', {
            is: 'AAAA',
            then: Joi.string()
                .ip({
                    version: ['ipv6'],
                    cidr: 'forbidden'
                })
                .required()
        })
        .description('Address for A/AAAA')
        .label('Address'),

    healthCheck: Joi.any()
        .example('tcps://127.0.0.1:8080')
        .when('type', {
            is: 'A',
            then: Joi.string()
                .empty('')
                .allow(false)
                .uri({
                    scheme: ['http', 'https', 'tcp', 'tcps'],
                    allowRelative: false,
                    allowQuerySquareBrackets: false
                })
                .default(false)
                .optional()
        })
        .when('type', {
            is: 'AAAA',
            then: Joi.string()
                .empty('')
                .allow(false)
                .uri({
                    scheme: ['http', 'https', 'tcp', 'tcps'],
                    allowRelative: false,
                    allowQuerySquareBrackets: false
                })
                .default(false)
                .optional()
        })
        .description('Health check URI for A/AAAA')
        .label('HealthCheck'),

    target: Joi.any()
        .example('example.com')
        .when('type', {
            is: 'ANAME',
            then: Joi.string().domain().required()
        })
        .when('type', {
            is: 'CNAME',
            then: Joi.string()
                .allow('@')
                .custom(
                    subdomainValidator({
                        allowUnderscore: true,
                        allowWildcard: false
                    }),
                    'subdomain validation'
                )
                .required()
        })
        .description('Target domain for CNAME/ANAME')
        .label('Target'),

    exchange: Joi.any()
        .example('mx.example.com')
        .when('type', {
            is: 'MX',
            then: Joi.string().allow('@').domain().required()
        })
        .description('Mail exchage server for MX')
        .label('Exchange'),

    priority: Joi.any()
        .example(20)
        .when('type', {
            is: 'MX',
            then: Joi.number().min(1).max(255).required()
        })
        .description('Mail exchage priority for MX')
        .label('Priority'),

    value: Joi.any()
        .example('letsencrypt.org')
        .when('type', {
            is: 'CAA',
            then: Joi.string().domain().required()
        })
        .description('Certificate authority domain for CAA')
        .label('CADomain'),

    tag: Joi.any()
        .example('issue')
        .when('type', {
            is: 'CAA',
            then: Joi.string()
                .valid(...allowedTags)
                .required()
        })
        .description('Certificate authority tag for CAA')
        .label('Tag'),

    flags: Joi.any()
        .example(0)
        .when('type', {
            is: 'CAA',
            then: Joi.number().integer().min(0).max(255).default(0)
        })
        .description('Certificate authority flags for CAA')
        .label('Flags'),

    ns: Joi.any()
        .example('ns01.pendingdns.com')
        .when('type', {
            is: 'NS',
            then: Joi.string().domain().required()
        })
        .description('Name server')
        .label('NSDomain'),

    data: Joi.any()
        .example('v=spf1 include:_spf.google.com ~all')
        .when('type', {
            is: 'TXT',
            then: Joi.string().max(512).required()
        })
        .description('Data for TXT record')
        .label('TXTData'),

    usage: tlsaField(Joi.number().integer().min(0).max(3), {
        example: 3,
        description: 'Certificate usage for TLSA (0 PKIX-TA, 1 PKIX-EE, 2 DANE-TA, 3 DANE-EE)',
        label: 'TLSAUsage'
    }),

    selector: tlsaField(Joi.number().integer().min(0).max(1), {
        example: 1,
        description: 'Selector for TLSA (0 full certificate, 1 SubjectPublicKeyInfo)',
        label: 'TLSASelector'
    }),

    matchingType: tlsaField(Joi.number().integer().min(0).max(2), {
        example: 1,
        description: 'Matching type for TLSA (0 full, 1 SHA-256, 2 SHA-512)',
        label: 'TLSAMatchingType'
    }),

    certificate: tlsaField(
        Joi.string()
            .hex()
            .lowercase()
            .custom((value, helpers) => (isEvenHex(value) ? value : helpers.error('any.invalid')), 'even-length hex'),
        {
            example: '92003ba34942dc74152e2f2c408d29eca5a520e7f2e06bb944f4dca346baf63c',
            description: 'Certificate association data for TLSA (hex)',
            label: 'TLSACertificate'
        }
    ),

    url: Joi.any()
        .example('https://postalsys.com/')
        .when('type', {
            is: 'URL',
            then: Joi.string()
                .uri({
                    scheme: ['http', 'https'],
                    allowRelative: false,
                    allowQuerySquareBrackets: false
                })
                .required()
        })
        .description('Redirect target for URL record')
        .label('URLData'),

    proxy: Joi.any()
        .example(false)
        .when('type', {
            is: 'URL',
            then: Joi.boolean().default(false)
        })
        .description('If true then proxy requests instead of redirecting')
        .label('URLProxy'),

    code: Joi.any()
        .example(301)
        .when('type', {
            is: 'URL',
            then: Joi.number().empty('').valid(301, 302, 303, 307, 308).default(301)
        })
        .description('HTTP status code for URL record')
        .label('HTTPCode')
}).label('RecordData');

const failAction = async (request, h, err) => {
    let details = (err.details || []).map(detail => ({ message: detail.message, key: detail.context.key }));

    let error = Boom.boomify(new Error('Invalid input'), { statusCode: 400 });
    error.reformat();
    error.output.payload.fields = details; // Add custom key
    throw error;
};

const createServer = async () => {
    const server = Hapi.server({
        port: (process.env.API_PORT && Number(process.env.API_PORT)) || config.api.port,
        host: process.env.API_HOST || config.api.host
    });

    const swaggerOptions = {
        swaggerUI: true,
        swaggerUIPath: '/swagger/',
        documentationPage: true,
        documentationPath: '/docs',

        grouping: 'tags',

        info: {
            title: 'PendingDNS',
            version: packageData.version,
            contact: {
                name: 'Andris Reinman',
                email: 'andris@postalsys.com'
            }
        }
    };

    await server.register({
        plugin: hapiPino,
        options: {
            instance: logger.child({ component: 'api' }),
            // Redact Authorization headers, see https://getpino.io/#/docs/redaction
            redact: ['req.headers.authorization']
        }
    });

    await server.register([
        Inert,
        Vision,
        {
            plugin: HapiSwagger,
            options: swaggerOptions
        }
    ]);

    server.route({
        method: 'GET',
        path: '/v1/zone/{zone}/records',

        async handler(request) {
            try {
                let records = await zoneStore.list(request.params.zone);
                if (records && records.length) {
                    records = records.map(record => zoneStore.formatValue(record));

                    records.push(
                        Object.assign(
                            {
                                id: null,
                                type: 'SOA'
                            },
                            config.soa
                        )
                    );

                    config.ns.forEach(ns => {
                        records.push({
                            id: null,
                            type: 'NS',
                            ns: ns.domain,
                            address: ns.ip
                        });
                    });
                }
                return { zone: request.params.zone, records };
            } catch (err) {
                throw toBoom(err);
            }
        },

        options: {
            description: 'List zone entries',
            notes: 'Lists all records of a zone',
            tags: ['api', 'zone'],

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    zone: Joi.string().hostname().required().example('example.com').description('Zone domain').label('ZoneDomain')
                }).label('Zone')
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/zone/{zone}/records',

        async handler(request) {
            try {
                let value;
                switch (request.payload.type) {
                    case 'A':
                    case 'AAAA':
                        value = [request.payload.address, request.payload.healthCheck];
                        break;
                    case 'ANAME':
                    case 'CNAME':
                        value = [request.payload.target];
                        break;
                    case 'MX':
                        value = [request.payload.exchange, request.payload.priority];
                        break;
                    case 'CAA':
                        value = [request.payload.value, request.payload.tag, request.payload.flags];
                        break;
                    case 'NS':
                        value = [request.payload.ns];
                        break;
                    case 'TXT':
                        value = [request.payload.data];
                        break;
                    case 'TLSA':
                        value = tlsaToValue(request.payload);
                        break;
                    case 'URL':
                        value = [request.payload.url, request.payload.code, request.payload.proxy];
                        break;
                    default:
                        throw new Error('Unknown type');
                }

                let record = await zoneStore.add(request.params.zone, request.payload.subdomain, request.payload.type, value);
                return {
                    zone: request.params.zone,
                    record
                };
            } catch (err) {
                throw toBoom(err);
            }
        },

        options: {
            description: 'Create new Resource Record',
            notes: 'Add new  Resource Record to selected zone',
            tags: ['api', 'zone'],

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    zone: Joi.string().hostname().required().example('example.com').description('Zone domain').label('ZoneDomain')
                }).label('Zone'),

                payload: recordScheme
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/zone/{zone}/records/{record}',

        async handler(request) {
            try {
                let value;
                switch (request.payload.type) {
                    case 'A':
                    case 'AAAA':
                        value = [request.payload.address, request.payload.healthCheck];
                        break;
                    case 'ANAME':
                    case 'CNAME':
                        value = [request.payload.target];
                        break;
                    case 'MX':
                        value = [request.payload.exchange, request.payload.priority];
                        break;
                    case 'CAA':
                        value = [request.payload.value, request.payload.tag, request.payload.flags];
                        break;
                    case 'NS':
                        value = [request.payload.ns];
                        break;
                    case 'TXT':
                        value = [request.payload.data];
                        break;
                    case 'TLSA':
                        value = tlsaToValue(request.payload);
                        break;
                    case 'URL':
                        value = [request.payload.url, request.payload.code, request.payload.proxy];
                        break;
                    default:
                        throw new Error('Unknown type');
                }

                let record = await zoneStore.update(request.params.zone, request.params.record, request.payload.subdomain, request.payload.type, value);
                return { zone: request.params.zone, record };
            } catch (err) {
                throw toBoom(err);
            }
        },

        options: {
            description: 'Update existing Resource Record',
            notes: 'Update Resource Record in selected zone',
            tags: ['api', 'zone'],

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    zone: Joi.string().hostname().required().example('example.com').description('Zone domain').label('ZoneDomain'),
                    record: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(256)
                        .example('ZWUub3NrYXIBTVgBTjA3eW5PSHQ4')
                        .required()
                        .description('Record ID')
                }).label('Zone'),

                payload: recordScheme
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/zone/{zone}/records/{record}',

        async handler(request) {
            try {
                let deleted = await zoneStore.del(request.params.zone, request.params.record);
                return { zone: request.params.zone, record: request.params.record, deleted };
            } catch (err) {
                throw toBoom(err);
            }
        },
        options: {
            description: 'Delete record from zone',
            notes: 'Delete record from zone by ID',
            tags: ['api', 'zone'],

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    zone: Joi.string().hostname().required().example('example.com').description('Zone domain').label('ZoneDomain'),
                    record: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(256)
                        .example('ZWUub3NrYXIBTVgBTjA3eW5PSHQ4')
                        .required()
                        .description('Record ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/acme',

        async handler(request) {
            try {
                let cert = await getCertificate(request.payload.domains);
                if (cert.cert) {
                    return {
                        dnsNames: cert.dnsNames,
                        key: cert.key,
                        cert: [].concat(cert.cert).concat(cert.chain).join('\n\n').replace(/\n\n+/g, '\n\n'),
                        validFrom: cert.validFrom,
                        expires: cert.expires
                    };
                } else {
                    throw new Error('Missing certificate data');
                }
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }

                let error = Boom.boomify(new Error('Failed to acquire certificate'), { statusCode: 400 });
                error.reformat();

                if (err.code === 'ENODATA') {
                    error.output.payload.message = 'Failed to perform DNS queries, check name server configuration';
                } else {
                    error.output.payload.message = err.message;
                }

                if (err.code) {
                    error.output.payload.code = err.code;
                }

                throw error;
            }
        },

        options: {
            description: 'Generate certificate',
            notes: 'Generate certificate for listed domains',
            tags: ['api', 'acme'],

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object({
                    domains: Joi.array()
                        .items(
                            Joi.string().custom(
                                subdomainValidator({
                                    allowUnderscore: false,
                                    allowWildcard: true
                                }),
                                'subdomain validation'
                            )
                        )
                        .min(1)
                        .required()
                        .example(['example.com', '*.example.com'])
                        .description('List of domains to generate certificate for')
                        .label('DomainList')
                }).label('Acme')
            }
        }
    });

    const zoneParam = Joi.object({
        zone: Joi.string().hostname().required().example('example.com').description('Zone domain').label('ZoneDomain')
    }).label('Zone');

    server.route({
        method: 'GET',
        path: '/v1/zone/{zone}/dnssec',

        async handler(request) {
            try {
                return await dnssec.getZoneStatus(request.params.zone);
            } catch (err) {
                throw toBoom(err);
            }
        },

        options: {
            description: 'Get DNSSEC status',
            notes: 'Returns DNSSEC state, DS and DNSKEY records for a zone',
            tags: ['api', 'dnssec'],
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
                failAction,
                params: zoneParam
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/zone/{zone}/dnssec',

        async handler(request) {
            try {
                return await dnssec.enableZone(request.params.zone, { algorithm: request.payload && request.payload.algorithm });
            } catch (err) {
                throw toBoom(err);
            }
        },

        options: {
            description: 'Enable DNSSEC',
            notes: 'Enables DNSSEC for a zone, generating a signing key on first call. Returns DS records to set at the registrar.',
            tags: ['api', 'dnssec'],
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
                failAction,
                params: zoneParam,
                payload: Joi.object({
                    algorithm: Joi.number()
                        .valid(8, 13, 15)
                        .example(13)
                        .description('DNSSEC algorithm (8 RSASHA256, 13 ECDSAP256SHA256, 15 ED25519)')
                        .label('DnssecAlgorithm')
                })
                    .allow(null)
                    .label('DnssecOptions')
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/zone/{zone}/dnssec',

        async handler(request) {
            try {
                let disabled = await dnssec.disableZone(request.params.zone);
                return { zone: request.params.zone, disabled };
            } catch (err) {
                throw toBoom(err);
            }
        },

        options: {
            description: 'Disable DNSSEC',
            notes: 'Disables DNSSEC signing for a zone',
            tags: ['api', 'dnssec'],
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
                failAction,
                params: zoneParam
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/zone/{zone}/dnssec/key/{keyTag}',

        async handler(request) {
            try {
                let removed = await dnssec.removeKey(request.params.zone, request.params.keyTag);
                return { zone: request.params.zone, keyTag: request.params.keyTag, removed };
            } catch (err) {
                throw toBoom(err);
            }
        },

        options: {
            description: 'Remove a DNSSEC key',
            notes: 'Removes a non-active signing key from a zone, e.g. to finish an algorithm rollover after publishing the new DS. Refuses to remove the active or last key.',
            tags: ['api', 'dnssec'],
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
                failAction,
                params: zoneParam
                    .keys({
                        keyTag: Joi.number().integer().min(0).max(65535).required().example(48234).description('Key tag of the key to remove').label('KeyTag')
                    })
                    .label('ZoneKey')
            }
        }
    });

    server.route({
        method: '*',
        path: '/{any*}',
        async handler() {
            throw Boom.notFound('Requested page not found'); // 404
        }
    });

    return server;
};

const init = async () => {
    const server = await createServer();
    await server.start();
    return server;
};

module.exports = init;
module.exports.createServer = createServer;
