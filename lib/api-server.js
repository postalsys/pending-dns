'use strict';

const config = require('wild-config');
const Hapi = require('@hapi/hapi');
const Boom = require('@hapi/boom');
const hapiPino = require('hapi-pino');
const Inert = require('@hapi/inert');
const Vision = require('@hapi/vision');
const HapiSwagger = require('hapi-swagger');
const packageData = require('../package.json');
const Joi = require('@hapi/joi');
const logger = require('./logger').child({ component: 'api-server' });
const { zoneStore, allowedTypes, allowedTags } = require('./zone-store');
const { renewCertificate } = require('./certs');

const failAction = async (request, h, err) => {
    let details = (err.details || []).map(detail => ({ message: detail.message, key: detail.context.key }));

    let error = Boom.boomify(new Error('Invalid input'), { statusCode: 400 });
    error.reformat();
    error.output.payload.fields = details; // Add custom key
    throw error;
};

const init = async () => {
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
            title: 'Postal DNS',
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
                }
                return { zone: request.params.zone, records };
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
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
                        value = [request.payload.address];
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
                    default:
                        throw new Error('Unknown type');
                }

                let record = await zoneStore.add(request.params.zone, request.payload.subdomain, request.payload.type, value);
                return {
                    zone: request.params.zone,
                    record
                };
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
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

                payload: Joi.object({
                    subdomain: Joi.string().hostname().allow('').default('').example('www').description('Subdomain for zone').label('Subdomain'),

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

                    target: Joi.any()
                        .example('example.com')
                        .when('type', {
                            is: 'ANAME',
                            then: Joi.string().domain().required()
                        })
                        .when('type', {
                            is: 'CNAME',
                            then: Joi.string().allow('@').domain().required()
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
                            then: Joi.string().valid(0).default(0)
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
                        .label('TXTData')
                }).label('RecordData')
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
                        value = [request.payload.address];
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
                    default:
                        throw new Error('Unknown type');
                }

                let updated = await zoneStore.update(request.params.zone, request.params.record, request.payload.subdomain, request.payload.type, value);
                return { zone: request.params.zone, updated };
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
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

                payload: Joi.object({
                    subdomain: Joi.string().hostname().allow('').default('').example('www').description('Subdomain for zone').label('Subdomain'),

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

                    target: Joi.any()
                        .example('example.com')
                        .when('type', {
                            is: 'ANAME',
                            then: Joi.string().domain().required()
                        })
                        .when('type', {
                            is: 'CNAME',
                            then: Joi.string().allow('@').domain().required()
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

                    tags: Joi.any()
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
                            then: Joi.string().valid(0).default(0)
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
                        .label('TXTData')
                }).label('RecordData')
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
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
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
                let cert = await renewCertificate(request.payload.domains);
                return { cert };
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },

        options: {
            description: 'Generate certificates',
            notes: 'Generate certificates for listed domains. Each domain must be in a zone with at least 1 record.',
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
                        .items(Joi.string().domain())
                        .min(1)
                        .required()
                        .description('List of domains to generate certificate for')
                        .label('DomainList')
                }).label('Acme')
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

    await server.start();
};

init().catch(err => {
    throw err;
});
