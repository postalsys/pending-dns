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
const logger = require('./logger');
const { zoneStore } = require('./zone-store');

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
        path: '/v1/zone/{zone}',

        async handler(request) {
            try {
                let list = await zoneStore.list(request.params.zone);
                return { zone: request.params.zone, list };
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
                    zone: Joi.string().hostname().required().example('example.com').description('Zone domain').label('Zone')
                }).label('ZoneFilter')
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
