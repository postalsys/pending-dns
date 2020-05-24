'use strict';

const config = require('wild-config');
const Redis = require('ioredis');

module.exports.redisRead = new Redis(config.dbs.redisRead || config.dbs.redis);
module.exports.redisWrite = new Redis(config.dbs.redisWrite || config.dbs.redis);
