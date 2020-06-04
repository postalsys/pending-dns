'use strict';

const config = require('wild-config');
const Redis = require('ioredis');
const fs = require('fs');
const pathlib = require('path');

const healthScript = fs.readFileSync(pathlib.join(__dirname, 'lua', 'health.lua'), 'utf-8');

module.exports.redisRead = new Redis(config.dbs.redisRead || config.dbs.redis);
module.exports.redisWrite = new Redis(config.dbs.redisWrite || config.dbs.redis);

module.exports.redisWrite.defineCommand('nextHealth', {
    numberOfKeys: 1,
    lua: healthScript
});
