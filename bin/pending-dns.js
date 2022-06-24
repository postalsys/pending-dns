#!/usr/bin/env node
/* eslint global-require: 0 */
'use strict';

const packageData = require('../package.json');
const fs = require('fs');
const pathlib = require('path');
const argv = require('minimist')(process.argv.slice(2));

function run() {
    let cmd = ((argv._ && argv._[0]) || '').toLowerCase();
    if (!cmd) {
        if (argv.version || argv.v) {
            cmd = 'version';
        }

        if (argv.help || argv.h) {
            cmd = 'help';
        }
    }

    switch (cmd) {
        case 'help':
            // Show version
            fs.readFile(pathlib.join(__dirname, '..', 'help.txt'), (err, helpText) => {
                if (err) {
                    console.error('Failed to load help information');
                    console.error(err);
                    return process.exit(1);
                }
                console.error(helpText.toString().trim());
                console.error('');
                process.exit();
            });
            break;

        case 'version':
            // Show version
            console.log(`EmailEngine v${packageData.version} (${packageData.license})`);
            return process.exit();

        default:
            // run normally
            require('../server');
            break;
    }
}

run();
