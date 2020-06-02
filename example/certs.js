'use strict';

const { getCertificate } = require('../lib/certs');
const { zoneStore } = require('../lib/zone-store');

async function main() {
    let list = await zoneStore.list('mailtanker.com');
    if (!list.length) {
        await zoneStore.add('mailtanker.com', '', 'A', '127.0.0.1');
    }

    let cert = await getCertificate(['mailtanker.com', '*.mailtanker.com']);

    console.log(cert);
}

main()
    .then(() => {
        console.log('DONE');
        setImmediate(() => process.exit());
    })
    .catch(err => {
        console.error(err);
        setImmediate(() => process.exit(1));
    });
