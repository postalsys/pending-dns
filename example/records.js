'use strict';

const logger = require('../lib/logger');
const { zoneStore } = require('../lib/zone-store');

let main = async () => {
    let createEntries = [
        ['neti.ee', false, 'A', ['1.2.3.4']],
        ['neti.ee', 'xxx', 'A', '1.2.3.6'],
        ['neti.ee', false, 'A', ['1.2.3.5']],
        ['neti.ee', 'www', 'CNAME', ['neti.ee']],
        ['neti.ee', 'jõgeva', 'CNAME', ['jõgeva.ee']],
        ['neti.ee', '*.test', 'CNAME', ['neti.ee']],
        ['neti.ee', 'test', 'CNAME', ['neti.ee']],
        ['neti.ee', 'peeter', 'ANAME', ['github.io']],

        ['neti.ee', '', 'MX', ['mx1.neti.ee', 100]],
        ['neti.ee', '', 'MX', ['mx2.neti.ee', 1]],

        ['neti.ee', 'peeter', 'NS', ['ns01.pendingdns.com']],
        ['neti.ee', 'peeter', 'NS', ['ns02.pendingdns.com']],
        ['neti.ee', '', 'CAA', ['letsencrypt.org', 'issuewild', 0]],
        ['neti.ee', 'delfi.test', 'CNAME', ['delfi.neti.ee']],
        [
            'neti.ee',
            '01._domainkey',
            'TXT',
            [
                'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsD6Th73ZDKkFAntNZDbxEh8VV2DSMs3re6v9/gXoT3dGcbSsuUMpfLzP5MWp4sW5cPyZxEGSiC03ZVIcCca0GRAuX9b1M0Qy25wLmPq8eT129mhwbeX50xTaXqq63A/oDM0QOPe1IeBMfPnR9tWXxvEzZKvVbmTlMY5bf+3QHLqmaEihnGlXh2LRVZbe2EMlYo18YM4LU/LkZKe06rxlq38W22TL7964tr7jmOZ+huXf2iLSg4nc4UzLwb2aOdOA+w4c87h+HW/L80548pFguF46TKc0C0egZ+oll3Y8zySYrbkVrWFrcpnrw5qDiRVHEjxqZSubSYX+16TjNcJg9QIDAQAB'
            ]
        ]
    ];
    for (let [zone, subdomain, type, value] of createEntries) {
        let id = await zoneStore.add(zone, subdomain, type, value);
        logger.info({ msg: 'Create record', zone, subdomain, type, value, id });
    }

    let list = await zoneStore.list('neti.ee');
    logger.info({ msg: 'Full list', list });

    let reqs = [
        ['neti.ee', 'A'],
        ['o1._domainkey.neti.ee', 'TXT'],
        ['www.neti.ee', 'CNAME'],
        ['www.neti.ee', 'CNAME', true],
        ['supikas.test.neti.ee', 'CNAME'],
        ['supikas.test.neti.ee', 'CNAME', true],
        ['jupikas.supikas.test.neti.ee', 'CNAME'],
        ['delfi.test.neti.ee', 'CNAME'],
        ['delfi.test.neti.ee', 'CNAME', true],
        ['supikas.neti.ee', 'CNAME'],
        ['supikas.neti.ee', 'CNAME', true]
    ];
    for (let [domain, type, short] of reqs) {
        let record = await zoneStore.resolve(domain, type, short);
        logger.info({ msg: 'query', domain, type, short, record });
    }

    let zone = await zoneStore.resolveDomainZone('supikas.neti.ee');
    logger.info({ msg: 'Resolve zone', domain: 'supikas.neti.ee', zone });

    for (let entry of list) {
        //let deleted = await zoneStore.del(entry.id);
        let deleted = await zoneStore.deleteDomain(entry.domain, entry.type);
        logger.info({ msg: 'Delete', key: entry.id, domain: entry.domain, type: entry.type, deleted });
    }

    list = await zoneStore.list('neti.ee');
    logger.info({ msg: 'List should be empty', list });
};

main()
    .then(() => {
        console.log('DONE');
        setImmediate(() => process.exit());
    })
    .catch(err => {
        console.error(err);
        setImmediate(() => process.exit(1));
    });
