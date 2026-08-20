# Changelog

## [1.4.2](https://github.com/postalsys/pending-dns/compare/v1.4.1...v1.4.2) (2026-08-20)


### Bug Fixes

* keep the Redis password out of the log ([44a4399](https://github.com/postalsys/pending-dns/commit/44a4399e41c8cc08b6b5c71c558fd2394864c71a))
* refresh TLS session tickets on the write client ([1920ceb](https://github.com/postalsys/pending-dns/commit/1920ceb193dd5d3b8d9b898a0c6c18dc8d00c13b))
* stop buffering TCP DNS input after a query is handed off ([ce64999](https://github.com/postalsys/pending-dns/commit/ce649999e9c9f046053c91b78a4dd35d3814bb27))
* survive a Redis outage instead of wedging every worker ([a1d33b6](https://github.com/postalsys/pending-dns/commit/a1d33b6d0d7d19d04957bbdf0a729100c81b137a))

## [1.4.1](https://github.com/postalsys/pending-dns/compare/v1.4.0...v1.4.1) (2026-06-20)


### Bug Fixes

* trigger standalone pkg build rebuild ([6484e02](https://github.com/postalsys/pending-dns/commit/6484e027edf7cb890e61379e677eba71561f09d6))

## [1.4.0](https://github.com/postalsys/pending-dns/compare/v1.3.0...v1.4.0) (2026-06-20)


### Features

* add DNSSEC online signing, TLSA records, and EDNS UDP truncation ([414beb7](https://github.com/postalsys/pending-dns/commit/414beb7114d56f35e2d02e945abfb4125ee51404))
* replace Bugsnag with self-hosted Sentry error reporting ([3b374c7](https://github.com/postalsys/pending-dns/commit/3b374c737ff0a22509f79976bee18ab9d425f8bd))

## [1.3.0](https://github.com/postalsys/pending-dns/compare/pending-dns-v1.2.5...pending-dns-v1.3.0) (2026-06-18)


### Features

* replace Bugsnag with self-hosted Sentry error reporting ([3b374c7](https://github.com/postalsys/pending-dns/commit/3b374c737ff0a22509f79976bee18ab9d425f8bd))
