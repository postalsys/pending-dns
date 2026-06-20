# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

PendingDNS is a lightweight, API-driven **authoritative** DNS server (UDP + TCP), bundled with a REST API for managing zone records, a public HTTP/HTTPS redirect/proxy server, automatic Let's Encrypt certificate generation, and periodic health checks. All state lives in Redis.

## Commands

```bash
npm start          # run the whole app (node server.js)
npm test           # run the test suite (requires a local Redis on 127.0.0.1:6379)
npm run lint       # ESLint 9 (flat config: eslint.config.js)
npm run licenses   # regenerate licenses.txt (license-report)
```

Running the app or tests requires a reachable Redis and a config with a valid `acme.email` (the bootstrap in `server.js` exits otherwise). For local runs, either set it in `config/development.toml` or pass `--acme.email=you@example.com`.

### Tests

- Built on the Node.js built-in test runner (`node:test`). `npm test` runs `NODE_ENV=test node --test --test-force-exit --test-concurrency=1 test/*.test.js`.
- `NODE_ENV=test` loads `config/test.toml`, which points Redis at a **dedicated database (db 15)**. `test/helpers.js#flushTestDb` wipes db 15 between cases and **refuses to run unless the Redis URL ends in `/15`** — so tests never touch dev (db 2) or prod data. Always run tests with `NODE_ENV=test`.
- `--test-concurrency=1` is required because all test files share db 15. `--test-force-exit` is required because requiring `lib/db` opens persistent ioredis connections; every test file must also call `closeDb()` in an `after()` hook or the process hangs.
- Some `cached-resolver`/`dns-server` tests do real DNS lookups (e.g. `one.one.one.one`); they are written to skip or tolerate missing network.

Run a single file or filter by test name:

```bash
NODE_ENV=test node --test --test-force-exit test/zone-store.test.js
NODE_ENV=test node --test --test-force-exit --test-name-pattern="wildcard" test/*.test.js
```

### Building standalone executables

Executables are built with `@yao-pkg/pkg` (the maintained `pkg` fork) via the `pkg` block in `package.json`, targeting node24. The org-wide `../emailengine-api/upload.sh <repo>` script installs `@yao-pkg/pkg` globally, then runs `npm run build-source` followed by `npm run build-dist` (or `build-dist-fast` for an unsigned test build) and signs/notarizes/uploads the artifacts. Output binaries are named `pending-dns-<target>` under `ee-dist/`.

Because workers are loaded through **dynamic `require()` / `worker_threads`** (see below), `pkg.scripts` must list `lib/**/*.js` and `workers/**/*.js` or the worker code is missing from the snapshot. Runtime files read via `__dirname` (`lib/lua/health.lua`, `config/*.pem`) must be in `pkg.assets`. Do **not** add `pkg.options` like `max_old_space_size`: the workers forward `argv`, and an injected V8 flag leaks in as a bogus module path and crashes every worker.

## Architecture

### Process model (the most important thing to understand)

`server.js` is the supervisor. For each enabled subsystem (`api`, `dns`, `public`, `health`) it spawns a **worker thread** running `workers/<type>.js`, and restarts it on exit. Each `workers/<type>.js` is itself a small bootstrap that:

1. installs crash handlers + optional Sentry error reporting via `lib/sentry.js#initSentry` (only when `SENTRY_DSN` / `[sentry] dsn` is set; uses Sentry's uncaught-exception / unhandled-rejection integrations so crashes are reported, then `closeProcess`'s `if (!logger.errorReportingEnabled)` lets Sentry flush+exit),
2. uses Node `cluster` to fork `config[type].workers` processes (or runs in-thread when `workers === 1` and no user/group drop is configured),
3. dynamically `require`s the implementation: ``require(`../lib/${type}-server.js`)`` (or `-worker.js` for `health`) and calls it,
4. drops privileges via `config.process.user`/`group` after ports are bound.

So `lib/<type>-server.js` are entry points reached **only through dynamic requires** — static analysis (and `pkg`) won't find them. The implementations are: `lib/api-server.js`, `lib/dns-server.js`, `lib/public-server.js`, `lib/health-worker.js`.

### Configuration (`wild-config`)

Config is loaded by `wild-config` from `config/default.toml` merged with `config/<NODE_ENV>.toml`, then overridden by CLI args (`--dns.port=53`) and `appconf_*` env vars. `NODE_CONFIG_PATH` points to an external file in production (see `systemd/pending-dns.service`). Values are coerced to the type of the default (a string env var for a numeric default becomes a number). Config is read from `process.cwd()/config`, **not** from `__dirname` — relevant for packaged binaries, which need a `config/` directory next to them.

### Redis data model (`lib/zone-store.js`)

This is the heart of the system and is non-obvious:

- **Domain names are stored label-reversed**: `www.example.com` → `com.example.www` (`domainToName`/`nameToDomain`). This lets `resolveZone` walk *up* from a name to its registered zone by progressively dropping the most-specific label. A "zone" is any name with a `d:<name>:z` set; the shortest possible zone is the 2-label boundary (e.g. `example.com`).
- Keys: `d:<name>:z` is a **set of record keys** belonging to that zone; `d:<name>:r:<TYPE>` is a **hash** of `hid → JSON.stringify(valueArray)`. Each record's value is a positional array whose meaning depends on type (e.g. A = `[address, healthCheckUri]`, MX = `[exchange, priority]`, CAA = `[value, tag, flags]`, TLSA = `[usage, selector, matchingType, certificate]`, URL = `[url, code, proxy]`).
- A record's public **ID is `base64url(name \x01 TYPE \x01 hid)`** (`getFullId`/`parseFullId`); `hid` is a `nanoid()`. IDs are opaque and stable only while domain+type are unchanged (an `update` that changes either deletes and re-adds, producing a new ID).
- **Wildcards** are single-label: a record stored under subdomain `*.foo` matches `anything.foo.<zone>` only (`resolve` retries with the last label replaced by `*`).
- **Read/write split**: reads go to `db.redisRead`, writes to `db.redisWrite` (configurable as separate master/replica URLs). The health-check Lua script `lib/lua/health.lua` is registered as a custom command `nextHealth` on the write client.

### DNS request handling (`lib/dns-handler.js` + custom servers)

`lib/dns-udp-server.js` and `lib/dns-tcp-server.js` are hand-rolled servers that parse/serialize with `dns2`'s `Packet` (the project does **not** use dns2's built-in server). `lib/dns-server.js` wires them to `dnsHandler` and returns the bound server handles.

`processQuestion` does more than a lookup: for an A/AAAA query it also pulls `CNAME`, `ANAME`, and `URL` records; it follows CNAME chains recursively (depth-limited); A/AAAA results are health-filtered and shuffled; MX is priority-sorted. When nothing is stored it synthesizes fallbacks — `NS` from `config.ns`, a `SOA` from `config.soa`, default Let's Encrypt `CAA` records, and `version.bind`-style CHAOS TXT answers.

Two pseudo-record types: **ANAME** (apex alias) is resolved to real A/AAAA at query time via `lib/cached-resolver.js` (a Redis-cached wrapper over Node's `dns.Resolver`, with soft/hard TTLs for both hits and errors). **URL** records answer A/AAAA with the redirect server IPs from `config.public.hosts`; the actual redirect/proxy happens in `lib/public-server.js`.

### DNSSEC online signing (`lib/dnssec.js`, `lib/dnssec-wire.js`)

DNSSEC is **online (query-time) signing**, gated on `[dnssec] enabled` AND a per-zone key AND the client's EDNS **DO** bit. `lib/dnssec-wire.js` is a pure, dependency-free (only `crypto` + `ipaddr.js`) wire/crypto layer: canonical RDATA/name encoding (RFC 4034 6.2), the `ALGS` table for algorithms 8/13/15, key-tag + DS-digest computation, NSEC bitmaps, and RRSIG encoding. **Invariant:** signatures are computed over the canonical uncompressed lowercased wire form produced here, never over dns2's serialization (validators decompress + downcase before verifying, so the two agree).

`lib/dnssec.js` owns per-zone keys and signing orchestration. Keys live in Redis: `d:dnssec:<revname>` is the state hash (`enabled`, `algorithm`, `activeKeyTag`) and `d:dnssec:<revname>:keys` is a hash of `hid → JSON` (private key PEM + public material). A zone has one **CSK** per algorithm; an algorithm rollover keeps both and signs with every algorithm (RFC 6840 5.11) until `removeKey`. `getSigner` assembles + caches the signer per process (short `signerCacheTtl`, since API and DNS run as separate workers); `enableZone`/`removeKey`/`disableZone` mutate under a shared Redis lock (`lib/lock.js`) and invalidate the cache.

The query-time path is `lib/dns-handler.js#signResponse` (DO queries only): it serves+self-signs DNSKEY at the apex, signs each in-zone RRset (`signSection`, but never a below-apex delegation NS — RFC 4035 2.2), and proves denial-of-existence as **NODATA (NOERROR) "black lies"** — a signed SOA + a compact NSEC at the queried name (`bitmapTypeNums`/`nsecRecord`), never NXDOMAIN or NSEC3, because the server synthesizes CAA/SOA for any name. The NSEC bitmap lists only **answerable** types and must exclude the queried-absent type (e.g. a `URL` record only advertises the `config.public.hosts` families) or a validator SERVFAILs. The API (`lib/api-server.js`) exposes `GET/POST/DELETE /v1/zone/{zone}/dnssec` and `DELETE .../dnssec/key/{keyTag}`.

**TLSA** records are stored as `[usage, selector, matchingType, certificate]` (even-length hex, guarded in the API Joi schema, the store's `add`/`update`, and `encodeTLSARdata`). dns2 has no TLSA/RRSIG/NSEC/DS encoder, so those are emitted as `{ type:<num>, data:<Buffer> }` and routed through dns2's raw-RDATA (RFC 3597) fallback; `dns-handler.js` merges `wire.EXTRA_TYPES` into its type maps to recognize them.

**EDNS / truncation** (`lib/dns-server.js`): `parseEdns` reads the OPT (DO bit + advertised payload size); `finalizeResponse` replaces the additional section with our own OPT and, for UDP, truncates with TC=1 above the smaller of the requestor's advertised size and our configured `udpPayloadSize` (anti-fragmentation), so the client retries over TCP.

### Certificates & the public server

`lib/certs.js` issues Let's Encrypt certs via the **dns-01** challenge, using the zone store itself as the ACME DNS provider (it writes/reads the `_acme-challenge` TXT records). Concurrent issuance is guarded with an `ioredfour` Redis lock (the shared `lib/lock.js`, also used by DNSSEC key management; callers namespace their own lock keys); results and a per-domain renewal lock are cached in Redis. `lib/public-server.js` uses an SNI callback to load the right cert per hostname (falling back to a bundled self-signed cert in `config/`), then serves URL-record redirects or reverse-proxies (`proxy=true`), with TLS session tickets stored in Redis.

### Testability seams

Production code exposes hooks used only by tests: `lib/api-server.js` exports `createServer()` (build the Hapi server without `start()`, for `server.inject()`); `lib/dns-server.js`'s `init()` awaits binding and returns `{ udpServer, tcpServer }`, and also attaches `.testables` (`parseEdns`, `finalizeResponse`); `lib/dns-handler.js` (`signResponse`, `bitmapTypeNums`, `processQuestion`, ...), `lib/certs.js`, and `lib/dnssec.js` attach a `.testables` object. `lib/dnssec-wire.js` is pure and is tested directly.

## CI / release

GitHub Actions mirror the `postalsys/emailengine` conventions and run on Node 24: `test.yml` (license check + lint + tests with a Redis service), `codeql.yml`, and `release.yaml` (release-please in manifest mode — see `release-please-config.json` + `.release-please-manifest.json`; publishes to npm via OIDC trusted publishing, which must be configured registry-side). `deploy.yml` tarballs the repo and ships it to the two name servers. Security policy lives in `SECURITY.md` + a GPG-signed `SECURITY.txt`.

## Commit conventions

- Use **Conventional Commits** (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `ci:`, etc.). release-please derives the version bump and `CHANGELOG.md` from these prefixes, so `feat:`/`fix:` commits landing on `master` are what open a release PR.
- **Do not** add Claude (or any AI assistant) as a co-author / co-contributor in commit messages.
- For commits that do not change runtime behaviour (docs, comments, CI/workflow tweaks, formatting), append `[skip ci]` to the commit message to avoid triggering the workflows. **Exception:** never add `[skip ci]` to a `feat:`/`fix:` commit — those must run so the release workflow fires.
- Run `npm run lint` and `npm test` before committing (the test run needs a local Redis; see the Tests section).
- After pushing, check the workflow runs (`gh run list --branch <branch>`) and report their status. If a run fails for an unrelated infrastructure reason (auth errors, HTTP 403, "account suspended"), check <https://www.githubstatus.com/> for an active incident before assuming the change is at fault.

## Code style

- No emojis in code or documentation — printable ASCII only.
- Use a single hyphen-minus (`-`) as a dash in user-facing strings and docs; never em dashes, en dashes, or double hyphens (`--`).
- Never swallow errors at the global `uncaughtException` / `unhandledRejection` handlers to keep a worker alive — those handlers are the last line of defence and the worker is expected to exit. Fix the error at its source (add the missing `try/catch`, `.catch()`, or `error` listener at the call site) instead.
