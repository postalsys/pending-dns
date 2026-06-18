# Security Policy

PendingDNS is a lightweight, API-driven authoritative DNS server. It also runs a
public HTTP/HTTPS redirect/proxy server and generates Let's Encrypt certificates
over an ACME flow, and it stores all zone data in Redis. Because it is exposed to
untrusted DNS and HTTP traffic and handles certificate private keys, we take
security reports seriously and aim to respond quickly.

## Supported Versions

Security fixes are released only against the latest version. We do not backport
patches to older releases - upgrading to the current release line is the
supported way to receive security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

If you are on an older version, please upgrade. See the release notes at
<https://github.com/postalsys/pending-dns/releases> before updating.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Report privately through one of the following channels:

1. **GitHub Security Advisories (preferred).** Open a private report at
   <https://github.com/postalsys/pending-dns/security/advisories/new>. This keeps
   the discussion private until a fix is published and lets us credit you.
2. **Email.** Send details to **andris@postalsys.com** (the contact listed in
   [`SECURITY.txt`](SECURITY.txt)). Encrypt sensitive details if possible using
   the key referenced there.

When reporting, please include as much of the following as you can:

- The affected version(s) and environment (PendingDNS version, Node.js version,
  OS, deployment method - npm or prebuilt binary).
- The component involved (e.g. the UDP/TCP DNS server, the REST API, the public
  HTTP/HTTPS redirect and proxy server, ACME certificate generation, health
  checks, or the Redis-backed zone store).
- A clear description of the issue and its impact (e.g. cache poisoning, DNS
  amplification, request smuggling, SSRF via the URL/proxy records or health
  checks, certificate mis-issuance, credential or private-key disclosure,
  injection, information disclosure, denial of service).
- A minimal proof of concept or reproduction steps.
- Any suggested remediation, if you have one.

We are a small team, so there is no guaranteed response time - sometimes reports
are handled within hours, sometimes they take longer. Accepted issues are fixed
in a new release and coordinated through a GitHub Security Advisory, and
reporters who wish to be named are credited.

## CVEs

We track and disclose vulnerabilities through GitHub Security Advisories. We do
not request or manage CVE identifiers ourselves. If you need a CVE assigned for a
reported issue, please request one yourself - for example, through GitHub's own
CVE request flow on the published advisory, or another CNA.

## Scope

In scope: the PendingDNS application source in this repository - the
authoritative DNS server (UDP and TCP), the REST API for managing zone records,
the public HTTP/HTTPS redirect and proxy server, ACME/Let's Encrypt certificate
generation and storage, the health-check subsystem, and the Redis-backed zone
store.

Out of scope:

- Vulnerabilities in your own application code or automation that integrates
  with the PendingDNS API.
- Misconfiguration of your deployment - for example, exposing the management API
  to untrusted networks, an unauthenticated or publicly reachable Redis instance,
  binding the DNS server in a way that enables open-resolver-style abuse, or
  missing TLS on the API.
- The inherent properties of plain DNS over UDP/TCP without DNSSEC (PendingDNS
  does not implement DNSSEC, DoH, or DoT by design).
- Issues that require an already-compromised host or pre-existing administrator
  access.
- Vulnerabilities in third-party services PendingDNS connects to (Let's Encrypt,
  upstream resolvers, health-check targets).
- Social-engineering reports and missing security headers without a
  demonstrated, concrete impact.

Thank you for helping keep PendingDNS and its users safe.
