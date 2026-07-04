# OpenClaw OSINT

MIT-licensed standalone OpenClaw plugin for bounded public-source OSINT helpers.

This plugin is intentionally conservative. It provides useful public-source primitives without credentialed scraping, private data broker access, exploit checks, port scans, or shell execution.

## Tools

### `osint_extract_indicators`

Extracts indicators from supplied text without network access.

Returns:

- URLs
- domains
- IPv4 addresses
- email addresses present in the input
- social handles present in the input
- common cryptographic hashes

### `osint_url_snapshot`

Fetches one public HTTP(S) URL through OpenClaw's SSRF guard and returns bounded metadata:

- HTTP status and final URL
- content type
- page title
- description
- canonical URL
- bounded body excerpt wrapped as untrusted external content

### `osint_crtsh_domain`

Looks up certificate transparency names for a public domain using `crt.sh`.

Returns:

- normalized domain observations
- confidence and source reference per observation
- cache status (`hit` or `refreshed`)
- bounded counts for returned and stored observations

The tool stores scoped observations in a local SQLite cache and drops names that do not match the requested domain suffix.

### `osint_domain_network_intel`

Resolves a domain and enriches the returned IPs with passive network ownership data.

Sources and behavior:

- uses the local DNS resolver for A/AAAA records
- queries the supported bgp.tools WHOIS automation interface on TCP/43
- caches bgp.tools WHOIS rows locally
- returns ASN, BGP prefix, country, registry, allocation date, and AS name per IP
- can include an operator-side traceroute plan
- does not run traceroute or shell commands itself

### `osint_cache_status`

Reports local OSINT cache counts and byte totals without exposing cached raw data.

### `osint_hibp_email_breach`

Checks an email address against Have I Been Pwned.

Requirements and behavior:

- requires `HIBP_API_KEY`
- sends the email address to HIBP
- stores cache entries under a SHA-256 email target key, not the raw email address
- returns breach names, domains, dates, data classes, and flags
- omits HIBP HTML descriptions from tool output
- includes HIBP attribution

### `osint_hibp_latest_breach`

Fetches the most recently added HIBP breach metadata. This is unauthenticated and can be used as a cheap preflight before account checks.

### `osint_pwned_password_hash`

Checks a SHA-1 or NTLM password hash against HIBP Pwned Passwords using the k-anonymity range API.

Requirements and behavior:

- accepts only SHA-1 or NTLM hashes
- rejects plaintext-like input
- sends only the first five hash characters to the API
- checks the suffix locally
- does not store searched hashes

### `osint_phone_reputation`

Checks a US phone number against FTC Do Not Call reported-call complaint data.

Requirements and behavior:

- works without API keys for local US phone normalization
- adds FTC complaint evidence when `FTC_API_KEY` is configured
- supports US numbers only
- fetches a bounded recent area-code sample and matches the number locally
- returns complaint count, robocall count, subjects, dates, and caveats
- treats FTC reports as unverified reputation evidence, not owner identity

### `osint_infra_reputation`

Checks IPv4 infrastructure against abuse reputation sources.

Sources:

- Spamhaus DROP IPv4 netblocks, cached locally
- AbuseIPDB, when `ABUSEIPDB_API_KEY` is configured

The result classifies service/spam infrastructure likelihood without identifying a private human owner.

### `osint_bot_identity_assess`

Combines explicit evidence into a bot/service identity assessment.

Inputs can include:

- platform bot/app/webhook metadata
- official service-source evidence
- phone complaint counts
- Spamhaus listing state
- AbuseIPDB confidence score

Outputs include owner-class hints, confidence, evidence, allowed actions, and blocked actions. Human identity resolution stays blocked even when spam/service evidence exists.

## Cache Behavior

The plugin uses a bounded local SQLite cache for cacheable public sources.

- default path: OpenClaw user state under `state/plugins/osint/osint.sqlite`
- override path: `OPENCLAW_OSINT_DB_PATH`
- `crt.sh` cache TTL: 24 hours
- bgp.tools WHOIS cache TTL: 6 hours
- HIBP email cache TTL: 24 hours
- HIBP latest breach cache TTL: 1 hour
- FTC phone reputation cache TTL: 6 hours
- Spamhaus DROP cache TTL: 12 hours
- per-source cache pruning: latest 250 source targets
- no shell execution, scanning, credentialed APIs, or private-data-broker lookups

## Install

```bash
pnpm install
pnpm build
pnpm pack
openclaw plugins install ./openclaw-osint-0.5.0.tgz
```

Restart the OpenClaw gateway after install.

## Build And Test

```bash
pnpm install
pnpm build
pnpm test
```

## Versioning

Use `v<major>.<feature>.<patch>` git tags. Keep the tag, `package.json` version, and `openclaw.plugin.json` version aligned.
