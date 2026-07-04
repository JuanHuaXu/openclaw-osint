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

## Cache Behavior

The plugin uses a bounded local SQLite cache for cacheable public sources.

- default path: OpenClaw user state under `state/plugins/osint/osint.sqlite`
- override path: `OPENCLAW_OSINT_DB_PATH`
- `crt.sh` cache TTL: 24 hours
- HIBP email cache TTL: 24 hours
- HIBP latest breach cache TTL: 1 hour
- per-source cache pruning: latest 250 source targets
- no shell execution, scanning, credentialed APIs, or private-data-broker lookups

## Install

```bash
pnpm install
pnpm build
pnpm pack
openclaw plugins install ./openclaw-osint-0.3.0.tgz
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
