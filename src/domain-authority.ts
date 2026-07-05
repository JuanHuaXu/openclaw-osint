import { createHash } from "node:crypto";
import { promises as dns } from "node:dns";
import { fetchWithSsrFGuard } from "openclaw/plugin-sdk/ssrf-runtime";
import { Type, type Static } from "typebox";
import { OsintCache, type OsintObservation } from "./cache.js";

const DOMAIN_AUTHORITY_SOURCE = "domain-authority";
const RDAP_BOOTSTRAP_SOURCE = "iana-rdap-dns-bootstrap";
const DOMAIN_AUTHORITY_TTL_MS = 6 * 60 * 60 * 1000;
const RDAP_BOOTSTRAP_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const DNS_TIMEOUT_MS = 5_000;
const RDAP_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const DEFAULT_MAX_CONTACTS = 8;
const MAX_CONTACTS = 25;

export const DomainAuthorityIntelSchema = Type.Object(
  {
    domain: Type.String({
      description: "Domain or host to inspect through authoritative DNS records and domain RDAP.",
    }),
    maxContacts: Type.Optional(
      Type.Integer({
        description: "Maximum RDAP-derived email and phone indicators to return.",
        minimum: 1,
        maximum: MAX_CONTACTS,
      }),
    ),
    refresh: Type.Optional(Type.Boolean({ description: "Bypass fresh local cache where supported." })),
  },
  { additionalProperties: false },
);

type DomainAuthorityIntelParams = Static<typeof DomainAuthorityIntelSchema>;

type Rdata = {
  objectClassName?: string;
  handle?: string;
  ldhName?: string;
  unicodeName?: string;
  status?: string[];
  events?: Array<{ eventAction?: string; eventDate?: string }>;
  entities?: unknown[];
  nameservers?: Array<{ ldhName?: string; unicodeName?: string }>;
  secureDNS?: { delegationSigned?: boolean };
};

type RdataBootstrap = {
  services?: Array<[string[], string[]]>;
};

export async function queryDomainAuthorityIntelForTool(
  params: DomainAuthorityIntelParams & { signal?: AbortSignal; cache?: OsintCache },
) {
  const inputDomain = normalizeDomain(params.domain);
  if (!inputDomain) {
    return { ok: false, source: DOMAIN_AUTHORITY_SOURCE, error: "Expected a DNS domain." };
  }
  const maxContacts = Math.min(Math.max(params.maxContacts ?? DEFAULT_MAX_CONTACTS, 1), MAX_CONTACTS);
  const cache = params.cache ?? new OsintCache();
  const closeCache = !params.cache;
  try {
    const registration = await resolveRegistration(inputDomain, {
      signal: params.signal,
      cache,
      refresh: Boolean(params.refresh),
    });
    const registeredDomain = registration.domain;
    const fresh = params.refresh ? undefined : cache.getFreshSource(DOMAIN_AUTHORITY_SOURCE, registeredDomain);
    if (fresh) {
      return {
        ...JSON.parse(fresh.rawJson),
        cacheStatus: "hit",
        fetchedAt: fresh.fetchedAt,
        expiresAt: fresh.expiresAt,
      };
    }

    const fetchedAt = Date.now();
    const dnsAuthority = await queryDnsAuthority(registeredDomain);
    const rdap = registration.rdap;
    const derivedIndicators = deriveIndicatorsFromRdap(rdap.rdap, maxContacts);
    const result = {
      ok: true,
      source: DOMAIN_AUTHORITY_SOURCE,
      inputDomain,
      registeredDomain,
      cacheStatus: "refreshed",
      fetchedAt,
      expiresAt: fetchedAt + DOMAIN_AUTHORITY_TTL_MS,
      dnsAuthority,
      rdap,
      derivedIndicators,
      sources: [
        "local DNS resolver for NS/SOA/MX/TXT/CAA authority records",
        "IANA RDAP bootstrap",
        ...(rdap.rdapUrl ? [rdap.rdapUrl] : []),
      ],
      caveat:
        "RDAP contact data is often redacted or role-based. Treat derived emails and phones as reputation indicators only, not private identity attribution.",
    };
    const rawJson = JSON.stringify(result);
    cache.putSource({
      source: DOMAIN_AUTHORITY_SOURCE,
      target: registeredDomain,
      fetchedAt,
      expiresAt: fetchedAt + DOMAIN_AUTHORITY_TTL_MS,
      rawJson,
      rawBytes: Buffer.byteLength(rawJson),
      status: "ok",
    });
    cache.replaceObservations(
      DOMAIN_AUTHORITY_SOURCE,
      registeredDomain,
      observationsFromAuthorityResult(registeredDomain, derivedIndicators, fetchedAt),
    );
    return result;
  } catch (error) {
    return {
      ok: false,
      source: DOMAIN_AUTHORITY_SOURCE,
      domain: inputDomain,
      error: formatError(error),
    };
  } finally {
    if (closeCache) {
      cache.close();
    }
  }
}

async function queryDnsAuthority(domain: string) {
  const [ns, soa, mx, txt, caa] = await Promise.all([
    withTimeout(dns.resolveNs(domain), DNS_TIMEOUT_MS).catch((error) => ({ error: formatError(error) })),
    withTimeout(dns.resolveSoa(domain), DNS_TIMEOUT_MS).catch((error) => ({ error: formatError(error) })),
    withTimeout(dns.resolveMx(domain), DNS_TIMEOUT_MS).catch((error) => ({ error: formatError(error) })),
    withTimeout(dns.resolveTxt(domain), DNS_TIMEOUT_MS).catch((error) => ({ error: formatError(error) })),
    withTimeout(resolveCaa(domain), DNS_TIMEOUT_MS).catch((error) => ({ error: formatError(error) })),
  ]);
  return { ns, soa, mx, txt, caa };
}

async function resolveCaa(domain: string): Promise<unknown> {
  const resolver = dns as typeof dns & { resolveCaa?: (hostname: string) => Promise<unknown> };
  return resolver.resolveCaa ? resolver.resolveCaa(domain) : { error: "CAA lookup is unavailable in this Node runtime." };
}

async function resolveRegistration(
  domain: string,
  params: { signal?: AbortSignal; cache: OsintCache; refresh: boolean },
): Promise<{ domain: string; rdap: Awaited<ReturnType<typeof queryDomainRdap>> }> {
  for (const candidate of domainCandidates(domain)) {
    const rdap = await queryDomainRdap(candidate, params);
    if (rdap.ok) {
      return { domain: candidate, rdap };
    }
  }
  const fallback = inferRegisteredDomain(domain);
  return {
    domain: fallback,
    rdap: await queryDomainRdap(fallback, params),
  };
}

async function queryDomainRdap(
  domain: string,
  params: { signal?: AbortSignal; cache: OsintCache; refresh: boolean },
) {
  const rdapUrl = await resolveDomainRdapUrl(domain, params);
  if (!rdapUrl) {
    return { ok: false, error: "No RDAP service found for domain TLD." };
  }
  const guarded = await fetchWithSsrFGuard({
    url: rdapUrl,
    init: {
      headers: {
        Accept: "application/rdap+json,application/json;q=0.8,*/*;q=0.1",
        "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
      },
    },
    timeoutMs: RDAP_TIMEOUT_MS,
    signal: params.signal,
    auditContext: "openclaw-osint-domain-rdap",
  });
  const { response, release, finalUrl } = guarded;
  try {
    if (!response.ok) {
      return { ok: false, rdapUrl, error: `RDAP returned HTTP ${response.status}` };
    }
    const rdap = JSON.parse(await readResponseTextBounded(response, MAX_RESPONSE_BYTES)) as Rdata;
    return {
      ok: true,
      rdapUrl: finalUrl,
      summary: summarizeRdap(rdap),
      rdap,
    };
  } finally {
    await release();
  }
}

async function resolveDomainRdapUrl(
  domain: string,
  params: { signal?: AbortSignal; cache: OsintCache; refresh: boolean },
): Promise<string | undefined> {
  const tld = domain.split(".").at(-1);
  if (!tld) {
    return undefined;
  }
  const bootstrap = await getRdapBootstrap(params);
  for (const service of bootstrap.services ?? []) {
    const [tlds, urls] = service;
    if (tlds.map((value) => value.toLowerCase()).includes(tld)) {
      const baseUrl = urls[0];
      return baseUrl ? new URL(`domain/${domain}`, ensureTrailingSlash(baseUrl)).toString() : undefined;
    }
  }
  return undefined;
}

async function getRdapBootstrap(params: { signal?: AbortSignal; cache: OsintCache; refresh: boolean }) {
  const fresh = params.refresh ? undefined : params.cache.getFreshSource(RDAP_BOOTSTRAP_SOURCE, "dns");
  if (fresh) {
    return JSON.parse(fresh.rawJson) as RdataBootstrap;
  }
  const guarded = await fetchWithSsrFGuard({
    url: "https://data.iana.org/rdap/dns.json",
    init: { headers: { Accept: "application/json" } },
    timeoutMs: RDAP_TIMEOUT_MS,
    signal: params.signal,
    auditContext: "openclaw-osint-rdap-bootstrap",
  });
  const { response, release } = guarded;
  try {
    if (!response.ok) {
      throw new Error(`IANA RDAP bootstrap returned HTTP ${response.status}`);
    }
    const rawJson = await readResponseTextBounded(response, MAX_RESPONSE_BYTES);
    const fetchedAt = Date.now();
    params.cache.putSource({
      source: RDAP_BOOTSTRAP_SOURCE,
      target: "dns",
      fetchedAt,
      expiresAt: fetchedAt + RDAP_BOOTSTRAP_TTL_MS,
      rawJson,
      rawBytes: Buffer.byteLength(rawJson),
      status: "ok",
    });
    return JSON.parse(rawJson) as RdataBootstrap;
  } finally {
    await release();
  }
}

function deriveIndicatorsFromRdap(rdap: unknown, maxContacts: number) {
  const text = collectStringLeaves(rdap).join("\n");
  return {
    emails: uniqueBounded(
      Array.from(text.matchAll(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi)).map((match) =>
        match[0].toLowerCase()
      ),
      maxContacts,
    ),
    phones: uniqueBounded(
      Array.from(text.matchAll(/(?<!\d)(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}(?!\d)/g))
        .map((match) => match[0].trim()),
      maxContacts,
    ),
  };
}

function collectStringLeaves(value: unknown): string[] {
  if (typeof value === "string") {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.flatMap(collectStringLeaves);
  }
  if (value && typeof value === "object") {
    return Object.values(value).flatMap(collectStringLeaves);
  }
  return [];
}

function summarizeRdap(rdap: Rdata) {
  return {
    objectClassName: rdap.objectClassName,
    handle: rdap.handle,
    ldhName: rdap.ldhName,
    unicodeName: rdap.unicodeName,
    status: rdap.status ?? [],
    events: (rdap.events ?? []).map((event) => ({
      action: event.eventAction,
      date: event.eventDate,
    })),
    nameservers: (rdap.nameservers ?? []).flatMap((nameserver) =>
      nameserver.ldhName ?? nameserver.unicodeName ?? []
    ),
    secureDnsDelegationSigned: rdap.secureDNS?.delegationSigned,
    entityCount: rdap.entities?.length ?? 0,
  };
}

function observationsFromAuthorityResult(
  domain: string,
  derivedIndicators: { emails: readonly string[]; phones: readonly string[] },
  observedAt: number,
): OsintObservation[] {
  return [
    ...derivedIndicators.emails.map((email) => ({
      id: stableObservationId(DOMAIN_AUTHORITY_SOURCE, domain, "email", email),
      source: DOMAIN_AUTHORITY_SOURCE,
      target: domain,
      type: "email",
      value: email,
      confidence: 0.75,
      admissionScore: 0.7,
      storageTier: "thin" as const,
      observedAt,
      sourceRef: "rdap:contact-email",
    })),
    ...derivedIndicators.phones.map((phone) => ({
      id: stableObservationId(DOMAIN_AUTHORITY_SOURCE, domain, "phone", phone),
      source: DOMAIN_AUTHORITY_SOURCE,
      target: domain,
      type: "phone",
      value: phone,
      confidence: 0.62,
      admissionScore: 0.55,
      storageTier: "thin" as const,
      observedAt,
      sourceRef: "rdap:contact-phone",
    })),
  ];
}

function normalizeDomain(input: string): string | undefined {
  const value = input.trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/?#]/, 1)[0] ?? "";
  if (value.length > 253 || !value.includes(".") || value.includes("..")) {
    return undefined;
  }
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value)) {
    return undefined;
  }
  return value.replace(/\.$/, "");
}

function inferRegisteredDomain(domain: string): string {
  const labels = domain.split(".").filter(Boolean);
  return labels.length > 2 ? labels.slice(-2).join(".") : domain;
}

function domainCandidates(domain: string): string[] {
  const labels = domain.split(".").filter(Boolean);
  const candidates = [];
  for (let index = 0; index <= labels.length - 2; index += 1) {
    candidates.push(labels.slice(index).join("."));
  }
  return candidates;
}

function uniqueBounded(values: readonly string[], limit: number): string[] {
  return Array.from(new Set(values.filter(Boolean))).slice(0, limit);
}

function ensureTrailingSlash(value: string): string {
  return value.endsWith("/") ? value : `${value}/`;
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("DNS authority lookup timed out")), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

async function readResponseTextBounded(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) {
    return (await response.text()).slice(0, maxBytes);
  }
  const chunks: Uint8Array[] = [];
  let received = 0;
  while (received < maxBytes) {
    const { done, value } = await reader.read();
    if (done || !value) {
      break;
    }
    const remaining = maxBytes - received;
    const chunk = value.byteLength > remaining ? value.slice(0, remaining) : value;
    chunks.push(chunk);
    received += chunk.byteLength;
    if (value.byteLength > remaining) {
      break;
    }
  }
  await reader.cancel().catch(() => {});
  return new TextDecoder().decode(concatUint8Arrays(chunks));
}

function concatUint8Arrays(chunks: readonly Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return combined;
}

function stableObservationId(...parts: readonly string[]): string {
  return createHash("sha256").update(parts.join("\0")).digest("hex").slice(0, 32);
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export const testing = {
  domainCandidates,
  deriveIndicatorsFromRdap,
  inferRegisteredDomain,
  normalizeDomain,
  summarizeRdap,
};
