import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { fetchWithSsrFGuard } from "openclaw/plugin-sdk/ssrf-runtime";
import { Type, type Static } from "typebox";
import { OsintCache, type OsintObservation } from "./cache.js";

const IP_ASSIGNMENT_SOURCE = "ip-assignment-rdap";
const IPV4_BOOTSTRAP_SOURCE = "iana-rdap-ipv4-bootstrap";
const IPV6_BOOTSTRAP_SOURCE = "iana-rdap-ipv6-bootstrap";
const IP_ASSIGNMENT_TTL_MS = 6 * 60 * 60 * 1000;
const RDAP_BOOTSTRAP_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const RDAP_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const DEFAULT_MAX_CONTACTS = 8;
const MAX_CONTACTS = 25;

export const IpAssignmentIntelSchema = Type.Object(
  {
    ip: Type.String({
      description: "IPv4 or IPv6 address to enrich with the appropriate RIR RDAP allocation record.",
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

type IpAssignmentIntelParams = Static<typeof IpAssignmentIntelSchema>;

type IpBootstrap = {
  services?: Array<[string[], string[]]>;
};

type IpRdap = {
  objectClassName?: string;
  handle?: string;
  name?: string;
  type?: string;
  country?: string;
  parentHandle?: string;
  startAddress?: string;
  endAddress?: string;
  ipVersion?: string;
  status?: string[];
  events?: Array<{ eventAction?: string; eventDate?: string }>;
  entities?: unknown[];
  links?: Array<{ rel?: string; href?: string }>;
  notices?: Array<{ title?: string; description?: string[] }>;
};

export async function queryIpAssignmentIntelForTool(
  params: IpAssignmentIntelParams & { signal?: AbortSignal; cache?: OsintCache },
) {
  const ip = normalizeIp(params.ip);
  if (!ip) {
    return { ok: false, source: IP_ASSIGNMENT_SOURCE, error: "Expected an IPv4 or IPv6 address." };
  }
  const maxContacts = Math.min(Math.max(params.maxContacts ?? DEFAULT_MAX_CONTACTS, 1), MAX_CONTACTS);
  const cache = params.cache ?? new OsintCache();
  const closeCache = !params.cache;
  try {
    const fresh = params.refresh ? undefined : cache.getFreshSource(IP_ASSIGNMENT_SOURCE, ip);
    if (fresh) {
      return {
        ...JSON.parse(fresh.rawJson),
        cacheStatus: "hit",
        fetchedAt: fresh.fetchedAt,
        expiresAt: fresh.expiresAt,
      };
    }

    const fetchedAt = Date.now();
    const rdapUrl = await resolveIpRdapUrl(ip, { signal: params.signal, cache, refresh: Boolean(params.refresh) });
    if (!rdapUrl) {
      return { ok: false, source: IP_ASSIGNMENT_SOURCE, ip, error: "No RIR RDAP service found for IP." };
    }
    const rdap = await fetchIpRdap(rdapUrl, params.signal);
    const derivedIndicators = deriveIndicatorsFromRdap(rdap.rdap, maxContacts);
    const result = {
      ok: true,
      source: IP_ASSIGNMENT_SOURCE,
      ip,
      cacheStatus: "refreshed",
      fetchedAt,
      expiresAt: fetchedAt + IP_ASSIGNMENT_TTL_MS,
      rdapUrl: rdap.rdapUrl,
      registryHint: registryHintFromRdapUrl(rdap.rdapUrl),
      summary: summarizeIpRdap(rdap.rdap),
      derivedIndicators,
      sources: [
        ipVersion(ip) === 6 ? "IANA IPv6 RDAP bootstrap" : "IANA IPv4 RDAP bootstrap",
        rdap.rdapUrl,
      ],
      caveat:
        "RIR RDAP identifies allocation and role contacts for an IP resource. It does not prove subscriber, device, or private human identity.",
    };
    const rawJson = JSON.stringify(result);
    cache.putSource({
      source: IP_ASSIGNMENT_SOURCE,
      target: ip,
      fetchedAt,
      expiresAt: fetchedAt + IP_ASSIGNMENT_TTL_MS,
      rawJson,
      rawBytes: Buffer.byteLength(rawJson),
      status: "ok",
    });
    cache.replaceObservations(
      IP_ASSIGNMENT_SOURCE,
      ip,
      observationsFromIpAssignment(ip, derivedIndicators, fetchedAt),
    );
    return result;
  } catch (error) {
    return { ok: false, source: IP_ASSIGNMENT_SOURCE, ip, error: formatError(error) };
  } finally {
    if (closeCache) {
      cache.close();
    }
  }
}

async function resolveIpRdapUrl(
  ip: string,
  params: { signal?: AbortSignal; cache: OsintCache; refresh: boolean },
): Promise<string | undefined> {
  const bootstrap = await getIpBootstrap(ipVersion(ip), params);
  const value = ipToBigInt(ip);
  for (const service of bootstrap.services ?? []) {
    const [ranges, urls] = service;
    if (ranges.some((range) => rangeContainsIp(range, value, ipVersion(ip)))) {
      const baseUrl = urls[0];
      return baseUrl ? new URL(`ip/${ip}`, ensureTrailingSlash(baseUrl)).toString() : undefined;
    }
  }
  return undefined;
}

async function getIpBootstrap(
  version: 4 | 6,
  params: { signal?: AbortSignal; cache: OsintCache; refresh: boolean },
) {
  const source = version === 6 ? IPV6_BOOTSTRAP_SOURCE : IPV4_BOOTSTRAP_SOURCE;
  const url = version === 6 ? "https://data.iana.org/rdap/ipv6.json" : "https://data.iana.org/rdap/ipv4.json";
  const fresh = params.refresh ? undefined : params.cache.getFreshSource(source, "ip");
  if (fresh) {
    return JSON.parse(fresh.rawJson) as IpBootstrap;
  }
  const guarded = await fetchWithSsrFGuard({
    url,
    init: { headers: { Accept: "application/json" } },
    timeoutMs: RDAP_TIMEOUT_MS,
    signal: params.signal,
    auditContext: "openclaw-osint-ip-rdap-bootstrap",
  });
  const { response, release } = guarded;
  try {
    if (!response.ok) {
      throw new Error(`IANA IP RDAP bootstrap returned HTTP ${response.status}`);
    }
    const rawJson = await readResponseTextBounded(response, MAX_RESPONSE_BYTES);
    const fetchedAt = Date.now();
    params.cache.putSource({
      source,
      target: "ip",
      fetchedAt,
      expiresAt: fetchedAt + RDAP_BOOTSTRAP_TTL_MS,
      rawJson,
      rawBytes: Buffer.byteLength(rawJson),
      status: "ok",
    });
    return JSON.parse(rawJson) as IpBootstrap;
  } finally {
    await release();
  }
}

async function fetchIpRdap(rdapUrl: string, signal?: AbortSignal) {
  const guarded = await fetchWithSsrFGuard({
    url: rdapUrl,
    init: {
      headers: {
        Accept: "application/rdap+json,application/json;q=0.8,*/*;q=0.1",
        "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
      },
    },
    timeoutMs: RDAP_TIMEOUT_MS,
    signal,
    auditContext: "openclaw-osint-ip-rdap",
  });
  const { response, release, finalUrl } = guarded;
  try {
    if (!response.ok) {
      throw new Error(`IP RDAP returned HTTP ${response.status}`);
    }
    return {
      rdapUrl: finalUrl,
      rdap: JSON.parse(await readResponseTextBounded(response, MAX_RESPONSE_BYTES)) as IpRdap,
    };
  } finally {
    await release();
  }
}

function summarizeIpRdap(rdap: IpRdap) {
  return {
    objectClassName: rdap.objectClassName,
    handle: rdap.handle,
    name: rdap.name,
    type: rdap.type,
    country: rdap.country,
    parentHandle: rdap.parentHandle,
    startAddress: rdap.startAddress,
    endAddress: rdap.endAddress,
    ipVersion: rdap.ipVersion,
    status: rdap.status ?? [],
    events: (rdap.events ?? []).map((event) => ({
      action: event.eventAction,
      date: event.eventDate,
    })),
    entityCount: rdap.entities?.length ?? 0,
    noticeTitles: (rdap.notices ?? []).flatMap((notice) => notice.title ?? []),
  };
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

function observationsFromIpAssignment(
  ip: string,
  derivedIndicators: { emails: readonly string[]; phones: readonly string[] },
  observedAt: number,
): OsintObservation[] {
  return [
    ...derivedIndicators.emails.map((email) => ({
      id: stableObservationId(IP_ASSIGNMENT_SOURCE, ip, "email", email),
      source: IP_ASSIGNMENT_SOURCE,
      target: ip,
      type: "email",
      value: email,
      confidence: 0.78,
      admissionScore: 0.72,
      storageTier: "thin" as const,
      observedAt,
      sourceRef: "rir-rdap:contact-email",
    })),
    ...derivedIndicators.phones.map((phone) => ({
      id: stableObservationId(IP_ASSIGNMENT_SOURCE, ip, "phone", phone),
      source: IP_ASSIGNMENT_SOURCE,
      target: ip,
      type: "phone",
      value: phone,
      confidence: 0.62,
      admissionScore: 0.55,
      storageTier: "thin" as const,
      observedAt,
      sourceRef: "rir-rdap:contact-phone",
    })),
  ];
}

function rangeContainsIp(range: string, ip: bigint, version: 4 | 6): boolean {
  const [base, prefixText] = range.split("/");
  const baseValue = base ? ipToBigInt(base) : undefined;
  const prefix = prefixText ? Number(prefixText) : undefined;
  if (baseValue === undefined || prefix === undefined || !Number.isInteger(prefix)) {
    return false;
  }
  const bits = version === 6 ? 128 : 32;
  if (prefix < 0 || prefix > bits) {
    return false;
  }
  const hostBits = BigInt(bits - prefix);
  const size = 1n << hostBits;
  const start = (baseValue / size) * size;
  const end = start + size - 1n;
  return ip >= start && ip <= end;
}

function ipToBigInt(ip: string): bigint {
  return ipVersion(ip) === 6 ? ipv6ToBigInt(ip) : ipv4ToBigInt(ip);
}

function ipv4ToBigInt(ip: string): bigint {
  return ip.split(".").reduce((value, part) => (value << 8n) + BigInt(Number(part)), 0n);
}

function ipv6ToBigInt(ip: string): bigint {
  const [head = "", tail = ""] = ip.toLowerCase().split("::", 2);
  const headParts = head ? head.split(":") : [];
  const tailParts = tail ? tail.split(":") : [];
  const missing = 8 - headParts.length - tailParts.length;
  const parts = [...headParts, ...Array(Math.max(missing, 0)).fill("0"), ...tailParts];
  return parts.reduce((value, part) => (value << 16n) + BigInt(parseInt(part || "0", 16)), 0n);
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

function registryHintFromRdapUrl(url: string): string {
  const host = new URL(url).hostname.toLowerCase();
  if (host.includes("arin")) return "ARIN";
  if (host.includes("apnic")) return "APNIC";
  if (host.includes("ripe")) return "RIPE NCC";
  if (host.includes("lacnic")) return "LACNIC";
  if (host.includes("registro.br")) return "LACNIC/NIC.br";
  if (host.includes("afrinic")) return "AFRINIC";
  return "unknown_rir";
}

function normalizeIp(input: string): string | undefined {
  const value = input.trim();
  return isIP(value) ? value : undefined;
}

function ipVersion(ip: string): 4 | 6 {
  return isIP(ip) === 6 ? 6 : 4;
}

function uniqueBounded(values: readonly string[], limit: number): string[] {
  return Array.from(new Set(values.filter(Boolean))).slice(0, limit);
}

function ensureTrailingSlash(value: string): string {
  return value.endsWith("/") ? value : `${value}/`;
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
  deriveIndicatorsFromRdap,
  ipv4ToBigInt,
  ipv6ToBigInt,
  rangeContainsIp,
  registryHintFromRdapUrl,
  summarizeIpRdap,
};
