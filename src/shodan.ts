import { isIP } from "node:net";
import { fetchWithSsrFGuard } from "openclaw/plugin-sdk/ssrf-runtime";
import { Type, type Static } from "typebox";
import { OsintCache } from "./cache.js";

const SHODAN_INTERNETDB_SOURCE = "shodan-internetdb";
const SHODAN_HOST_SOURCE = "shodan-host";
const SHODAN_INTERNETDB_TTL_MS = 24 * 60 * 60 * 1000;
const SHODAN_HOST_TTL_MS = 6 * 60 * 60 * 1000;
const SHODAN_INTERNETDB_TIMEOUT_MS = 8_000;
const SHODAN_HOST_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 512 * 1024;
const MAX_LIST_ITEMS = 50;
const MAX_SERVICE_SUMMARIES = 20;

export const ShodanInternetDbHostSchema = Type.Object(
  {
    ip: Type.String({
      description: "Public IPv4 or IPv6 address to check with Shodan InternetDB's keyless host summary.",
    }),
    refresh: Type.Optional(Type.Boolean({ description: "Bypass fresh local cache." })),
  },
  { additionalProperties: false },
);

export const ShodanHostSchema = Type.Object(
  {
    ip: Type.String({
      description:
        "Public IPv4 or IPv6 address to check with full Shodan host lookup when SHODAN_API_KEY exists, otherwise Shodan InternetDB.",
    }),
    includeBanners: Type.Optional(
      Type.Boolean({
        description:
          "Include compact service banner summaries from keyed Shodan. Defaults to false; ignored by InternetDB fallback.",
      }),
    ),
    history: Type.Optional(
      Type.Boolean({
        description:
          "Ask keyed Shodan for historical banners. Defaults to false; ignored by InternetDB fallback.",
      }),
    ),
    refresh: Type.Optional(Type.Boolean({ description: "Bypass fresh local cache." })),
  },
  { additionalProperties: false },
);

type ShodanInternetDbHostParams = Static<typeof ShodanInternetDbHostSchema>;
type ShodanHostParams = Static<typeof ShodanHostSchema>;

type InternetDbResponse = {
  ip?: string;
  ports?: unknown[];
  hostnames?: unknown[];
  cpes?: unknown[];
  tags?: unknown[];
  vulns?: unknown[] | Record<string, unknown>;
};

type ShodanHostResponse = {
  ip_str?: string;
  ports?: unknown[];
  hostnames?: unknown[];
  domains?: unknown[];
  org?: string;
  isp?: string;
  asn?: string;
  country_code?: string;
  city?: string;
  tags?: unknown[];
  vulns?: unknown[] | Record<string, unknown>;
  data?: Array<Record<string, unknown>>;
};

export async function queryShodanHostForTool(
  params: ShodanHostParams & { signal?: AbortSignal; cache?: OsintCache },
) {
  const apiKey = process.env.SHODAN_API_KEY?.trim();
  if (!apiKey) {
    const fallback = await queryShodanInternetDbHostForTool(params);
    return {
      ...fallback,
      source: SHODAN_HOST_SOURCE,
      provider: "shodan-internetdb",
      mode: "keyless_fallback",
      fallbackSource: SHODAN_INTERNETDB_SOURCE,
      caveat:
        "SHODAN_API_KEY is not configured, so this used Shodan InternetDB's keyless host summary instead of full Shodan banners.",
    };
  }
  const ip = normalizePublicIp(params.ip);
  if (!ip) {
    return {
      ok: false,
      source: SHODAN_HOST_SOURCE,
      error: "Expected a public IPv4 or IPv6 address.",
    };
  }
  const cache = params.cache ?? new OsintCache();
  const closeCache = !params.cache;
  const includeBanners = Boolean(params.includeBanners);
  const history = Boolean(params.history);
  const target = `${ip}:banners=${includeBanners}:history=${history}`;
  try {
    const fresh = params.refresh ? undefined : cache.getFreshSource(SHODAN_HOST_SOURCE, target);
    if (fresh) {
      return {
        ...JSON.parse(fresh.rawJson),
        cacheStatus: "hit",
        fetchedAt: fresh.fetchedAt,
        expiresAt: fresh.expiresAt,
      };
    }

    const fetchedAt = Date.now();
    const result = await fetchShodanHost({
      ip,
      apiKey,
      includeBanners,
      history,
      signal: params.signal,
    });
    const output = {
      ...result,
      cacheStatus: "refreshed" as const,
      fetchedAt,
      expiresAt: fetchedAt + SHODAN_HOST_TTL_MS,
    };
    const rawJson = JSON.stringify(output);
    cache.putSource({
      source: SHODAN_HOST_SOURCE,
      target,
      fetchedAt,
      expiresAt: fetchedAt + SHODAN_HOST_TTL_MS,
      rawJson,
      rawBytes: Buffer.byteLength(rawJson),
      status: "ok",
    });
    return output;
  } catch (error) {
    return {
      ok: false,
      source: SHODAN_HOST_SOURCE,
      ip,
      error: formatError(error),
    };
  } finally {
    if (closeCache) {
      cache.close();
    }
  }
}

export async function queryShodanInternetDbHostForTool(
  params: ShodanInternetDbHostParams & { signal?: AbortSignal; cache?: OsintCache },
) {
  const ip = normalizePublicIp(params.ip);
  if (!ip) {
    return {
      ok: false,
      source: SHODAN_INTERNETDB_SOURCE,
      error: "Expected a public IPv4 or IPv6 address.",
    };
  }
  const cache = params.cache ?? new OsintCache();
  const closeCache = !params.cache;
  try {
    const fresh = params.refresh ? undefined : cache.getFreshSource(SHODAN_INTERNETDB_SOURCE, ip);
    if (fresh) {
      return {
        ...JSON.parse(fresh.rawJson),
        cacheStatus: "hit",
        fetchedAt: fresh.fetchedAt,
        expiresAt: fresh.expiresAt,
      };
    }

    const fetchedAt = Date.now();
    const result = await fetchShodanInternetDb(ip, params.signal);
    const output = {
      ...result,
      cacheStatus: "refreshed" as const,
      fetchedAt,
      expiresAt: fetchedAt + SHODAN_INTERNETDB_TTL_MS,
    };
    const rawJson = JSON.stringify(output);
    cache.putSource({
      source: SHODAN_INTERNETDB_SOURCE,
      target: ip,
      fetchedAt,
      expiresAt: fetchedAt + SHODAN_INTERNETDB_TTL_MS,
      rawJson,
      rawBytes: Buffer.byteLength(rawJson),
      status: "ok",
    });
    return output;
  } catch (error) {
    return {
      ok: false,
      source: SHODAN_INTERNETDB_SOURCE,
      ip,
      error: formatError(error),
    };
  } finally {
    if (closeCache) {
      cache.close();
    }
  }
}

async function fetchShodanHost(params: {
  ip: string;
  apiKey: string;
  includeBanners: boolean;
  history: boolean;
  signal?: AbortSignal;
}) {
  const url = new URL(`https://api.shodan.io/shodan/host/${encodeURIComponent(params.ip)}`);
  url.searchParams.set("key", params.apiKey);
  url.searchParams.set("minify", String(!params.includeBanners));
  url.searchParams.set("history", String(params.history));
  const guarded = await fetchWithSsrFGuard({
    url: url.toString(),
    init: {
      headers: {
        Accept: "application/json",
        "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
      },
    },
    timeoutMs: SHODAN_HOST_TIMEOUT_MS,
    signal: params.signal,
    auditContext: "openclaw-osint-shodan-host",
  });
  const { response, release } = guarded;
  try {
    if (response.status === 404) {
      return {
        ok: true,
        source: SHODAN_HOST_SOURCE,
        provider: "shodan",
        mode: "keyed_full",
        ip: params.ip,
        found: false,
        ports: [],
        hostnames: [],
        domains: [],
        tags: [],
        vulnerabilities: [],
        services: [],
        summary: {
          openPortCount: 0,
          vulnerabilityCount: 0,
          hostnameCount: 0,
          serviceCount: 0,
        },
        caveat: "Shodan has no host record for this IP.",
      };
    }
    if (!response.ok) {
      throw new Error(`Shodan host lookup returned HTTP ${response.status}`);
    }
    return formatShodanHostResponse(
      params.ip,
      JSON.parse(await readResponseTextBounded(response, MAX_RESPONSE_BYTES)),
      params.includeBanners,
    );
  } finally {
    await release();
  }
}

async function fetchShodanInternetDb(ip: string, signal?: AbortSignal) {
  const guarded = await fetchWithSsrFGuard({
    url: `https://internetdb.shodan.io/${encodeURIComponent(ip)}`,
    init: {
      headers: {
        Accept: "application/json",
        "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
      },
    },
    timeoutMs: SHODAN_INTERNETDB_TIMEOUT_MS,
    signal,
    auditContext: "openclaw-osint-shodan-internetdb",
  });
  const { response, release } = guarded;
  try {
    if (response.status === 404) {
      return {
        ok: true,
        source: SHODAN_INTERNETDB_SOURCE,
        ip,
        found: false,
        ports: [],
        hostnames: [],
        cpes: [],
        tags: [],
        vulnerabilities: [],
        summary: {
          openPortCount: 0,
          vulnerabilityCount: 0,
          hostnameCount: 0,
        },
        caveat: "Shodan InternetDB has no keyless host summary for this IP.",
      };
    }
    if (!response.ok) {
      throw new Error(`Shodan InternetDB returned HTTP ${response.status}`);
    }
    return formatInternetDbResponse(ip, JSON.parse(await readResponseTextBounded(response, MAX_RESPONSE_BYTES)));
  } finally {
    await release();
  }
}

function formatInternetDbResponse(ip: string, parsed: unknown) {
  const response = parsed && typeof parsed === "object" ? parsed as InternetDbResponse : {};
  const ports = numericArray(response.ports);
  const hostnames = stringArray(response.hostnames);
  const cpes = stringArray(response.cpes);
  const tags = stringArray(response.tags);
  const vulnerabilities = vulnerabilityIds(response.vulns);
  return {
    ok: true,
    source: SHODAN_INTERNETDB_SOURCE,
    ip,
    found: true,
    ports,
    hostnames,
    cpes,
    tags,
    vulnerabilities,
    summary: {
      openPortCount: ports.length,
      vulnerabilityCount: vulnerabilities.length,
      hostnameCount: hostnames.length,
      hasIndustrialTags: tags.some((tag) => ["ics", "scada", "plc"].includes(tag.toLowerCase())),
    },
    caveat:
      "Shodan InternetDB is a keyless summary service. It does not include full Shodan banners or prove current exploitability.",
  };
}

function formatShodanHostResponse(ip: string, parsed: unknown, includeBanners: boolean) {
  const response = parsed && typeof parsed === "object" ? parsed as ShodanHostResponse : {};
  const services = includeBanners ? serviceSummaries(response.data) : [];
  const vulnerabilities = vulnerabilityIds(response.vulns);
  const ports = numericArray(response.ports?.length ? response.ports : services.map((service) => service.port));
  const hostnames = stringArray(response.hostnames);
  const domains = stringArray(response.domains);
  const tags = stringArray(response.tags);
  return {
    ok: true,
    source: SHODAN_HOST_SOURCE,
    provider: "shodan",
    mode: "keyed_full",
    ip: response.ip_str ?? ip,
    found: true,
    ports,
    hostnames,
    domains,
    organization: response.org,
    isp: response.isp,
    asn: response.asn,
    countryCode: response.country_code,
    city: response.city,
    tags,
    vulnerabilities,
    services,
    summary: {
      openPortCount: ports.length,
      vulnerabilityCount: vulnerabilities.length,
      hostnameCount: hostnames.length,
      serviceCount: services.length,
      hasIndustrialTags: tags.some((tag) => ["ics", "scada", "plc"].includes(tag.toLowerCase())),
    },
    caveat:
      "Full Shodan host data is keyed, point-in-time scanner metadata. It does not prove current exploitability or ownership.",
  };
}

function serviceSummaries(value: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.slice(0, MAX_SERVICE_SUMMARIES).flatMap((service) => {
    if (!service || typeof service !== "object") {
      return [];
    }
    const row = service as Record<string, unknown>;
    return [{
      port: typeof row.port === "number" ? row.port : undefined,
      transport: stringValue(row.transport),
      product: stringValue(row.product),
      version: stringValue(row.version),
      module: stringValue(row._shodan, "module"),
      timestamp: stringValue(row.timestamp),
      ssl: summarizeSsl(row.ssl),
      http: summarizeHttp(row.http),
    }];
  });
}

function summarizeSsl(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const ssl = value as Record<string, unknown>;
  return {
    cipher: stringValue(ssl.cipher, "name") ?? stringValue(ssl.cipher),
    versions: stringArray(ssl.versions),
  };
}

function summarizeHttp(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const http = value as Record<string, unknown>;
  return {
    title: stringValue(http.title),
    server: stringValue(http.server),
    host: stringValue(http.host),
  };
}

function stringValue(value: unknown, key?: string): string | undefined {
  const raw = key && value && typeof value === "object" ? (value as Record<string, unknown>)[key] : value;
  return typeof raw === "string" && raw.length > 0 ? raw : undefined;
}

function vulnerabilityIds(value: unknown): string[] {
  if (Array.isArray(value)) {
    return stringArray(value);
  }
  if (value && typeof value === "object") {
    return stringArray(Object.keys(value));
  }
  return [];
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return Array.from(new Set(value.filter((item): item is string => typeof item === "string" && item.length > 0)))
    .slice(0, MAX_LIST_ITEMS);
}

function numericArray(value: unknown): number[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return Array.from(new Set(value.filter((item): item is number => Number.isInteger(item) && item > 0 && item <= 65535)))
    .sort((a, b) => a - b)
    .slice(0, MAX_LIST_ITEMS);
}

function normalizePublicIp(input: string): string | undefined {
  const ip = input.trim().toLowerCase();
  const version = isIP(ip);
  if (!version || isBlockedIp(ip)) {
    return undefined;
  }
  return ip;
}

function isBlockedIp(address: string): boolean {
  return isIP(address) === 6 ? isBlockedIpv6(address) : isBlockedIpv4(address);
}

function isBlockedIpv4(address: string): boolean {
  const value = ipv4ToNumber(address);
  return [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ].some(([base, prefix]) => ipv4InCidr(value, ipv4ToNumber(String(base)), Number(prefix)));
}

function isBlockedIpv6(address: string): boolean {
  const normalized = address.toLowerCase();
  return (
    normalized === "::1" ||
    normalized === "::" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80") ||
    normalized.startsWith("2001:db8") ||
    normalized.startsWith("ff")
  );
}

function ipv4InCidr(value: number, base: number, prefix: number): boolean {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (base & mask);
}

function ipv4ToNumber(address: string): number {
  return address.split(".").reduce((value, part) => ((value << 8) + Number(part)) >>> 0, 0);
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

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export const testing = {
  formatInternetDbResponse,
  formatShodanHostResponse,
  isBlockedIpv4,
  isBlockedIpv6,
  normalizePublicIp,
  queryShodanHostForTool,
  queryShodanInternetDbHostForTool,
};
