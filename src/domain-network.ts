import { promises as dns } from "node:dns";
import { Socket } from "node:net";
import { Type, type Static } from "typebox";
import { OsintCache } from "./cache.js";

const BGPTOOLS_SOURCE = "bgp-tools-whois";
const BGPTOOLS_TTL_MS = 6 * 60 * 60 * 1000;
const DNS_TIMEOUT_MS = 5_000;
const BGPTOOLS_TIMEOUT_MS = 8_000;
const DEFAULT_MAX_IPS = 8;
const MAX_IPS = 20;

export const DomainNetworkIntelSchema = Type.Object(
  {
    domain: Type.String({
      description: "Domain to resolve and enrich with passive BGP/network ownership data.",
    }),
    maxIps: Type.Optional(
      Type.Integer({
        description: "Maximum resolved IPs to enrich.",
        minimum: 1,
        maximum: MAX_IPS,
      }),
    ),
    includeTraceroutePlan: Type.Optional(
      Type.Boolean({
        description:
          "Include safe operator traceroute commands. The plugin does not run traceroute itself.",
      }),
    ),
    refresh: Type.Optional(
      Type.Boolean({
        description: "Refresh cached bgp.tools WHOIS results.",
      }),
    ),
  },
  { additionalProperties: false },
);

type DomainNetworkIntelParams = Static<typeof DomainNetworkIntelSchema>;

type BgpToolsRow = {
  asn: string;
  ip: string;
  prefix: string;
  countryCode: string;
  registry: string;
  allocated: string;
  asName: string;
};

export async function queryDomainNetworkIntelForTool(
  params: DomainNetworkIntelParams & { cache?: OsintCache },
) {
  const domain = normalizeDomain(params.domain);
  if (!domain) {
    return { ok: false, error: "Expected a DNS domain." };
  }
  const maxIps = Math.min(Math.max(params.maxIps ?? DEFAULT_MAX_IPS, 1), MAX_IPS);
  const cache = params.cache ?? new OsintCache();
  const closeCache = !params.cache;
  try {
    const dnsRecords = await resolveDomainIps(domain, maxIps);
    const bgp = [];
    for (const ip of dnsRecords.map((record) => record.address)) {
      bgp.push(await queryBgpToolsWithCache(ip, cache, Boolean(params.refresh)));
    }
    return {
      ok: true,
      domain,
      dns: dnsRecords,
      bgp,
      traceroute: params.includeTraceroutePlan ? traceroutePlan(domain, dnsRecords) : undefined,
      sources: [
        "local DNS resolver",
        "bgp.tools WHOIS automation interface on TCP/43",
        ...(params.includeTraceroutePlan ? ["operator-side traceroute plan"] : []),
      ],
      caveat:
        "DNS and BGP data are point-in-time routing observations. CDN/anycast domains may return different IPs from other networks.",
    };
  } finally {
    if (closeCache) {
      cache.close();
    }
  }
}

async function resolveDomainIps(domain: string, maxIps: number) {
  const [v4, v6] = await Promise.all([
    withTimeout(resolve4WithTtl(domain), DNS_TIMEOUT_MS).catch(() => []),
    withTimeout(resolve6WithTtl(domain), DNS_TIMEOUT_MS).catch(() => []),
  ]);
  return [...v4, ...v6].slice(0, maxIps);
}

async function resolve4WithTtl(domain: string): Promise<Array<{ family: 4; address: string; ttl?: number }>> {
  const records = await dns.resolve4(domain, { ttl: true });
  return records.map((record) => ({ family: 4, address: record.address, ttl: record.ttl }));
}

async function resolve6WithTtl(domain: string): Promise<Array<{ family: 6; address: string; ttl?: number }>> {
  const records = await dns.resolve6(domain, { ttl: true });
  return records.map((record) => ({ family: 6, address: record.address, ttl: record.ttl }));
}

async function queryBgpToolsWithCache(
  ip: string,
  cache: OsintCache,
  refresh: boolean,
): Promise<BgpToolsRow | { ip: string; error: string }> {
  const fresh = refresh ? undefined : cache.getFreshSource(BGPTOOLS_SOURCE, ip);
  if (fresh) {
    return JSON.parse(fresh.rawJson) as BgpToolsRow;
  }
  try {
    const row = parseBgpToolsWhois(await queryBgpToolsWhois(ip));
    const fetchedAt = Date.now();
    cache.putSource({
      source: BGPTOOLS_SOURCE,
      target: ip,
      fetchedAt,
      expiresAt: fetchedAt + BGPTOOLS_TTL_MS,
      rawJson: JSON.stringify(row),
      rawBytes: Buffer.byteLength(JSON.stringify(row)),
      status: "ok",
    });
    return row;
  } catch (error) {
    return { ip, error: formatError(error) };
  }
}

function queryBgpToolsWhois(ip: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = new Socket();
    let output = "";
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      if (error) {
        reject(error);
      } else {
        resolve(output);
      }
    };
    socket.setEncoding("utf8");
    socket.setTimeout(BGPTOOLS_TIMEOUT_MS);
    socket.on("data", (chunk) => {
      output += chunk;
    });
    socket.on("error", (error) => finish(error));
    socket.on("timeout", () => finish(new Error("bgp.tools WHOIS timed out")));
    socket.on("end", () => finish());
    socket.connect({ host: "bgp.tools", port: 43 }, () => {
      socket.end(` -v ${ip}\n`);
    });
  });
}

function parseBgpToolsWhois(input: string): BgpToolsRow {
  const row = input
    .split(/\r?\n/g)
    .map((line) => line.trim())
    .find((line) => /^\d+\s*\|/.test(line));
  if (!row) {
    throw new Error("No bgp.tools WHOIS data row returned.");
  }
  const [asn, ip, prefix, countryCode, registry, allocated, asName] = row
    .split("|")
    .map((part) => part.trim());
  return {
    asn: asn ?? "",
    ip: ip ?? "",
    prefix: prefix ?? "",
    countryCode: countryCode ?? "",
    registry: registry ?? "",
    allocated: allocated ?? "",
    asName: asName ?? "",
  };
}

function traceroutePlan(
  domain: string,
  records: ReadonlyArray<{ address: string }>,
) {
  return {
    automated: false,
    reason:
      "The OSINT plugin does not run traceroute or shell commands. Traceroute is active probing and should be operator-initiated.",
    targets: records.map((record) => record.address),
    commands: [`traceroute ${domain}`, ...records.slice(0, 3).map((record) => `traceroute ${record.address}`)],
    caveat:
      "Traceroute is path-dependent and may reveal the operator network location. Run it only from an intended vantage point.",
  };
}

function normalizeDomain(input: string): string | undefined {
  const value = input.trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/?#]/, 1)[0] ?? "";
  if (value.length > 253 || !value.includes(".") || value.includes("..")) {
    return undefined;
  }
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value)) {
    return undefined;
  }
  return value;
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("DNS lookup timed out")), timeoutMs);
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

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export const testing = {
  normalizeDomain,
  parseBgpToolsWhois,
  traceroutePlan,
};
