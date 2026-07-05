import { promises as dns } from "node:dns";
import { isIP, Socket } from "node:net";
import { Type, type Static } from "typebox";
import { OsintCache } from "./cache.js";
import { queryIpAssignmentIntelForTool } from "./ip-assignment.js";
import { publicKnowledgeQueriesForBusiness, queryPublicKnowledgeContextForTool } from "./public-knowledge.js";

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
    const ipAssignments = [];
    for (const ip of dnsRecords.map((record) => record.address)) {
      bgp.push(await queryBgpToolsWithCache(ip, cache, Boolean(params.refresh)));
      ipAssignments.push(await queryIpAssignmentIntelForTool({ ip, refresh: params.refresh, cache }));
    }
    const traceroute = params.includeTraceroutePlan ? traceroutePlan(domain, dnsRecords) : undefined;
    const publicKnowledgeContext = await publicKnowledgeForNetworkOwners(bgp, ipAssignments);
    return {
      ok: true,
      domain,
      dns: dnsRecords,
      bgp,
      ipAssignments,
      publicKnowledgeContext,
      summary: summarizeNetworkIntel(dnsRecords, bgp, Boolean(traceroute), ipAssignments),
      correlatedPaths: correlateNetworkPaths(dnsRecords, bgp, traceroute, ipAssignments),
      traceroute,
      sources: [
        "local DNS resolver",
        "bgp.tools WHOIS automation interface on TCP/43",
        "IANA IP RDAP bootstrap plus RIR RDAP allocation records",
        "Wikidata/Wikipedia public-knowledge context for network owner names",
        ...(params.includeTraceroutePlan ? ["operator-side traceroute plan"] : []),
      ],
      caveat:
        "DNS and BGP data are point-in-time routing observations. Wikidata/Wikipedia context is a lead, not routing or ownership proof. CDN/anycast domains may return different IPs from other networks.",
    };
  } finally {
    if (closeCache) {
      cache.close();
    }
  }
}

export async function queryObservedIpsNetworkIntelForTool(
  params: { ips: readonly string[]; refresh?: boolean; cache?: OsintCache },
) {
  const records = Array.from(new Set(params.ips.map(normalizeIp).filter(isString))).map((address) => ({
    family: isIP(address) === 6 ? 6 as const : 4 as const,
    address,
  }));
  const cache = params.cache ?? new OsintCache();
  const closeCache = !params.cache;
  try {
    const bgp = [];
    const ipAssignments = [];
    for (const ip of records.map((record) => record.address)) {
      bgp.push(await queryBgpToolsWithCache(ip, cache, Boolean(params.refresh)));
      ipAssignments.push(await queryIpAssignmentIntelForTool({ ip, refresh: params.refresh, cache }));
    }
    const publicKnowledgeContext = await publicKnowledgeForNetworkOwners(bgp, ipAssignments);
    return {
      ok: true,
      ips: records.map((record) => record.address),
      bgp,
      ipAssignments,
      publicKnowledgeContext,
      summary: summarizeNetworkIntel(records, bgp, false, ipAssignments),
      correlatedPaths: correlateNetworkPaths(records, bgp, undefined, ipAssignments),
      caveat:
        "Observed SIP/RTP IPs are operator-supplied evidence. Wikidata/Wikipedia context is a lead, not routing or ownership proof. BGP data identifies routing/network ownership, not subscriber identity.",
    };
  } finally {
    if (closeCache) {
      cache.close();
    }
  }
}

async function publicKnowledgeForNetworkOwners(bgp: readonly unknown[], ipAssignments: readonly unknown[]) {
  const queries = uniqueBounded([
    ...businessValuesAt(bgp, ["asName"]),
    ...businessValuesAt(ipAssignments, ["summary", "name"]),
    ...businessValuesAt(ipAssignments, ["organization"]),
    ...businessValuesAt(ipAssignments, ["org"]),
  ].flatMap(publicKnowledgeQueriesForBusiness), 4);
  return queryPublicKnowledgeContextForTool({ queries, maxRelated: 4 });
}

function businessValuesAt(value: unknown, path: readonly string[]): string[] {
  if (path.length === 0) {
    return typeof value === "string" ? [value] : [];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item) => businessValuesAt(item, path));
  }
  if (!value || typeof value !== "object") {
    return [];
  }
  const [key, ...rest] = path;
  return key ? businessValuesAt((value as Record<string, unknown>)[key], rest) : [];
}

function uniqueBounded(values: readonly string[], limit: number): string[] {
  return Array.from(new Set(values.map(cleanBusinessCandidate).filter((value): value is string => Boolean(value)))).slice(0, limit);
}

function cleanBusinessCandidate(value: string): string | undefined {
  const cleaned = value.replace(/\s+/g, " ").trim();
  if (cleaned.length < 2 || cleaned.length > 120 || /^\d+$/.test(cleaned)) {
    return undefined;
  }
  return cleaned;
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

function summarizeNetworkIntel(
  records: ReadonlyArray<{ family: 4 | 6; address: string }>,
  bgp: ReadonlyArray<BgpToolsRow | { ip: string; error: string }>,
  hasTraceroutePlan: boolean,
  ipAssignments: ReadonlyArray<unknown> = [],
) {
  const successful = bgp.filter(isBgpToolsRow);
  const successfulAssignments = ipAssignments.filter(isSuccessfulIpAssignment);
  const asns = Array.from(new Map(successful.map((row) => [row.asn, row])).values());
  const families = Array.from(new Set(records.map((record) => record.family))).sort();
  return {
    resolvedIpCount: records.length,
    dnsFamilies: families,
    bgpResolvedCount: successful.length,
    bgpErrorCount: bgp.length - successful.length,
    ipAssignmentResolvedCount: successfulAssignments.length,
    ipAssignmentErrorCount: ipAssignments.length - successfulAssignments.length,
    asnCount: asns.length,
    primaryAsns: asns.map((row) => `AS${row.asn} ${row.asName}`),
    registries: Array.from(new Set(successfulAssignments.flatMap((row) => row.registryHint ?? []))),
    networkShape: inferNetworkShape(records, successful),
    tracerouteAvailable: hasTraceroutePlan ? "operator_plan_only" : "not_requested",
  };
}

function correlateNetworkPaths(
  records: ReadonlyArray<{ family: 4 | 6; address: string; ttl?: number }>,
  bgp: ReadonlyArray<BgpToolsRow | { ip: string; error: string }>,
  traceroute?: ReturnType<typeof traceroutePlan>,
  ipAssignments: ReadonlyArray<unknown> = [],
) {
  return records.map((record) => {
    const bgpRow = bgp.find((row) => row.ip === record.address);
    const assignment = ipAssignments.find((row) =>
      row && typeof row === "object" && "ip" in row && row.ip === record.address
    );
    const bgpValue = bgpRow
      ? isBgpToolsRow(bgpRow)
        ? {
            asn: bgpRow.asn,
            prefix: bgpRow.prefix,
            asName: bgpRow.asName,
            countryCode: bgpRow.countryCode,
            registry: bgpRow.registry,
            allocated: bgpRow.allocated,
          }
        : { error: bgpRow.error }
      : undefined;
    return {
      ip: record.address,
      dns: {
        family: record.family,
        ...(record.ttl !== undefined ? { ttl: record.ttl } : {}),
      },
      ...(bgpValue ? { bgp: bgpValue } : {}),
      ...(assignment ? { ipAssignment: compactIpAssignment(assignment) } : {}),
      trace: {
        automated: false,
        status: "not_run",
        ...(traceroute?.commands.includes(`traceroute ${record.address}`)
          ? { operatorCommand: `traceroute ${record.address}` }
          : {}),
      },
      assessment: assessPathRole(bgpValue),
    };
  });
}

function inferNetworkShape(
  records: ReadonlyArray<{ family: 4 | 6 }>,
  bgp: ReadonlyArray<BgpToolsRow>,
): string {
  const asnNames = bgp.map((row) => row.asName.toLowerCase());
  if (asnNames.some((name) => /cloudflare|akamai|fastly|cloudfront|cdn|edgecast|bunny/.test(name))) {
    return "cdn_or_anycast_likely";
  }
  if (new Set(bgp.map((row) => row.asn)).size > 1) {
    return "multi_asn_hosting";
  }
  if (records.some((record) => record.family === 4) && records.some((record) => record.family === 6)) {
    return "dual_stack_single_network";
  }
  return bgp.length > 0 ? "single_network" : "dns_only";
}

function assessPathRole(bgp?: { asName?: string; error?: string }) {
  if (!bgp || bgp.error) {
    return { role: "unclassified", confidence: 0.1 };
  }
  const asName = bgp.asName?.toLowerCase() ?? "";
  if (/cloudflare|akamai|fastly|cloudfront|cdn|edgecast|bunny/.test(asName)) {
    return { role: "edge_or_cdn_endpoint", confidence: 0.75 };
  }
  if (/hosting|cloud|amazon|google|microsoft|digitalocean|linode|hetzner/.test(asName)) {
    return { role: "cloud_or_hosting_endpoint", confidence: 0.65 };
  }
  return { role: "network_endpoint", confidence: 0.45 };
}

function isBgpToolsRow(row: BgpToolsRow | { ip: string; error: string }): row is BgpToolsRow {
  return "asn" in row;
}

function isSuccessfulIpAssignment(row: unknown): row is { ok: true; registryHint?: string } {
  return Boolean(row && typeof row === "object" && "ok" in row && row.ok === true);
}

function compactIpAssignment(row: unknown): unknown {
  if (!row || typeof row !== "object") {
    return row;
  }
  const value = row as Record<string, unknown>;
  if (value.ok !== true) {
    return value;
  }
  return {
    ok: true,
    registryHint: value.registryHint,
    rdapUrl: value.rdapUrl,
    summary: value.summary,
    derivedIndicators: value.derivedIndicators,
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

function normalizeIp(input: string): string | undefined {
  const value = input.trim();
  return isIP(value) ? value : undefined;
}

function isString(value: string | undefined): value is string {
  return typeof value === "string";
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
  correlateNetworkPaths,
  inferNetworkShape,
  normalizeDomain,
  normalizeIp,
  parseBgpToolsWhois,
  summarizeNetworkIntel,
  traceroutePlan,
};
