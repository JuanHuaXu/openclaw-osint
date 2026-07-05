import { Type, type Static } from "typebox";
import { queryBusinessReputationForTool } from "./business.js";
import { OsintCache } from "./cache.js";
import { detectCdnDdos } from "./cdn.js";
import { queryDomainAuthorityIntelForTool } from "./domain-authority.js";
import { queryDomainNetworkIntelForTool } from "./domain-network.js";
import {
  queryHibpEmailBreachForTool,
  queryPwnedPasswordHashForTool,
} from "./hibp.js";
import { queryIpAssignmentIntelForTool } from "./ip-assignment.js";
import { queryInfraReputationForTool, queryPhoneReputationForTool } from "./reputation.js";
import { queryShodanHostForTool } from "./shodan.js";
import { queryTlsCertificateChainForTool } from "./tls-certificate.js";
import {
  extractIndicatorsForTool,
  snapshotUrlForTool,
} from "./tools.js";

const DEFAULT_MAX_LOOKUPS = 3;
const MAX_LOOKUPS = 10;
const MAX_DERIVED_HOSTS = 100;

export const PipelineReconSchema = Type.Object(
  {
    text: Type.String({
      description: "Text, logs, URL list, transcript, or indicators to investigate.",
    }),
    effort: Type.Union([Type.Literal("light"), Type.Literal("medium"), Type.Literal("high")], {
      description: "Recon effort: light extracts only, medium adds URL and domain lookups, high runs the broader bounded safe suite.",
    }),
    maxLookups: Type.Optional(
      Type.Integer({
        description: "Maximum indicators per category to enrich. Defaults to 3, capped at 10.",
        minimum: 1,
        maximum: MAX_LOOKUPS,
      }),
    ),
    refresh: Type.Optional(Type.Boolean({ description: "Bypass fresh local cache where supported." })),
  },
  { additionalProperties: false },
);

type PipelineReconParams = Static<typeof PipelineReconSchema>;

export async function pipelineReconForTool(
  params: PipelineReconParams & { signal?: AbortSignal; cache?: OsintCache; skipHighExpansion?: boolean },
) {
  const maxLookups = Math.min(Math.max(params.maxLookups ?? DEFAULT_MAX_LOOKUPS, 1), MAX_LOOKUPS);
  const indicators = extractIndicatorsForTool({ text: params.text });
  const stages = ["extract_indicators"];
  if (params.effort === "light") {
    return {
      ok: true,
      effort: params.effort,
      stages,
      indicators,
      results: {},
      caveat: "Light recon is local-only and performs no network lookups.",
    };
  }

  const cache = params.cache ?? new OsintCache();
  const closeCache = !params.cache;
  try {
    const urls = indicators.urls.slice(0, maxLookups);
    const domains = indicators.domains.slice(0, maxLookups);
    const urlSnapshots = await Promise.all(
      urls.map((url) => snapshotUrlForTool({ url, signal: params.signal })),
    );
    const domainNetworkFull = await Promise.all(
      domains.map((domain) =>
        queryDomainNetworkIntelForTool({ domain, maxIps: 4, refresh: params.refresh, cache })
      ),
    );
    const domainNetwork = domainNetworkFull.map(compactDomainNetworkResult);
    stages.push("url_snapshot", "domain_network_intel");
    if (params.effort === "medium") {
      return {
        ok: true,
        effort: params.effort,
        stages,
        indicators,
        limits: { maxLookups },
        results: {
          urlSnapshots,
          domainNetwork,
        },
        caveat: "Medium recon enriches URLs and domains only; use high for broader indicator checks.",
      };
    }

    const domainAuthorityFull = await Promise.all(
      domains.map((domain) =>
        queryDomainAuthorityIntelForTool({ domain, maxContacts: maxLookups, refresh: params.refresh, signal: params.signal, cache })
      ),
    );
    const domainAuthority = domainAuthorityFull.map(compactDomainAuthorityResult);
    const ips = uniqueBounded([
      ...indicators.ipv4,
      ...domainNetworkFull.flatMap(dnsIpsFromDomainNetworkResult),
    ], maxLookups);
    const ipAssignmentsFull = params.skipHighExpansion ? [] : await Promise.all(
      ips.map((ip) =>
        queryIpAssignmentIntelForTool({ ip, maxContacts: maxLookups, refresh: params.refresh, signal: params.signal, cache })
      ),
    );
    const ipAssignments = ipAssignmentsFull.map(compactIpAssignmentResult);
    const contactIndicators = mergeDerivedIndicators(
      derivedIndicatorsFromAuthorityResults(domainAuthorityFull),
      derivedIndicatorsFromAuthorityResults(ipAssignmentsFull),
    );
    const emails = uniqueBounded([...indicators.emails, ...contactIndicators.emails], maxLookups);
    const phones = uniqueBounded(contactIndicators.phones, maxLookups);
    const hashes = indicators.hashes.slice(0, maxLookups);
    const [tlsCertificatesFull, infraReputation, shodanHost, hibpEmails, phoneReputation, pwnedHashes] = await Promise.all([
      Promise.all(
        domains.map((domain) =>
          queryTlsCertificateChainForTool({ host: domain })
        ),
      ),
      Promise.all(
        ips.map((ip) =>
          queryInfraReputationForTool({ ip, refresh: params.refresh, signal: params.signal, cache })
        ),
      ),
      Promise.all(
        ips.map((ip) =>
          queryShodanHostForTool({ ip, refresh: params.refresh, signal: params.signal, cache })
        ),
      ),
      params.skipHighExpansion ? Promise.resolve([]) : Promise.all(
        emails.map((email) =>
          queryHibpEmailBreachForTool({ email, refresh: params.refresh, signal: params.signal, cache })
        ),
      ),
      Promise.all(
        phones.map((phone) =>
          queryPhoneReputationForTool({
            phone,
            organizationDomain: domains[0],
            refresh: params.refresh,
            signal: params.signal,
            cache,
          })
        ),
      ).then((results) => results.map(compactPhoneReputationResult)),
      params.skipHighExpansion ? Promise.resolve([]) : Promise.all(
        hashes.map((hash) =>
          queryPwnedPasswordHashForTool({ hash, algorithm: "auto", signal: params.signal })
        ),
      ),
    ]);
    const derivedIndicators = mergeDerivedIndicators(
      hostIndicatorsFromInput(indicators),
      contactIndicators,
      derivedIndicatorsFromTlsResults(tlsCertificatesFull),
      derivedIndicatorsFromShodanResults(shodanHost),
    );
    const tlsCertificates = tlsCertificatesFull.map(compactTlsCertificateResult);
    const cdnDdosProtection = await Promise.all(
      domains.map((domain, index) =>
        detectCdnDdos({
          target: { url: `https://${domain}/`, domain },
          refresh: params.refresh,
          signal: params.signal,
          cache,
          network: domainNetworkFull[index],
          tls: tlsCertificatesFull[index],
        })
      ),
    );
    const businessNames = businessNamesFromWhoisEvidence(
      domainNetworkFull,
      domainAuthorityFull,
      ipAssignmentsFull,
      shodanHost,
    ).slice(0, maxLookups);
    const businessReputation = await Promise.all(
      businessNames.map((business) =>
        queryBusinessReputationForTool({
          business,
          domain: domains[0],
          maxResults: maxLookups,
          refresh: params.refresh,
          signal: params.signal,
          cache,
        })
      ),
    );
    stages.push("domain_authority_intel", "ip_assignment_intel", "tls_certificate_chain", "cdn_ddos_detect", "business_reputation_lookup", "infra_reputation", "shodan_host", "hibp_email_breach", "phone_reputation", "pwned_password_hash");
    return {
      ok: true,
      effort: params.effort,
      stages,
      indicators,
      limits: { maxLookups },
      results: {
        urlSnapshots,
        domainNetwork,
        domainAuthority,
        ipAssignments,
        tlsCertificates,
        cdnDdosProtection,
        businessReputation,
        derivedIndicators,
        infraReputation,
        shodanHost,
        hibpEmails,
        phoneReputation,
        pwnedHashes,
        deferredSources: [
          {
            source: "crt.sh",
            tool: "osint_crtsh_domain",
            reason: "Certificate transparency lookup is intentionally not run by default in high pipeline because crt.sh is frequently slow or unavailable. Use the standalone tool when CT history is specifically needed.",
          },
        ],
      },
      caveat:
        "High recon is bounded by maxLookups and available API keys. HIBP email checks require HIBP_API_KEY; failed keyed checks are returned as errors.",
    };
  } finally {
    if (closeCache) {
      cache.close();
    }
  }
}

function businessNamesFromWhoisEvidence(...sources: readonly unknown[]): string[] {
  return uniqueBounded(
    sources.flatMap((source) => [
      ...businessValuesAt(source, ["bgp", "asName"]),
      ...businessValuesAt(source, ["summary", "name"]),
      ...businessValuesAt(source, ["rdap", "summary", "name"]),
      ...businessValuesAt(source, ["rdap", "summary", "entities", "fn"]),
      ...businessValuesAt(source, ["organization"]),
      ...businessValuesAt(source, ["org"]),
    ]).map(cleanBusinessCandidate).filter((value): value is string => Boolean(value)),
    MAX_LOOKUPS,
  );
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

function cleanBusinessCandidate(value: string): string | undefined {
  const cleaned = value.replace(/\s+/g, " ").trim();
  if (cleaned.length < 2 || cleaned.length > 120) {
    return undefined;
  }
  if (/^(n\/a|none|unknown|private|redacted)$/i.test(cleaned)) {
    return undefined;
  }
  return cleaned;
}

function uniqueBounded(values: readonly string[], limit: number): string[] {
  return Array.from(new Set(values)).slice(0, limit);
}

function dnsIpsFromDomainNetworkResult(result: unknown): string[] {
  if (!result || typeof result !== "object" || !("dns" in result) || !Array.isArray(result.dns)) {
    return [];
  }
  return result.dns.flatMap((record) =>
    record && typeof record === "object" && "address" in record && typeof record.address === "string"
      ? [record.address]
      : []
  );
}

function derivedIndicatorsFromAuthorityResults(results: readonly unknown[]) {
  return {
    emails: uniqueBounded(
      results.flatMap((result) => indicatorValues(result, "emails")),
      MAX_LOOKUPS,
    ),
    phones: uniqueBounded(
      results.flatMap((result) => indicatorValues(result, "phones")),
      MAX_LOOKUPS,
    ),
  };
}

function mergeDerivedIndicators(
  ...items: Array<{
    emails?: readonly string[];
    phones?: readonly string[];
    hosts?: readonly string[];
    ipAddresses?: readonly string[];
  }>
) {
  return {
    emails: uniqueBounded(items.flatMap((item) => item.emails ?? []), MAX_LOOKUPS),
    phones: uniqueBounded(items.flatMap((item) => item.phones ?? []), MAX_LOOKUPS),
    hosts: uniqueBounded(items.flatMap((item) => item.hosts ?? []), MAX_DERIVED_HOSTS),
    ipAddresses: uniqueBounded(items.flatMap((item) => item.ipAddresses ?? []), MAX_LOOKUPS),
  };
}

function hostIndicatorsFromInput(indicators: { domains: readonly string[]; emails: readonly string[] }) {
  return {
    hosts: uniqueBounded([
      ...indicators.domains,
      ...indicators.emails.flatMap((email) => emailDomain(email)),
    ], MAX_DERIVED_HOSTS),
  };
}

function derivedIndicatorsFromTlsResults(results: readonly unknown[]) {
  return {
    hosts: uniqueBounded(
      results.flatMap((result) => indicatorValues(result, "hosts")),
      MAX_DERIVED_HOSTS,
    ),
    ipAddresses: uniqueBounded(
      results.flatMap((result) => indicatorValues(result, "ipAddresses")),
      MAX_LOOKUPS,
    ),
  };
}

function derivedIndicatorsFromShodanResults(results: readonly unknown[]) {
  return {
    hosts: uniqueBounded(
      results.flatMap((result) => hostnameValues(result, "hostnames")),
      MAX_DERIVED_HOSTS,
    ),
  };
}

function indicatorValues(result: unknown, key: "emails" | "phones" | "hosts" | "ipAddresses"): string[] {
  if (!result || typeof result !== "object" || !("derivedIndicators" in result)) {
    return [];
  }
  const derived = result.derivedIndicators as Record<string, unknown>;
  const values = derived[key];
  if (!Array.isArray(values)) {
    return [];
  }
  return values.filter((value): value is string => typeof value === "string");
}

function hostnameValues(value: unknown, key: string): string[] {
  if (!value || typeof value !== "object" || !(key in value)) {
    return [];
  }
  const array = (value as Record<string, unknown>)[key];
  return Array.isArray(array) ? array.flatMap(normalizeHostname) : [];
}

function emailDomain(email: string): string[] {
  const domain = email.split("@")[1]?.trim().toLowerCase();
  return domain ? [domain] : [];
}

function normalizeHostname(value: unknown): string[] {
  if (typeof value !== "string") {
    return [];
  }
  const host = value.trim().toLowerCase().replace(/\.$/, "");
  if (!host || host.length > 253 || host.includes("..") || !host.includes(".")) {
    return [];
  }
  return /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host) ? [host] : [];
}

function compactDomainNetworkResult(result: unknown): unknown {
  if (!result || typeof result !== "object") {
    return result;
  }
  const source = result as Record<string, unknown>;
  if (source.ok !== true) {
    return result;
  }
  return {
    ok: true,
    domain: source.domain,
    dns: source.dns,
    bgp: source.bgp,
    ipAssignments: Array.isArray(source.ipAssignments)
      ? source.ipAssignments.map(compactIpAssignmentResult)
      : source.ipAssignments,
    summary: source.summary,
    correlatedPaths: Array.isArray(source.correlatedPaths)
      ? source.correlatedPaths.map(compactCorrelatedPath)
      : source.correlatedPaths,
    traceroute: source.traceroute,
    sources: source.sources,
    caveat: source.caveat,
  };
}

function compactCorrelatedPath(result: unknown): unknown {
  if (!result || typeof result !== "object") {
    return result;
  }
  const source = result as Record<string, unknown>;
  return {
    ...source,
    ipAssignment: compactIpAssignmentResult(source.ipAssignment),
  };
}

function compactDomainAuthorityResult(result: unknown): unknown {
  if (!result || typeof result !== "object") {
    return result;
  }
  const source = result as Record<string, unknown>;
  if (source.ok !== true) {
    return result;
  }
  return {
    ok: true,
    source: source.source,
    inputDomain: source.inputDomain,
    registeredDomain: source.registeredDomain,
    cacheStatus: source.cacheStatus,
    dnsAuthority: source.dnsAuthority,
    rdap: compactRdapResult(source.rdap),
    sources: source.sources,
    caveat: source.caveat,
  };
}

function compactRdapResult(result: unknown): unknown {
  if (!result || typeof result !== "object") {
    return result;
  }
  const source = result as Record<string, unknown>;
  return {
    ok: source.ok,
    rdapUrl: source.rdapUrl,
    summary: source.summary,
    error: source.error,
  };
}

function compactPhoneReputationResult(result: unknown): unknown {
  if (!result || typeof result !== "object") {
    return result;
  }
  const source = result as Record<string, unknown>;
  if (source.ok !== true) {
    return result;
  }
  return {
    ok: true,
    source: source.source,
    attribution: source.attribution,
    phone: source.phone,
    sourceStatuses: source.sourceStatuses,
    complaintCount: source.complaintCount,
    robocallCount: source.robocallCount,
    numberingPlan: source.numberingPlan,
    networkCorrelation: compactPhoneNetworkCorrelation(source.networkCorrelation),
    confidence: source.confidence,
    ownerClassHint: source.ownerClassHint,
    caveat: source.caveat,
  };
}

function compactPhoneNetworkCorrelation(result: unknown): unknown {
  if (!result || typeof result !== "object") {
    return result;
  }
  const source = result as Record<string, unknown>;
  const networkIntel = source.networkIntel && typeof source.networkIntel === "object"
    ? source.networkIntel as Record<string, unknown>
    : undefined;
  return {
    organizationDomain: source.organizationDomain,
    status: source.status,
    basis: source.basis,
    networkSummary: networkIntel?.summary,
  };
}

function compactIpAssignmentResult(result: unknown): unknown {
  if (!result || typeof result !== "object") {
    return result;
  }
  const source = result as Record<string, unknown>;
  if (source.ok !== true) {
    return result;
  }
  return {
    ok: true,
    source: source.source,
    ip: source.ip,
    registryHint: source.registryHint,
    rdapUrl: source.rdapUrl,
    summary: source.summary,
    caveat: source.caveat,
  };
}

function compactTlsCertificateResult(result: unknown): unknown {
  if (!result || typeof result !== "object") {
    return result;
  }
  const source = result as Record<string, unknown>;
  if (source.ok !== true) {
    return result;
  }
  return {
    ok: true,
    host: source.host,
    port: source.port,
    authorized: source.authorized,
    authorizationError: source.authorizationError,
    protocol: source.protocol,
    cipher: source.cipher,
    resolvedAddresses: source.resolvedAddresses,
    chain: source.chain,
    operatorCommand: source.operatorCommand,
    caveat: source.caveat,
  };
}
