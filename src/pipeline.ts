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
import {
  publicKnowledgeBusinessNames,
  publicKnowledgeQueriesForDomain,
  publicKnowledgeTickers,
  queryPublicKnowledgeContextForTool,
} from "./public-knowledge.js";
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
const PIPELINE_OUTPUT_TARGET_CHARS = 30_000;
const PIPELINE_BUDGET_ARRAY_LIMIT = 3;

export const PipelineReconSchema = Type.Object(
  {
    text: Type.Optional(Type.String({
      description: "Canonical input: text, logs, URL list, transcript, or indicators to investigate.",
    })),
    target: Type.Optional(Type.String({
      description: "Alias for text. Use this when the request is phrased as a target URL, domain, actor, or indicator list.",
    })),
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
  const text = normalizePipelineInput(params);
  if (!text) {
    return {
      ok: false,
      source: "osint-pipeline",
      error: "Expected text or target input for OSINT pipeline recon.",
    };
  }
  const indicators = extractIndicatorsForTool({ text });
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
    const publicKnowledgeContext = await Promise.all(
      domains.map((domain) =>
        queryPublicKnowledgeContextForTool({
          queries: publicKnowledgeQueriesForDomain(domain),
          maxRelated: maxLookups,
          signal: params.signal,
        })
      ),
    );
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
          publicKnowledgeContext,
        },
        caveat: "Medium recon enriches URLs, domains, and public-knowledge context only; use high for broader indicator checks.",
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
    const phones = uniqueBounded(indicators.phones, maxLookups);
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
      publicKnowledgeContext,
    ).slice(0, maxLookups);
    const publicKnowledgeTicker = uniqueBounded(publicKnowledgeContext.flatMap(publicKnowledgeTickers), 1)[0];
    const businessReputation = await Promise.all(
      businessNames.map((business) =>
        queryBusinessReputationForTool({
          business,
          domain: domains[0],
          ...(publicKnowledgeTicker ? { ticker: publicKnowledgeTicker } : {}),
          maxResults: maxLookups,
          refresh: params.refresh,
          signal: params.signal,
          cache,
        })
      ),
    );
    const businessReputationSummary = summarizeBusinessReputationResults(businessReputation);
    const compactBusinessReputation = businessReputation.map(compactBusinessReputationResult);
    stages.push("domain_authority_intel", "ip_assignment_intel", "tls_certificate_chain", "cdn_ddos_detect", "business_reputation_lookup", "infra_reputation", "shodan_host", "hibp_email_breach", "phone_reputation", "pwned_password_hash");
    return fitPipelineOutputBudget({
      ok: true,
      effort: params.effort,
      stages,
      indicators,
      limits: { maxLookups },
      keyFindings: buildPipelineKeyFindings({
        businessReputationSummary,
        execution: {
          phoneReputationRan: phones.length > 0,
          phoneReputationInputCount: phones.length,
          outputTruncationMarkerPresent: false,
        },
      }),
      results: {
        urlSnapshots,
        domainNetwork,
        domainAuthority,
        ipAssignments,
        tlsCertificates,
        cdnDdosProtection,
        publicKnowledgeContext,
        businessReputationSummary,
        businessReputation: compactBusinessReputation,
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
    });
  } finally {
    if (closeCache) {
      cache.close();
    }
  }
}

function normalizePipelineInput(params: Pick<PipelineReconParams, "text" | "target">): string | undefined {
  const text = params.text?.trim() || params.target?.trim();
  return text || undefined;
}

function businessNamesFromWhoisEvidence(...sources: readonly unknown[]): string[] {
  return uniqueBounded(
    sources.flatMap((source) => [
      ...publicKnowledgeBusinessNames(source),
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
  if (/^[A-Z0-9-]+$/.test(cleaned) && (/\d/.test(cleaned) || cleaned.split("-").length > 2)) {
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

function fitPipelineOutputBudget<T extends { results?: Record<string, unknown>; limits?: Record<string, unknown> }>(
  result: T,
): T {
  const originalChars = measurePipelineOutputChars(result);
  if (originalChars <= PIPELINE_OUTPUT_TARGET_CHARS || !result.results) {
    return result;
  }
  const compacted = {
    ...result,
    limits: {
      ...result.limits,
      outputMode: "compacted",
      outputCompacted: true,
      outputTargetChars: PIPELINE_OUTPUT_TARGET_CHARS,
      outputTruncationMarkerPresent: false,
      originalChars,
    },
    results: compactPipelineResultsForBudget(result.results),
  };
  const compactedChars = measurePipelineOutputChars(compacted);
  if (compactedChars <= PIPELINE_OUTPUT_TARGET_CHARS) {
    return {
      ...compacted,
      limits: {
        ...compacted.limits,
        compactedChars,
      },
    } as T;
  }
  const summaryOnly = {
    ...compacted,
    limits: {
      ...compacted.limits,
      compactedChars,
      outputMode: "summary_only",
      summaryOnly: true,
    },
    results: summarizePipelineResultsForBudget(result.results),
  };
  return {
    ...summaryOnly,
    limits: {
      ...summaryOnly.limits,
      summaryChars: measurePipelineOutputChars(summaryOnly),
    },
  } as T;
}

function measurePipelineOutputChars(value: unknown): number {
  return JSON.stringify(value, null, 2).length;
}

function compactPipelineResultsForBudget(results: Record<string, unknown>): Record<string, unknown> {
  return {
    ...results,
    urlSnapshots: compactArray(results.urlSnapshots, compactUrlSnapshotForBudget),
    domainNetwork: compactArray(results.domainNetwork, compactDomainNetworkForBudget),
    domainAuthority: compactArray(results.domainAuthority, compactDomainAuthorityForBudget),
    ipAssignments: compactArray(results.ipAssignments, compactIdentityForBudget),
    tlsCertificates: compactArray(results.tlsCertificates, compactTlsCertificateForBudget),
    cdnDdosProtection: compactArray(results.cdnDdosProtection, compactIdentityForBudget),
    publicKnowledgeContext: compactArray(results.publicKnowledgeContext, compactPublicKnowledgeForBudget),
    businessReputation: compactArray(results.businessReputation, compactIdentityForBudget),
    infraReputation: compactArray(results.infraReputation, compactIdentityForBudget),
    shodanHost: compactArray(results.shodanHost, compactIdentityForBudget),
    hibpEmails: compactArray(results.hibpEmails, compactIdentityForBudget),
    phoneReputation: compactArray(results.phoneReputation, compactIdentityForBudget),
    pwnedHashes: compactArray(results.pwnedHashes, compactIdentityForBudget),
    derivedIndicators: compactDerivedIndicatorsForBudget(results.derivedIndicators),
    omittedResultCounts: omittedResultCounts(results),
  };
}

function compactArray(value: unknown, compact: (value: unknown) => unknown): unknown {
  return Array.isArray(value) ? value.slice(0, PIPELINE_BUDGET_ARRAY_LIMIT).map(compact) : value;
}

function omittedResultCounts(results: Record<string, unknown>): Record<string, number> {
  return Object.fromEntries(
    Object.entries(results)
      .filter(([, value]) => Array.isArray(value) && value.length > PIPELINE_BUDGET_ARRAY_LIMIT)
      .map(([key, value]) => [key, (value as unknown[]).length - PIPELINE_BUDGET_ARRAY_LIMIT]),
  );
}

function summarizePipelineResultsForBudget(results: Record<string, unknown>): Record<string, unknown> {
  return {
    resultCounts: Object.fromEntries(
      Object.entries(results).filter(([, value]) => Array.isArray(value)).map(([key, value]) => [key, (value as unknown[]).length]),
    ),
    businessReputationSummary: compactArray(results.businessReputationSummary, compactIdentityForBudget),
    derivedIndicators: compactDerivedIndicatorsForBudget(results.derivedIndicators),
    deferredSources: results.deferredSources,
  };
}

function compactIdentityForBudget(value: unknown): unknown {
  return value;
}

function compactUrlSnapshotForBudget(value: unknown): unknown {
  if (!value || typeof value !== "object") {
    return value;
  }
  const source = value as Record<string, unknown>;
  return {
    ok: source.ok,
    url: source.url,
    finalUrl: source.finalUrl,
    status: source.status,
    contentType: source.contentType,
    title: source.title,
    canonicalUrl: source.canonicalUrl,
    truncated: source.truncated,
  };
}

function compactDomainNetworkForBudget(value: unknown): unknown {
  if (!value || typeof value !== "object") {
    return value;
  }
  const source = value as Record<string, unknown>;
  return {
    ok: source.ok,
    domain: source.domain,
    dns: source.dns,
    bgp: source.bgp,
    summary: source.summary,
    sources: source.sources,
    caveat: source.caveat,
  };
}

function compactDomainAuthorityForBudget(value: unknown): unknown {
  if (!value || typeof value !== "object") {
    return value;
  }
  const source = value as Record<string, unknown>;
  return {
    ok: source.ok,
    inputDomain: source.inputDomain,
    registeredDomain: source.registeredDomain,
    dnsAuthority: source.dnsAuthority,
    rdap: source.rdap,
    sources: source.sources,
    caveat: source.caveat,
  };
}

function compactTlsCertificateForBudget(value: unknown): unknown {
  if (!value || typeof value !== "object") {
    return value;
  }
  const source = value as Record<string, unknown>;
  return {
    ok: source.ok,
    host: source.host,
    port: source.port,
    authorized: source.authorized,
    authorizationError: source.authorizationError,
    protocol: source.protocol,
    resolvedAddresses: source.resolvedAddresses,
    chain: Array.isArray(source.chain)
      ? source.chain.slice(0, 2).map((cert) => {
        if (!cert || typeof cert !== "object") {
          return cert;
        }
        const item = cert as Record<string, unknown>;
        return {
          subject: item.subject,
          issuer: item.issuer,
          validFrom: item.validFrom,
          validTo: item.validTo,
          fingerprint256: item.fingerprint256,
          subjectAltNames: Array.isArray(item.subjectAltNames) ? item.subjectAltNames.slice(0, 12) : item.subjectAltNames,
        };
      })
      : source.chain,
    caveat: source.caveat,
  };
}

function compactPublicKnowledgeForBudget(value: unknown): unknown {
  if (!value || typeof value !== "object") {
    return value;
  }
  const source = value as Record<string, unknown>;
  return {
    ok: source.ok,
    query: source.query,
    wikidata: compactKnownObject(source.wikidata, ["id", "label", "description", "aliases", "facts", "url"]),
    wikipedia: compactKnownObject(source.wikipedia, ["title", "description", "url"]),
    relatedEntities: Array.isArray(source.relatedEntities) ? source.relatedEntities.slice(0, 5) : source.relatedEntities,
    caveat: source.caveat,
  };
}

function compactKnownObject(value: unknown, keys: readonly string[]): unknown {
  if (!value || typeof value !== "object") {
    return value;
  }
  const source = value as Record<string, unknown>;
  return Object.fromEntries(keys.map((key) => [key, source[key]]).filter(([, item]) => item !== undefined));
}

function compactDerivedIndicatorsForBudget(value: unknown): unknown {
  if (!value || typeof value !== "object") {
    return value;
  }
  const source = value as Record<string, unknown>;
  return {
    emails: Array.isArray(source.emails) ? source.emails.slice(0, 10) : source.emails,
    phones: Array.isArray(source.phones) ? source.phones.slice(0, 10) : source.phones,
    hosts: Array.isArray(source.hosts) ? source.hosts.slice(0, 25) : source.hosts,
    ipAddresses: Array.isArray(source.ipAddresses) ? source.ipAddresses.slice(0, 10) : source.ipAddresses,
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
    publicKnowledgeContext: source.publicKnowledgeContext,
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

function summarizeBusinessReputationResults(results: readonly unknown[]): unknown[] {
  return results.map((result) => {
    if (!result || typeof result !== "object") {
      return result;
    }
    const source = result as Record<string, unknown>;
    if (source.ok !== true) {
      return {
        ok: source.ok,
        business: source.business,
        error: source.error,
      };
    }
    const bbbCoverage = source.bbbCoverage && typeof source.bbbCoverage === "object"
      ? source.bbbCoverage as Record<string, unknown>
      : {};
    return {
      business: source.business,
      domain: source.domain,
      bbbSummary: bbbCoverage.summary,
      exactBbbProfiles: bbbCoverage.exactProfileCount,
      relatedBbbProfiles: bbbCoverage.relatedProfileCount,
      hasRelatedBbbProfiles: bbbCoverage.hasRelatedProfiles,
      wikipediaTitle: source.wikipediaBusinessContext
          && typeof source.wikipediaBusinessContext === "object"
          && "title" in source.wikipediaBusinessContext
        ? source.wikipediaBusinessContext.title
        : undefined,
      marketSymbol: source.marketFinancials
          && typeof source.marketFinancials === "object"
          && "ticker" in source.marketFinancials
        ? source.marketFinancials.ticker
        : undefined,
    };
  });
}

function buildPipelineKeyFindings(params: {
  businessReputationSummary: readonly unknown[];
  execution?: Record<string, unknown>;
}) {
  const businessCoverage = params.businessReputationSummary.flatMap((entry) => {
    if (!entry || typeof entry !== "object") {
      return [];
    }
    const source = entry as Record<string, unknown>;
    const bbbSummary = typeof source.bbbSummary === "string" ? source.bbbSummary : undefined;
    if (!bbbSummary) {
      return [];
    }
    return [{
      type: "business_bbb_coverage",
      business: source.business,
      summary: bbbSummary,
      exactBbbProfiles: source.exactBbbProfiles,
      relatedBbbProfiles: source.relatedBbbProfiles,
      hasRelatedBbbProfiles: source.hasRelatedBbbProfiles,
      wikipediaTitle: source.wikipediaTitle,
    }];
  });
  return {
    ...(params.execution ? { execution: params.execution } : {}),
    businessCoverage,
  };
}

function compactBusinessReputationResult(result: unknown): unknown {
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
    business: source.business,
    domain: source.domain,
    cacheStatus: source.cacheStatus,
    bbbCoverage: compactBbbCoverage(source.bbbCoverage),
    wikipediaBusinessContext: compactWikipediaBusinessContext(source.wikipediaBusinessContext),
    marketFinancials: compactMarketFinancials(source.marketFinancials),
    financialDisclosures: compactFinancialDisclosures(source.financialDisclosures),
    sourceStatuses: source.sourceStatuses,
    caveat: source.caveat,
  };
}

function compactBbbCoverage(value: unknown): unknown {
  if (!value || typeof value !== "object") {
    return value;
  }
  const source = value as Record<string, unknown>;
  const relatedProfiles = Array.isArray(source.relatedProfiles) ? source.relatedProfiles.slice(0, 4) : source.relatedProfiles;
  return {
    exactBusiness: source.exactBusiness,
    exactProfileCount: source.exactProfileCount,
    relatedProfileCount: source.relatedProfileCount,
    hasExactProfile: source.hasExactProfile,
    hasRelatedProfiles: source.hasRelatedProfiles,
    summary: source.summary,
    relatedProfiles,
  };
}

function compactWikipediaBusinessContext(value: unknown): unknown {
  if (!value || typeof value !== "object") {
    return value;
  }
  const source = value as Record<string, unknown>;
  return {
    ok: source.ok,
    title: source.title,
    description: source.description,
    extract: typeof source.extract === "string" ? source.extract.slice(0, 360) : source.extract,
    url: source.url,
    caveat: source.caveat,
  };
}

function compactMarketFinancials(value: unknown): unknown {
  if (!value || typeof value !== "object") {
    return value;
  }
  const source = value as Record<string, unknown>;
  return {
    ok: source.ok,
    ticker: source.ticker,
    quote: source.quote,
    metrics: source.metrics,
    sourceStatuses: source.sourceStatuses,
  };
}

function compactFinancialDisclosures(value: unknown): unknown {
  if (!value || typeof value !== "object") {
    return value;
  }
  const source = value as Record<string, unknown>;
  return {
    ok: source.ok,
    company: source.company,
    recentFilings: Array.isArray(source.recentFilings) ? source.recentFilings.slice(0, 3) : source.recentFilings,
    secCompanyPage: source.secCompanyPage,
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

export const testing = {
  fitPipelineOutputBudget,
  measurePipelineOutputChars,
};
