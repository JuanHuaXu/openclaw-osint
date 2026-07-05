import { Type, type Static } from "typebox";
import { OsintCache } from "./cache.js";
import { queryDomainAuthorityIntelForTool } from "./domain-authority.js";
import { queryDomainNetworkIntelForTool } from "./domain-network.js";
import {
  queryHibpEmailBreachForTool,
  queryPwnedPasswordHashForTool,
} from "./hibp.js";
import { queryIpAssignmentIntelForTool } from "./ip-assignment.js";
import { queryInfraReputationForTool, queryPhoneReputationForTool } from "./reputation.js";
import { queryTlsCertificateChainForTool } from "./tls-certificate.js";
import {
  extractIndicatorsForTool,
  snapshotUrlForTool,
} from "./tools.js";

const DEFAULT_MAX_LOOKUPS = 3;
const MAX_LOOKUPS = 10;

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
    const domainNetwork = await Promise.all(
      domains.map((domain) =>
        queryDomainNetworkIntelForTool({ domain, maxIps: 4, refresh: params.refresh, cache })
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
      ...domainNetwork.flatMap(dnsIpsFromDomainNetworkResult),
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
    const [tlsCertificates, infraReputation, hibpEmails, phoneReputation, pwnedHashes] = await Promise.all([
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
      contactIndicators,
      derivedIndicatorsFromTlsResults(tlsCertificates),
    );
    stages.push("domain_authority_intel", "ip_assignment_intel", "tls_certificate_chain", "infra_reputation", "hibp_email_breach", "phone_reputation", "pwned_password_hash");
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
        derivedIndicators,
        infraReputation,
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

function mergeDerivedIndicators(...items: Array<{ emails: readonly string[]; phones: readonly string[] }>) {
  return {
    emails: uniqueBounded(items.flatMap((item) => item.emails), MAX_LOOKUPS),
    phones: uniqueBounded(items.flatMap((item) => item.phones), MAX_LOOKUPS),
    hosts: uniqueBounded(items.flatMap((item) => optionalStringArray(item, "hosts")), MAX_LOOKUPS),
    ipAddresses: uniqueBounded(items.flatMap((item) => optionalStringArray(item, "ipAddresses")), MAX_LOOKUPS),
  };
}

function derivedIndicatorsFromTlsResults(results: readonly unknown[]) {
  return {
    emails: [],
    phones: [],
    hosts: uniqueBounded(
      results.flatMap((result) => indicatorValues(result, "hosts")),
      MAX_LOOKUPS,
    ),
    ipAddresses: uniqueBounded(
      results.flatMap((result) => indicatorValues(result, "ipAddresses")),
      MAX_LOOKUPS,
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

function optionalStringArray(value: unknown, key: string): string[] {
  if (!value || typeof value !== "object" || !(key in value)) {
    return [];
  }
  const array = (value as Record<string, unknown>)[key];
  return Array.isArray(array) ? array.filter((item): item is string => typeof item === "string") : [];
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
    derivedIndicators: source.derivedIndicators,
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
    derivedIndicators: source.derivedIndicators,
    caveat: source.caveat,
  };
}
