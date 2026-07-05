import { Type, type Static } from "typebox";
import { OsintCache } from "./cache.js";
import { queryCrtshDomainForTool } from "./crtsh.js";
import { queryDomainNetworkIntelForTool } from "./domain-network.js";
import {
  queryHibpEmailBreachForTool,
  queryPwnedPasswordHashForTool,
} from "./hibp.js";
import { queryInfraReputationForTool } from "./reputation.js";
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

    const ips = uniqueBounded([
      ...indicators.ipv4,
      ...domainNetwork.flatMap(dnsIpsFromDomainNetworkResult),
    ], maxLookups);
    const emails = indicators.emails.slice(0, maxLookups);
    const hashes = indicators.hashes.slice(0, maxLookups);
    const [crtshDomains, infraReputation, hibpEmails, pwnedHashes] = await Promise.all([
      params.skipHighExpansion ? Promise.resolve([]) : Promise.all(
        domains.map((domain) =>
          queryCrtshDomainForTool({ domain, limit: 25, refresh: params.refresh, signal: params.signal, cache })
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
      params.skipHighExpansion ? Promise.resolve([]) : Promise.all(
        hashes.map((hash) =>
          queryPwnedPasswordHashForTool({ hash, algorithm: "auto", signal: params.signal })
        ),
      ),
    ]);
    stages.push("crtsh_domain", "infra_reputation", "hibp_email_breach", "pwned_password_hash");
    return {
      ok: true,
      effort: params.effort,
      stages,
      indicators,
      limits: { maxLookups },
      results: {
        urlSnapshots,
        domainNetwork,
        crtshDomains,
        infraReputation,
        hibpEmails,
        pwnedHashes,
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
