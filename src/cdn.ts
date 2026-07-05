import { fetchWithSsrFGuard } from "openclaw/plugin-sdk/ssrf-runtime";
import { isIP } from "node:net";
import { Type, type Static } from "typebox";
import { OsintCache } from "./cache.js";
import { queryDomainNetworkIntelForTool } from "./domain-network.js";
import { queryTlsCertificateChainForTool } from "./tls-certificate.js";

const HEADER_TIMEOUT_MS = 8_000;
const DEFAULT_MAX_IPS = 4;

export const CdnDdosDetectSchema = Type.Object(
  {
    target: Type.String({
      description: "Public URL or domain to inspect for CDN, WAF, or DDoS-protection signals.",
    }),
    refresh: Type.Optional(Type.Boolean({ description: "Refresh cached network lookups where supported." })),
  },
  { additionalProperties: false },
);

type CdnDdosDetectParams = Static<typeof CdnDdosDetectSchema>;

type ProviderMatch = {
  provider: string;
  category: "cdn" | "cdn_or_ddos_protection" | "waf_or_ddos_protection";
  confidence: number;
  evidence: string[];
};

type EvidenceInput = {
  headers: Record<string, string>;
  headerError?: string;
  bgpNames: string[];
  tlsIssuers: string[];
  tlsSubjects: string[];
  tlsAltNames: string[];
  hostnames: string[];
};

const PROVIDERS = [
  {
    provider: "Cloudflare",
    category: "cdn_or_ddos_protection",
    patterns: [/cloudflare/i, /\bcf-ray\b/i, /\bcf-cache-status\b/i, /__cf_bm/i],
  },
  {
    provider: "Akamai",
    category: "cdn_or_ddos_protection",
    patterns: [/akamai/i, /akamaihd/i, /edgesuite/i, /akamaiedge/i, /\bx-akamai/i],
  },
  {
    provider: "Fastly",
    category: "cdn",
    patterns: [/fastly/i],
  },
  {
    provider: "Amazon CloudFront",
    category: "cdn_or_ddos_protection",
    patterns: [/cloudfront/i, /\bx-amz-cf-/i, /amazon cloudfront/i],
  },
  {
    provider: "Imperva",
    category: "waf_or_ddos_protection",
    patterns: [/imperva/i, /incapsula/i, /\bx-iinfo\b/i, /visid_incap/i],
  },
  {
    provider: "Sucuri",
    category: "waf_or_ddos_protection",
    patterns: [/sucuri/i, /\bx-sucuri/i],
  },
  {
    provider: "Google Cloud CDN",
    category: "cdn_or_ddos_protection",
    patterns: [/google cloud cdn/i, /\bcloud cdn\b/i, /googleusercontent\.com/i, /\bx-goog-/i],
  },
  {
    provider: "Azure Front Door",
    category: "cdn_or_ddos_protection",
    patterns: [/azure front door/i, /azurefd/i, /\bx-azure-/i, /\bx-ec-custom-error\b/i],
  },
  {
    provider: "Bunny CDN",
    category: "cdn",
    patterns: [/bunny/i, /\bcdn77\b/i],
  },
] as const;

export async function detectCdnDdosForTool(params: CdnDdosDetectParams & { signal?: AbortSignal }) {
  const target = normalizeTarget(params.target);
  if (!target) {
    return { ok: false, error: "Expected a public URL or DNS domain." };
  }
  return detectCdnDdos({
    target,
    refresh: params.refresh,
    signal: params.signal,
  });
}

export async function detectCdnDdos(params: {
  target: { url: string; domain: string };
  refresh?: boolean;
  signal?: AbortSignal;
  cache?: OsintCache;
  network?: unknown;
  tls?: unknown;
}) {
  const [headers, network, tls] = await Promise.all([
    fetchHeaders(params.target.url, params.signal),
    params.network ??
      queryDomainNetworkIntelForTool({
        domain: params.target.domain,
        maxIps: DEFAULT_MAX_IPS,
        refresh: params.refresh,
        cache: params.cache,
      }),
    params.tls ?? queryTlsCertificateChainForTool({ host: params.target.domain }),
  ]);
  const input = evidenceInput({
    headers,
    network,
    tls,
    domain: params.target.domain,
  });
  const matches = detectProviders(input);
  return {
    ok: true,
    normalizedUrl: params.target.url,
    domain: params.target.domain,
    protectedBy: matches,
    primaryProvider: matches[0]?.provider,
    likelyProtected: matches.some((match) => match.confidence >= 0.55),
    observedHeaders: input.headers,
    networkSummary: network && typeof network === "object" && "summary" in network
      ? (network as Record<string, unknown>).summary
      : undefined,
    caveat:
      "CDN/WAF detection is heuristic. It combines HTTP headers, BGP/ASN names, TLS metadata, and hostnames; absence of a match is not proof there is no protection.",
  };
}

function detectProviders(input: EvidenceInput): ProviderMatch[] {
  const haystacks = [
    ...Object.entries(input.headers).map(([key, value]) => `${key}: ${value}`),
    ...input.bgpNames,
    ...input.tlsIssuers,
    ...input.tlsSubjects,
    ...input.tlsAltNames,
    ...input.hostnames,
  ];
  return PROVIDERS.flatMap((provider) => {
    const evidence = provider.patterns.flatMap((pattern) =>
      haystacks.filter((value) => pattern.test(value)).map((value) => trimEvidence(value))
    );
    if (evidence.length === 0) {
      return [];
    }
    const confidence = Math.min(0.95, 0.35 + unique(evidence).length * 0.15);
    return [{
      provider: provider.provider,
      category: provider.category,
      confidence: Number(confidence.toFixed(2)),
      evidence: unique(evidence).slice(0, 10),
    }];
  }).sort((left, right) => right.confidence - left.confidence || left.provider.localeCompare(right.provider));
}

function evidenceInput(params: {
  headers: Awaited<ReturnType<typeof fetchHeaders>>;
  network: unknown;
  tls: unknown;
  domain: string;
}): EvidenceInput {
  return {
    headers: params.headers.ok ? params.headers.headers : {},
    headerError: params.headers.ok ? undefined : params.headers.error,
    bgpNames: valuesAt(params.network, ["bgp", "asName"]),
    tlsIssuers: valuesAt(params.tls, ["chain", "issuer", "O"]),
    tlsSubjects: valuesAt(params.tls, ["chain", "subject", "O"]),
    tlsAltNames: valuesAt(params.tls, ["chain", "altNames", "dnsNames"]),
    hostnames: [params.domain],
  };
}

async function fetchHeaders(url: string, signal?: AbortSignal): Promise<
  | { ok: true; headers: Record<string, string> }
  | { ok: false; error: string }
> {
  try {
    const head = await fetchSelectedHeaders(url, "HEAD", signal);
    if (head.ok && head.status !== 405) {
      return { ok: true, headers: head.headers };
    }
    const get = await fetchSelectedHeaders(url, "GET", signal);
    if (get.ok) {
      return { ok: true, headers: get.headers };
    }
    return head.ok ? { ok: true, headers: head.headers } : { ok: false, error: get.error ?? head.error };
  } catch (error) {
    return { ok: false, error: formatError(error) };
  }
}

async function fetchSelectedHeaders(
  url: string,
  method: "GET" | "HEAD",
  signal?: AbortSignal,
): Promise<
  | { ok: true; status: number; headers: Record<string, string> }
  | { ok: false; error: string }
> {
  try {
    const guarded = await fetchWithSsrFGuard({
      url,
      init: {
        method,
        headers: {
          Accept: "*/*",
          "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
        },
      },
      timeoutMs: HEADER_TIMEOUT_MS,
      signal,
      auditContext: "openclaw-osint-cdn-ddos-detect",
    });
    const { response, release } = guarded;
    try {
      return { ok: true, status: response.status, headers: selectedHeaders(response.headers) };
    } finally {
      await release();
    }
  } catch (error) {
    return { ok: false, error: formatError(error) };
  }
}

function selectedHeaders(headers: Headers): Record<string, string> {
  const selected = [
    "server",
    "via",
    "x-cache",
    "x-served-by",
    "x-timer",
    "cf-ray",
    "cf-cache-status",
    "x-amz-cf-id",
    "x-amz-cf-pop",
    "x-iinfo",
    "x-sucuri-id",
    "x-sucuri-cache",
    "x-azure-ref",
    "x-ec-custom-error",
  ];
  return Object.fromEntries(
    selected.flatMap((name) => {
      const value = headers.get(name);
      return value ? [[name, value]] : [];
    }),
  );
}

function normalizeTarget(input: string): { url: string; domain: string } | undefined {
  const raw = input.trim();
  const candidate = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return undefined;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return undefined;
  }
  const domain = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(domain) || !domain.includes(".")) {
    return undefined;
  }
  if (isIP(domain)) {
    return undefined;
  }
  return { url: parsed.toString(), domain };
}

function valuesAt(value: unknown, path: readonly string[]): string[] {
  if (path.length === 0) {
    return typeof value === "string" ? [value] : [];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item) => valuesAt(item, path));
  }
  if (!value || typeof value !== "object") {
    return [];
  }
  const [key, ...rest] = path;
  return key ? valuesAt((value as Record<string, unknown>)[key], rest) : [];
}

function unique(values: readonly string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

function trimEvidence(value: string): string {
  return value.length > 160 ? `${value.slice(0, 157)}...` : value;
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export const testing = {
  detectProviders,
  normalizeTarget,
  selectedHeaders,
};
