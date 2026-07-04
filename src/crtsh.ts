import { createHash } from "node:crypto";
import { fetchWithSsrFGuard } from "openclaw/plugin-sdk/ssrf-runtime";
import { Type, type Static } from "typebox";
import { OsintCache, type OsintObservation } from "./cache.js";

const CRTSH_SOURCE = "crtsh";
const CRTSH_TTL_MS = 24 * 60 * 60 * 1000;
const CRTSH_MAX_RESPONSE_BYTES = 1024 * 1024;
const CRTSH_FETCH_TIMEOUT_MS = 15_000;
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 250;

export const CrtshDomainSchema = Type.Object(
  {
    domain: Type.String({
      description: "Registered domain to inspect in crt.sh certificate transparency data.",
    }),
    limit: Type.Optional(
      Type.Integer({
        description: "Maximum normalized certificate names to return.",
        minimum: 1,
        maximum: MAX_LIMIT,
      }),
    ),
    refresh: Type.Optional(
      Type.Boolean({
        description: "Refresh crt.sh instead of using a fresh local cache entry.",
      }),
    ),
  },
  { additionalProperties: false },
);

export const OsintCacheStatusSchema = Type.Object(
  {
    source: Type.Optional(
      Type.String({
        description: "Optional OSINT source id, such as crtsh.",
      }),
    ),
  },
  { additionalProperties: false },
);

type CrtshDomainParams = Static<typeof CrtshDomainSchema>;
type OsintCacheStatusParams = Static<typeof OsintCacheStatusSchema>;

type CrtshRow = {
  id?: number | string;
  issuer_name?: string;
  common_name?: string;
  name_value?: string;
  entry_timestamp?: string;
  not_before?: string;
  not_after?: string;
};

type CrtshDomainResult =
  | {
      ok: true;
      source: "crtsh";
      domain: string;
      cacheStatus: "hit" | "refreshed";
      fetchedAt: number;
      expiresAt: number;
      returned: number;
      stored: number;
      truncated: boolean;
      observations: Array<{
        type: string;
        value: string;
        confidence: number;
        observedAt: number;
        sourceRef: string;
      }>;
    }
  | {
      ok: false;
      source: "crtsh";
      domain?: string;
      error: string;
    };

export async function queryCrtshDomainForTool(
  params: CrtshDomainParams & { signal?: AbortSignal; cache?: OsintCache },
): Promise<CrtshDomainResult> {
  const domain = normalizeDomainCandidate(params.domain);
  if (!domain) {
    return { ok: false, source: CRTSH_SOURCE, error: "Expected a public DNS domain." };
  }

  const limit = Math.min(Math.max(params.limit ?? DEFAULT_LIMIT, 1), MAX_LIMIT);
  const cache = params.cache ?? new OsintCache();
  const closeCache = !params.cache;
  try {
    const fresh = params.refresh ? undefined : cache.getFreshSource(CRTSH_SOURCE, domain);
    if (fresh) {
      const observations = cache.listObservations(CRTSH_SOURCE, domain, MAX_LIMIT * 4);
      return formatCrtshResult({
        domain,
        cacheStatus: "hit",
        fetchedAt: fresh.fetchedAt,
        expiresAt: fresh.expiresAt,
        observations,
        limit,
      });
    }

    const fetchedAt = Date.now();
    const rawJson = await fetchCrtshJson(domain, params.signal);
    const rows = parseCrtshRows(rawJson);
    const observations = observationsFromCrtshRows(domain, rows, fetchedAt);
    cache.replaceObservations(CRTSH_SOURCE, domain, observations);
    cache.putSource({
      source: CRTSH_SOURCE,
      target: domain,
      fetchedAt,
      expiresAt: fetchedAt + CRTSH_TTL_MS,
      rawJson,
      rawBytes: Buffer.byteLength(rawJson),
      status: "ok",
    });
    return formatCrtshResult({
      domain,
      cacheStatus: "refreshed",
      fetchedAt,
      expiresAt: fetchedAt + CRTSH_TTL_MS,
      observations,
      limit,
    });
  } catch (error) {
    return { ok: false, source: CRTSH_SOURCE, domain, error: formatError(error) };
  } finally {
    if (closeCache) {
      cache.close();
    }
  }
}

export function osintCacheStatusForTool(params: OsintCacheStatusParams = {}) {
  const cache = new OsintCache();
  try {
    return { ok: true, status: cache.getStatus(params.source) };
  } finally {
    cache.close();
  }
}

async function fetchCrtshJson(domain: string, signal?: AbortSignal): Promise<string> {
  const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
  const guarded = await fetchWithSsrFGuard({
    url,
    init: {
      headers: {
        Accept: "application/json,text/plain;q=0.5,*/*;q=0.1",
        "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
      },
    },
    timeoutMs: CRTSH_FETCH_TIMEOUT_MS,
    signal,
    auditContext: "openclaw-osint-crtsh-domain",
  });
  const { response, release } = guarded;
  try {
    if (!response.ok) {
      throw new Error(`crt.sh returned HTTP ${response.status}`);
    }
    return await readResponseTextBounded(response, CRTSH_MAX_RESPONSE_BYTES);
  } finally {
    await release();
  }
}

function parseCrtshRows(rawJson: string): CrtshRow[] {
  const parsed = JSON.parse(rawJson) as unknown;
  if (!Array.isArray(parsed)) {
    return [];
  }
  return parsed.filter((row): row is CrtshRow => row !== null && typeof row === "object");
}

function observationsFromCrtshRows(
  domain: string,
  rows: readonly CrtshRow[],
  observedAt: number,
): OsintObservation[] {
  const seen = new Set<string>();
  const observations: OsintObservation[] = [];
  for (const row of rows) {
    for (const name of namesFromCrtshRow(row)) {
      if (!isNameInDomain(name, domain) || seen.has(name)) {
        continue;
      }
      seen.add(name);
      const sourceRef = `crtsh:${String(row.id ?? name)}`;
      const exact = name === domain;
      observations.push({
        id: stableObservationId(CRTSH_SOURCE, domain, "domain", name, sourceRef),
        source: CRTSH_SOURCE,
        target: domain,
        type: "domain",
        value: name,
        confidence: exact ? 0.9 : 0.82,
        admissionScore: exact ? 0.9 : 0.82,
        storageTier: "full",
        observedAt,
        sourceRef,
        metadata: compactMetadata(row),
      });
    }
  }
  return observations.slice(0, MAX_LIMIT * 4);
}

function namesFromCrtshRow(row: CrtshRow): string[] {
  const values = [row.common_name, row.name_value]
    .filter((value): value is string => typeof value === "string")
    .flatMap((value) => value.split(/\s+/g));
  return Array.from(new Set(values.map(normalizeCertificateName).filter(Boolean) as string[]));
}

function normalizeDomainCandidate(input: string): string | undefined {
  const trimmed = input.trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/?#]/, 1)[0] ?? "";
  return normalizeCertificateName(trimmed);
}

function normalizeCertificateName(input: string): string | undefined {
  const value = input.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  if (value.length > 253 || !value.includes(".") || value.includes("..")) {
    return undefined;
  }
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value)) {
    return undefined;
  }
  return value;
}

function isNameInDomain(name: string, domain: string): boolean {
  return name === domain || name.endsWith(`.${domain}`);
}

function compactMetadata(row: CrtshRow): Record<string, unknown> {
  return {
    ...(row.issuer_name ? { issuerName: row.issuer_name.slice(0, 300) } : {}),
    ...(row.common_name ? { commonName: row.common_name.slice(0, 253) } : {}),
    ...(row.not_before ? { notBefore: row.not_before } : {}),
    ...(row.not_after ? { notAfter: row.not_after } : {}),
    ...(row.entry_timestamp ? { entryTimestamp: row.entry_timestamp } : {}),
  };
}

function formatCrtshResult(params: {
  domain: string;
  cacheStatus: "hit" | "refreshed";
  fetchedAt: number;
  expiresAt: number;
  observations: readonly OsintObservation[];
  limit: number;
}): CrtshDomainResult {
  const limited = params.observations.slice(0, params.limit);
  return {
    ok: true,
    source: CRTSH_SOURCE,
    domain: params.domain,
    cacheStatus: params.cacheStatus,
    fetchedAt: params.fetchedAt,
    expiresAt: params.expiresAt,
    returned: limited.length,
    stored: params.observations.length,
    truncated: params.observations.length > limited.length,
    observations: limited.map((observation) => ({
      type: observation.type,
      value: observation.value,
      confidence: observation.confidence,
      observedAt: observation.observedAt,
      sourceRef: observation.sourceRef,
    })),
  };
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
  namesFromCrtshRow,
  normalizeCertificateName,
  normalizeDomainCandidate,
  observationsFromCrtshRows,
  parseCrtshRows,
};
