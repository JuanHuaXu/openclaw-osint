import { createHash } from "node:crypto";
import { fetchWithSsrFGuard } from "openclaw/plugin-sdk/ssrf-runtime";
import { Type, type Static } from "typebox";
import { OsintCache, type OsintObservation } from "./cache.js";

const HIBP_SOURCE = "hibp";
const HIBP_EMAIL_TTL_MS = 24 * 60 * 60 * 1000;
const HIBP_LATEST_TTL_MS = 60 * 60 * 1000;
const HIBP_TIMEOUT_MS = 12_000;
const HIBP_MAX_RESPONSE_BYTES = 1024 * 1024;
const PWNED_PASSWORDS_TIMEOUT_MS = 12_000;
const PWNED_PASSWORDS_MAX_RESPONSE_BYTES = 256 * 1024;
const HIBP_USER_AGENT = "OpenClaw OSINT plugin";

export const HibpEmailBreachSchema = Type.Object(
  {
    email: Type.String({
      description: "Email address to check against Have I Been Pwned. Requires HIBP_API_KEY.",
    }),
    refresh: Type.Optional(
      Type.Boolean({
        description: "Refresh HIBP instead of using a fresh local cache entry.",
      }),
    ),
  },
  { additionalProperties: false },
);

export const HibpLatestBreachSchema = Type.Object(
  {
    refresh: Type.Optional(
      Type.Boolean({
        description: "Refresh HIBP instead of using a fresh local cache entry.",
      }),
    ),
  },
  { additionalProperties: false },
);

export const PwnedPasswordHashSchema = Type.Object(
  {
    hash: Type.String({
      description: "SHA-1 or NTLM password hash. Do not pass plaintext passwords.",
    }),
    algorithm: Type.Optional(
      Type.Union([Type.Literal("sha1"), Type.Literal("ntlm"), Type.Literal("auto")], {
        description: "Hash algorithm. Defaults to auto-detect by hash length.",
      }),
    ),
  },
  { additionalProperties: false },
);

type HibpEmailBreachParams = Static<typeof HibpEmailBreachSchema>;
type HibpLatestBreachParams = Static<typeof HibpLatestBreachSchema>;
type PwnedPasswordHashParams = Static<typeof PwnedPasswordHashSchema>;

type HibpBreach = {
  Name?: string;
  Title?: string;
  Domain?: string;
  BreachDate?: string;
  AddedDate?: string;
  ModifiedDate?: string;
  DataClasses?: string[];
  IsVerified?: boolean;
  IsFabricated?: boolean;
  IsSensitive?: boolean;
  IsRetired?: boolean;
  IsSpamList?: boolean;
};

type HibpEmailBreachResult =
  | {
      ok: true;
      source: "hibp";
      attribution: string;
      cacheStatus: "hit" | "refreshed";
      accountHash: string;
      breached: boolean;
      breachCount: number;
      fetchedAt: number;
      expiresAt: number;
      breaches: ReturnType<typeof publicBreachSummary>[];
    }
  | {
      ok: false;
      source: "hibp";
      error: string;
    };

type HibpLatestBreachResult =
  | {
      ok: true;
      source: "hibp";
      attribution: string;
      cacheStatus: "hit" | "refreshed";
      fetchedAt: number;
      expiresAt: number;
      breach?: ReturnType<typeof publicBreachSummary>;
    }
  | {
      ok: false;
      source: "hibp";
      error: string;
    };

type PwnedPasswordHashResult =
  | {
      ok: true;
      source: "pwned-passwords";
      attribution: string;
      algorithm: "sha1" | "ntlm";
      hashPrefix: string;
      pwned: boolean;
      count: number;
    }
  | {
      ok: false;
      source: "pwned-passwords";
      error: string;
    };

export async function queryHibpEmailBreachForTool(
  params: HibpEmailBreachParams & { signal?: AbortSignal; cache?: OsintCache },
): Promise<HibpEmailBreachResult> {
  const email = normalizeEmail(params.email);
  if (!email) {
    return { ok: false, source: HIBP_SOURCE, error: "Expected a valid email address." };
  }
  const apiKey = process.env.HIBP_API_KEY?.trim();
  if (!apiKey) {
    return {
      ok: false,
      source: HIBP_SOURCE,
      error: "HIBP_API_KEY is required for email breach lookup.",
    };
  }

  const target = `email-sha256:${sha256Hex(email)}`;
  const accountHash = target.slice("email-sha256:".length, "email-sha256:".length + 16);
  const cache = params.cache ?? new OsintCache();
  const closeCache = !params.cache;
  try {
    const fresh = params.refresh ? undefined : cache.getFreshSource(HIBP_SOURCE, target);
    if (fresh) {
      return formatEmailResult({
        cacheStatus: "hit",
        accountHash,
        fetchedAt: fresh.fetchedAt,
        expiresAt: fresh.expiresAt,
        breaches: parseHibpBreaches(fresh.rawJson),
      });
    }

    const fetchedAt = Date.now();
    const breaches = await fetchHibpBreaches(email, apiKey, params.signal);
    const rawJson = JSON.stringify(breaches);
    const observations = observationsFromBreaches(target, breaches, fetchedAt);
    cache.replaceObservations(HIBP_SOURCE, target, observations);
    cache.putSource({
      source: HIBP_SOURCE,
      target,
      fetchedAt,
      expiresAt: fetchedAt + HIBP_EMAIL_TTL_MS,
      rawJson,
      rawBytes: Buffer.byteLength(rawJson),
      status: "ok",
    });
    return formatEmailResult({
      cacheStatus: "refreshed",
      accountHash,
      fetchedAt,
      expiresAt: fetchedAt + HIBP_EMAIL_TTL_MS,
      breaches,
    });
  } catch (error) {
    return { ok: false, source: HIBP_SOURCE, error: formatError(error) };
  } finally {
    if (closeCache) {
      cache.close();
    }
  }
}

export async function queryHibpLatestBreachForTool(
  params: HibpLatestBreachParams & { signal?: AbortSignal; cache?: OsintCache } = {},
): Promise<HibpLatestBreachResult> {
  const target = "latest-breach";
  const cache = params.cache ?? new OsintCache();
  const closeCache = !params.cache;
  try {
    const fresh = params.refresh ? undefined : cache.getFreshSource(HIBP_SOURCE, target);
    if (fresh) {
      return formatLatestResult({
        cacheStatus: "hit",
        fetchedAt: fresh.fetchedAt,
        expiresAt: fresh.expiresAt,
        breach: parseHibpBreach(fresh.rawJson),
      });
    }

    const fetchedAt = Date.now();
    const breach = await fetchHibpLatestBreach(params.signal);
    const rawJson = JSON.stringify(breach ?? null);
    cache.putSource({
      source: HIBP_SOURCE,
      target,
      fetchedAt,
      expiresAt: fetchedAt + HIBP_LATEST_TTL_MS,
      rawJson,
      rawBytes: Buffer.byteLength(rawJson),
      status: "ok",
    });
    return formatLatestResult({
      cacheStatus: "refreshed",
      fetchedAt,
      expiresAt: fetchedAt + HIBP_LATEST_TTL_MS,
      breach,
    });
  } catch (error) {
    return { ok: false, source: HIBP_SOURCE, error: formatError(error) };
  } finally {
    if (closeCache) {
      cache.close();
    }
  }
}

export async function queryPwnedPasswordHashForTool(
  params: PwnedPasswordHashParams & { signal?: AbortSignal },
): Promise<PwnedPasswordHashResult> {
  const normalized = normalizePasswordHash(params.hash, params.algorithm ?? "auto");
  if (!normalized) {
    return {
      ok: false,
      source: "pwned-passwords",
      error: "Expected a SHA-1 hash (40 hex chars) or NTLM hash (32 hex chars).",
    };
  }
  try {
    const { suffixes, prefix } = await fetchPwnedPasswordRange(normalized, params.signal);
    const count = suffixes.get(normalized.suffix) ?? 0;
    return {
      ok: true,
      source: "pwned-passwords",
      attribution: "Data from Have I Been Pwned Pwned Passwords.",
      algorithm: normalized.algorithm,
      hashPrefix: prefix,
      pwned: count > 0,
      count,
    };
  } catch (error) {
    return { ok: false, source: "pwned-passwords", error: formatError(error) };
  }
}

async function fetchHibpBreaches(
  email: string,
  apiKey: string,
  signal?: AbortSignal,
): Promise<HibpBreach[]> {
  const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`;
  const guarded = await fetchWithSsrFGuard({
    url,
    init: {
      headers: {
        Accept: "application/json",
        "User-Agent": HIBP_USER_AGENT,
        "hibp-api-key": apiKey,
      },
    },
    timeoutMs: HIBP_TIMEOUT_MS,
    signal,
    auditContext: "openclaw-osint-hibp-email",
  });
  const { response, release } = guarded;
  try {
    if (response.status === 404) {
      return [];
    }
    if (!response.ok) {
      throw new Error(`HIBP returned HTTP ${response.status}`);
    }
    return parseHibpBreaches(await readResponseTextBounded(response, HIBP_MAX_RESPONSE_BYTES));
  } finally {
    await release();
  }
}

async function fetchHibpLatestBreach(signal?: AbortSignal): Promise<HibpBreach | undefined> {
  const guarded = await fetchWithSsrFGuard({
    url: "https://haveibeenpwned.com/api/v3/latestbreach",
    init: {
      headers: {
        Accept: "application/json",
        "User-Agent": HIBP_USER_AGENT,
      },
    },
    timeoutMs: HIBP_TIMEOUT_MS,
    signal,
    auditContext: "openclaw-osint-hibp-latest",
  });
  const { response, release } = guarded;
  try {
    if (response.status === 404) {
      return undefined;
    }
    if (!response.ok) {
      throw new Error(`HIBP returned HTTP ${response.status}`);
    }
    return parseHibpBreach(await readResponseTextBounded(response, HIBP_MAX_RESPONSE_BYTES));
  } finally {
    await release();
  }
}

async function fetchPwnedPasswordRange(
  hash: NormalizedPasswordHash,
  signal?: AbortSignal,
): Promise<{ prefix: string; suffixes: Map<string, number> }> {
  const mode = hash.algorithm === "ntlm" ? "?mode=ntlm" : "";
  const guarded = await fetchWithSsrFGuard({
    url: `https://api.pwnedpasswords.com/range/${hash.prefix}${mode}`,
    init: {
      headers: {
        Accept: "text/plain",
        "Add-Padding": "true",
        "User-Agent": HIBP_USER_AGENT,
      },
    },
    timeoutMs: PWNED_PASSWORDS_TIMEOUT_MS,
    signal,
    auditContext: "openclaw-osint-pwned-passwords",
  });
  const { response, release } = guarded;
  try {
    if (!response.ok) {
      throw new Error(`Pwned Passwords returned HTTP ${response.status}`);
    }
    return {
      prefix: hash.prefix,
      suffixes: parsePwnedPasswordSuffixes(
        await readResponseTextBounded(response, PWNED_PASSWORDS_MAX_RESPONSE_BYTES),
      ),
    };
  } finally {
    await release();
  }
}

function formatEmailResult(params: {
  cacheStatus: "hit" | "refreshed";
  accountHash: string;
  fetchedAt: number;
  expiresAt: number;
  breaches: readonly HibpBreach[];
}): HibpEmailBreachResult {
  return {
    ok: true,
    source: HIBP_SOURCE,
    attribution: "Data from Have I Been Pwned.",
    cacheStatus: params.cacheStatus,
    accountHash: params.accountHash,
    breached: params.breaches.length > 0,
    breachCount: params.breaches.length,
    fetchedAt: params.fetchedAt,
    expiresAt: params.expiresAt,
    breaches: params.breaches.map(publicBreachSummary),
  };
}

function formatLatestResult(params: {
  cacheStatus: "hit" | "refreshed";
  fetchedAt: number;
  expiresAt: number;
  breach?: HibpBreach;
}): HibpLatestBreachResult {
  return {
    ok: true,
    source: HIBP_SOURCE,
    attribution: "Data from Have I Been Pwned.",
    cacheStatus: params.cacheStatus,
    fetchedAt: params.fetchedAt,
    expiresAt: params.expiresAt,
    ...(params.breach ? { breach: publicBreachSummary(params.breach) } : {}),
  };
}

function publicBreachSummary(breach: HibpBreach) {
  return {
    name: String(breach.Name ?? ""),
    title: String(breach.Title ?? breach.Name ?? ""),
    domain: String(breach.Domain ?? ""),
    breachDate: String(breach.BreachDate ?? ""),
    addedDate: String(breach.AddedDate ?? ""),
    modifiedDate: String(breach.ModifiedDate ?? ""),
    dataClasses: Array.isArray(breach.DataClasses) ? breach.DataClasses.map(String).slice(0, 50) : [],
    isVerified: Boolean(breach.IsVerified),
    isFabricated: Boolean(breach.IsFabricated),
    isSensitive: Boolean(breach.IsSensitive),
    isRetired: Boolean(breach.IsRetired),
    isSpamList: Boolean(breach.IsSpamList),
  };
}

function observationsFromBreaches(
  target: string,
  breaches: readonly HibpBreach[],
  observedAt: number,
): OsintObservation[] {
  return breaches.map((breach) => {
    const summary = publicBreachSummary(breach);
    const sourceRef = `hibp:${summary.name || summary.title}`;
    return {
      id: stableObservationId(HIBP_SOURCE, target, "breach", sourceRef),
      source: HIBP_SOURCE,
      target,
      type: "breach",
      value: summary.name || summary.title,
      confidence: 0.95,
      admissionScore: 0.95,
      storageTier: "full",
      observedAt,
      sourceRef,
      metadata: summary,
    };
  });
}

function parseHibpBreaches(rawJson: string): HibpBreach[] {
  const parsed = JSON.parse(rawJson) as unknown;
  if (!Array.isArray(parsed)) {
    return [];
  }
  return parsed.filter(isObjectLike).map((row) => row as HibpBreach);
}

function parseHibpBreach(rawJson: string): HibpBreach | undefined {
  const parsed = JSON.parse(rawJson) as unknown;
  return isObjectLike(parsed) ? (parsed as HibpBreach) : undefined;
}

function parsePwnedPasswordSuffixes(input: string): Map<string, number> {
  const suffixes = new Map<string, number>();
  for (const line of input.split(/\r?\n/g)) {
    const [suffix, countText] = line.trim().split(":", 2);
    if (!suffix || !/^[A-F0-9]+$/i.test(suffix)) {
      continue;
    }
    const count = Number.parseInt(countText ?? "0", 10);
    suffixes.set(suffix.toUpperCase(), Number.isFinite(count) ? count : 0);
  }
  return suffixes;
}

type NormalizedPasswordHash = {
  algorithm: "sha1" | "ntlm";
  prefix: string;
  suffix: string;
};

function normalizePasswordHash(
  input: string,
  algorithm: "sha1" | "ntlm" | "auto",
): NormalizedPasswordHash | undefined {
  const hash = input.trim().toUpperCase();
  if (!/^[A-F0-9]+$/.test(hash)) {
    return undefined;
  }
  const detected = hash.length === 40 ? "sha1" : hash.length === 32 ? "ntlm" : undefined;
  const resolved = algorithm === "auto" ? detected : algorithm;
  if (!resolved || resolved !== detected) {
    return undefined;
  }
  return { algorithm: resolved, prefix: hash.slice(0, 5), suffix: hash.slice(5) };
}

function normalizeEmail(input: string): string | undefined {
  const email = input.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return undefined;
  }
  return email;
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

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function isObjectLike(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object";
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export const testing = {
  normalizeEmail,
  normalizePasswordHash,
  parseHibpBreach,
  parseHibpBreaches,
  parsePwnedPasswordSuffixes,
  publicBreachSummary,
};
