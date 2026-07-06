import { fetchWithSsrFGuard } from "openclaw/plugin-sdk/ssrf-runtime";
import { Type, type Static } from "typebox";
import { OsintCache } from "./cache.js";

const CVE_SOURCE = "fingerprint-cve";
const CVE_TTL_MS = 12 * 60 * 60 * 1000;
const CVE_TIMEOUT_MS = 12_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const DEFAULT_MAX_FINDINGS = 8;
const MAX_FINDINGS = 25;

export const FingerprintCveLookupSchema = Type.Object(
  {
    software: Type.Optional(Type.String({
      description: "Software or framework name, such as nginx, Apache httpd, gunicorn, Next.js, Caddy, PHP, or Express.",
    })),
    version: Type.Optional(Type.String({
      description: "Concrete detected version. Versionless fingerprints return a skipped result instead of broad CVE noise.",
    })),
    fingerprints: Type.Optional(Type.Array(Type.Object(
      {
        kind: Type.Optional(Type.String()),
        name: Type.String(),
        version: Type.Optional(Type.String()),
        confidence: Type.Optional(Type.String()),
        source: Type.Optional(Type.String()),
        evidence: Type.Optional(Type.Array(Type.String())),
      },
      { additionalProperties: true },
    ), {
      description: "Fingerprint objects from osint_url_snapshot.fingerprint.fingerprints.",
    })),
    maxFindings: Type.Optional(Type.Integer({
      description: "Maximum RCE/crash/bleed/hop findings to return per fingerprint.",
      minimum: 1,
      maximum: MAX_FINDINGS,
    })),
    refresh: Type.Optional(Type.Boolean({ description: "Bypass fresh local cache." })),
  },
  { additionalProperties: false },
);

type FingerprintCveLookupParams = Static<typeof FingerprintCveLookupSchema>;

type NormalizedFingerprint = {
  name: string;
  version?: string;
  confidence?: string;
  source?: string;
  evidence?: string[];
};

type VulnerabilityIdentity =
  | {
      source: "nvd";
      type: "cpe";
      cpe: string;
    }
  | {
      source: "osv";
      type: "package";
      ecosystem: string;
      packageName: string;
    };

type CveFinding = {
  id: string;
  source: "nvd" | "osv";
  severity?: string;
  cvss?: number;
  impactTags: string[];
  summary: string;
  references: string[];
  affected: "matched_version" | "reported_by_source";
  knownExploited?: boolean;
};

type FingerprintCveResult = {
  name: string;
  version?: string;
  identities: VulnerabilityIdentity[];
  skipped?: string;
  findings: CveFinding[];
  error?: string;
  caveat: string;
};

export async function queryFingerprintCvesForTool(
  params: FingerprintCveLookupParams & { signal?: AbortSignal; cache?: OsintCache },
) {
  const maxFindings = Math.min(Math.max(params.maxFindings ?? DEFAULT_MAX_FINDINGS, 1), MAX_FINDINGS);
  const fingerprints = normalizeFingerprintInputs(params).slice(0, 10);
  if (fingerprints.length === 0) {
    return {
      ok: false,
      source: CVE_SOURCE,
      error: "Expected software/version or fingerprints from osint_url_snapshot.fingerprint.fingerprints.",
    };
  }
  const cache = params.cache ?? new OsintCache();
  const closeCache = !params.cache;
  try {
    const results = await Promise.all(
      fingerprints.map((fingerprint) =>
        lookupFingerprintCves({
          fingerprint,
          maxFindings,
          refresh: params.refresh,
          signal: params.signal,
          cache,
        })
      ),
    );
    return {
      ok: true,
      source: CVE_SOURCE,
      results,
      summary: {
        fingerprintsChecked: results.length,
        withConcreteVersion: results.filter((result) => result.version).length,
        withMappedIdentity: results.filter((result) => result.identities.length > 0).length,
        findings: results.reduce((sum, result) => sum + result.findings.length, 0),
        impactFocus: ["rce", "crash", "bleed", "hop"],
      },
      caveat:
        "CVE matching is bounded and conservative. Versionless or unmapped fingerprints are skipped; source data may lag vendor advisories.",
    };
  } finally {
    if (closeCache) {
      cache.close();
    }
  }
}

async function lookupFingerprintCves(params: {
  fingerprint: NormalizedFingerprint;
  maxFindings: number;
  refresh?: boolean;
  signal?: AbortSignal;
  cache: OsintCache;
}): Promise<FingerprintCveResult> {
  const identities = identityForFingerprint(params.fingerprint);
  const base = {
    name: params.fingerprint.name,
    ...(params.fingerprint.version ? { version: params.fingerprint.version } : {}),
    identities,
  };
  if (!params.fingerprint.version) {
    return {
      ...base,
      skipped: "missing_version",
      findings: [],
      caveat: "No concrete version was detected, so broad CVE lookup was skipped.",
    };
  }
  if (identities.length === 0) {
    return {
      ...base,
      skipped: "unmapped_identity",
      findings: [],
      caveat: "No bounded NVD CPE or OSV package mapping exists for this fingerprint.",
    };
  }
  let fetched: CveFinding[][];
  try {
    fetched = await Promise.all(identities.map((identity) =>
      cachedIdentityLookup({
        identity,
        version: params.fingerprint.version!,
        refresh: params.refresh,
        signal: params.signal,
        cache: params.cache,
      })
    ));
  } catch (error) {
    return {
      ...base,
      findings: [],
      error: formatError(error),
      caveat: "The fingerprint mapped to a CVE source, but the source lookup failed; other pipeline stages remain usable.",
    };
  }
  const findings = dedupeFindings(fetched.flatMap((items) => items))
    .filter((finding) => finding.impactTags.length > 0)
    .sort(compareFindings)
    .slice(0, params.maxFindings);
  return {
    ...base,
    findings,
    caveat:
      findings.length === 0
        ? "No RCE/crash/bleed/hop-shaped CVEs matched the mapped identity/version in the queried sources."
        : "Findings are filtered to RCE and adjacent crash/bleed/hop impact shapes.",
  };
}

async function cachedIdentityLookup(params: {
  identity: VulnerabilityIdentity;
  version: string;
  refresh?: boolean;
  signal?: AbortSignal;
  cache: OsintCache;
}): Promise<CveFinding[]> {
  const target = `${identityKey(params.identity)}@${params.version}`;
  const fresh = params.refresh ? undefined : params.cache.getFreshSource(CVE_SOURCE, target);
  if (fresh) {
    return JSON.parse(fresh.rawJson) as CveFinding[];
  }
  const fetchedAt = Date.now();
  const findings = params.identity.source === "nvd"
    ? await fetchNvdCves(params.identity.cpe, params.signal)
    : await fetchOsvVulnerabilities(params.identity, params.version, params.signal);
  const rawJson = JSON.stringify(findings);
  params.cache.putSource({
    source: CVE_SOURCE,
    target,
    fetchedAt,
    expiresAt: fetchedAt + CVE_TTL_MS,
    rawJson,
    rawBytes: Buffer.byteLength(rawJson),
    status: "ok",
  });
  return findings;
}

async function fetchNvdCves(cpe: string, signal?: AbortSignal): Promise<CveFinding[]> {
  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
  url.searchParams.set("virtualMatchString", cpe);
  url.searchParams.set("noRejected", "");
  url.searchParams.set("resultsPerPage", "20");
  const guarded = await fetchWithSsrFGuard({
    url: url.toString(),
    init: {
      headers: {
        Accept: "application/json",
        "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
      },
    },
    timeoutMs: CVE_TIMEOUT_MS,
    signal,
    auditContext: "openclaw-osint-nvd-cve",
  });
  const { response, release } = guarded;
  try {
    if (!response.ok) {
      throw new Error(`NVD returned HTTP ${response.status}`);
    }
    return parseNvdFindings(JSON.parse(await readResponseTextBounded(response, MAX_RESPONSE_BYTES)));
  } finally {
    await release();
  }
}

async function fetchOsvVulnerabilities(
  identity: Extract<VulnerabilityIdentity, { source: "osv" }>,
  version: string,
  signal?: AbortSignal,
): Promise<CveFinding[]> {
  const guarded = await fetchWithSsrFGuard({
    url: "https://api.osv.dev/v1/query",
    init: {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
      },
      body: JSON.stringify({
        version,
        package: {
          name: identity.packageName,
          ecosystem: identity.ecosystem,
        },
      }),
    },
    timeoutMs: CVE_TIMEOUT_MS,
    signal,
    auditContext: "openclaw-osint-osv-query",
  });
  const { response, release } = guarded;
  try {
    if (!response.ok) {
      throw new Error(`OSV returned HTTP ${response.status}`);
    }
    return parseOsvFindings(JSON.parse(await readResponseTextBounded(response, MAX_RESPONSE_BYTES)));
  } finally {
    await release();
  }
}

function normalizeFingerprintInputs(params: FingerprintCveLookupParams): NormalizedFingerprint[] {
  const values = [
    ...(params.software ? [{ name: params.software, ...(params.version ? { version: params.version } : {}) }] : []),
    ...(params.fingerprints ?? []),
  ];
  const seen = new Set<string>();
  return values.flatMap((item) => {
    const name = cleanName(item.name);
    const version = cleanVersion(item.version);
    if (!name) {
      return [];
    }
    const key = `${name.toLowerCase()}@${version ?? ""}`;
    if (seen.has(key)) {
      return [];
    }
    seen.add(key);
    return [{
      name,
      ...(version ? { version } : {}),
      ...(item.confidence ? { confidence: item.confidence } : {}),
      ...(item.source ? { source: item.source } : {}),
      ...(item.evidence ? { evidence: item.evidence.slice(0, 3) } : {}),
    }];
  });
}

function identityForFingerprint(fingerprint: NormalizedFingerprint): VulnerabilityIdentity[] {
  if (!fingerprint.version) {
    return [];
  }
  const name = fingerprint.name.toLowerCase();
  const version = fingerprint.version;
  if (name === "nginx") {
    return [{ source: "nvd", type: "cpe", cpe: `cpe:2.3:a:nginx:nginx:${version}:*:*:*:*:*:*:*` }];
  }
  if (name === "apache httpd" || name === "apache" || name === "apache http server") {
    return [{ source: "nvd", type: "cpe", cpe: `cpe:2.3:a:apache:http_server:${version}:*:*:*:*:*:*:*` }];
  }
  if (name === "caddy") {
    return [{ source: "nvd", type: "cpe", cpe: `cpe:2.3:a:caddyserver:caddy:${version}:*:*:*:*:*:*:*` }];
  }
  if (name === "php") {
    return [{ source: "nvd", type: "cpe", cpe: `cpe:2.3:a:php:php:${version}:*:*:*:*:*:*:*` }];
  }
  if (name === "gunicorn") {
    return [{ source: "osv", type: "package", ecosystem: "PyPI", packageName: "gunicorn" }];
  }
  if (name === "uvicorn") {
    return [{ source: "osv", type: "package", ecosystem: "PyPI", packageName: "uvicorn" }];
  }
  if (name === "flask/werkzeug") {
    return [
      { source: "osv", type: "package", ecosystem: "PyPI", packageName: "flask" },
      { source: "osv", type: "package", ecosystem: "PyPI", packageName: "werkzeug" },
    ];
  }
  if (name === "flask" || name === "werkzeug") {
    return [{ source: "osv", type: "package", ecosystem: "PyPI", packageName: name }];
  }
  if (name === "django") {
    return [{ source: "osv", type: "package", ecosystem: "PyPI", packageName: "django" }];
  }
  if (name === "express") {
    return [{ source: "osv", type: "package", ecosystem: "npm", packageName: "express" }];
  }
  if (name === "next.js" || name === "nextjs") {
    return [{ source: "osv", type: "package", ecosystem: "npm", packageName: "next" }];
  }
  if (name === "react") {
    return [{ source: "osv", type: "package", ecosystem: "npm", packageName: "react" }];
  }
  if (name === "preact") {
    return [{ source: "osv", type: "package", ecosystem: "npm", packageName: "preact" }];
  }
  if (name === "three.js" || name === "three") {
    return [{ source: "osv", type: "package", ecosystem: "npm", packageName: "three" }];
  }
  return [];
}

function parseNvdFindings(value: unknown): CveFinding[] {
  const vulnerabilities = Array.isArray((value as { vulnerabilities?: unknown[] })?.vulnerabilities)
    ? (value as { vulnerabilities: unknown[] }).vulnerabilities
    : [];
  return vulnerabilities.flatMap((item) => {
    const cve = (item as { cve?: Record<string, unknown> })?.cve;
    if (!cve) {
      return [];
    }
    const id = typeof cve.id === "string" ? cve.id : undefined;
    const descriptions = Array.isArray(cve.descriptions) ? cve.descriptions : [];
    const summary = stringAt(descriptions.find((entry) => stringAt(entry, "lang") === "en"), "value") ?? "";
    if (!id || !summary) {
      return [];
    }
    const metrics = nvdMetrics(cve.metrics);
    return [{
      id,
      source: "nvd" as const,
      ...(metrics.severity ? { severity: metrics.severity } : {}),
      ...(metrics.cvss !== undefined ? { cvss: metrics.cvss } : {}),
      impactTags: classifyImpact(`${summary} ${id}`),
      summary: compactSummary(summary),
      references: nvdReferences(cve.references).slice(0, 5),
      affected: "matched_version" as const,
      knownExploited: Boolean(cve.cisaExploitAdd),
    }];
  });
}

function parseOsvFindings(value: unknown): CveFinding[] {
  const vulns = Array.isArray((value as { vulns?: unknown[] })?.vulns)
    ? (value as { vulns: unknown[] }).vulns
    : [];
  return vulns.flatMap((vuln) => {
    const item = vuln as Record<string, unknown>;
    const id = typeof item.id === "string" ? item.id : undefined;
    const summary = [item.summary, item.details].filter((part): part is string => typeof part === "string").join(" ");
    if (!id || !summary) {
      return [];
    }
    return [{
      id,
      source: "osv" as const,
      impactTags: classifyImpact(summary),
      summary: compactSummary(summary),
      references: osvReferences(item.references).slice(0, 5),
      affected: "reported_by_source" as const,
    }];
  });
}

function classifyImpact(text: string): string[] {
  const lower = text.toLowerCase();
  const tags = new Set<string>();
  if (/\b(remote code execution|arbitrary code execution|execute arbitrary|command injection|code injection|rce)\b/.test(lower)) {
    tags.add("rce");
  }
  if (/\b(denial of service|dos|crash|panic|null pointer|segmentation fault|resource exhaustion|infinite loop)\b/.test(lower)) {
    tags.add("crash");
  }
  if (/\b(information disclosure|memory disclosure|memory leak|out-of-bounds read|buffer overread|sensitive information|data leak|leakage)\b/.test(lower)) {
    tags.add("bleed");
  }
  if (/\b(privilege escalation|authorization bypass|authentication bypass|path traversal|directory traversal|ssrf|server-side request forgery|request smuggling|deserialization)\b/.test(lower)) {
    tags.add("hop");
  }
  return Array.from(tags);
}

function compareFindings(a: CveFinding, b: CveFinding): number {
  return impactRank(b) - impactRank(a) || (b.cvss ?? 0) - (a.cvss ?? 0) || a.id.localeCompare(b.id);
}

function impactRank(finding: CveFinding): number {
  return (finding.impactTags.includes("rce") ? 8 : 0) +
    (finding.impactTags.includes("hop") ? 4 : 0) +
    (finding.impactTags.includes("bleed") ? 2 : 0) +
    (finding.impactTags.includes("crash") ? 1 : 0);
}

function dedupeFindings(items: readonly CveFinding[]): CveFinding[] {
  const byId = new Map<string, CveFinding>();
  for (const item of items) {
    const existing = byId.get(item.id);
    byId.set(item.id, existing
      ? {
        ...existing,
        impactTags: Array.from(new Set([...existing.impactTags, ...item.impactTags])),
        references: Array.from(new Set([...existing.references, ...item.references])).slice(0, 5),
        knownExploited: existing.knownExploited || item.knownExploited,
      }
      : item);
  }
  return Array.from(byId.values());
}

function nvdMetrics(value: unknown): { severity?: string; cvss?: number } {
  const metrics = value as Record<string, unknown> | undefined;
  const candidates = [
    ...arrayAt(metrics, "cvssMetricV40"),
    ...arrayAt(metrics, "cvssMetricV31"),
    ...arrayAt(metrics, "cvssMetricV30"),
    ...arrayAt(metrics, "cvssMetricV2"),
  ];
  for (const candidate of candidates) {
    const source = candidate as Record<string, unknown>;
    const data = source.cvssData as Record<string, unknown> | undefined;
    const severity = stringAt(source, "cvssData", "baseSeverity") ?? stringAt(source, "baseSeverity");
    const score = numberAt(data, "baseScore");
    if (severity || score !== undefined) {
      return {
        ...(severity ? { severity } : {}),
        ...(score !== undefined ? { cvss: score } : {}),
      };
    }
  }
  return {};
}

function nvdReferences(value: unknown): string[] {
  const references = Array.isArray(value) ? value : arrayAt(value, "referenceData");
  return references.flatMap((entry) => {
    const url = stringAt(entry, "url");
    const source = stringAt(entry, "source");
    const tags = arrayAt(entry, "tags").filter((tag): tag is string => typeof tag === "string");
    return url ? [`${url}${source || tags.length ? ` (${[source, ...tags].filter(Boolean).join("; ")})` : ""}`] : [];
  });
}

function osvReferences(value: unknown): string[] {
  return Array.isArray(value)
    ? value.flatMap((entry) => {
      const url = stringAt(entry, "url");
      return url ? [url] : [];
    })
    : [];
}

function identityKey(identity: VulnerabilityIdentity): string {
  return identity.source === "nvd"
    ? `nvd:${identity.cpe}`
    : `osv:${identity.ecosystem}:${identity.packageName}`;
}

function cleanName(value: unknown): string | undefined {
  return typeof value === "string" ? value.replace(/\s+/g, " ").trim() || undefined : undefined;
}

function cleanVersion(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const cleaned = value.trim().replace(/^v/i, "");
  return /^[0-9][0-9A-Za-z._+-]{0,64}$/.test(cleaned) ? cleaned : undefined;
}

function compactSummary(value: string): string {
  return value.replace(/\s+/g, " ").trim().slice(0, 500);
}

function stringAt(value: unknown, ...path: string[]): string | undefined {
  const found = path.reduce<unknown>((current, key) =>
    current && typeof current === "object" ? (current as Record<string, unknown>)[key] : undefined
  , value);
  return typeof found === "string" ? found : undefined;
}

function numberAt(value: unknown, ...path: string[]): number | undefined {
  const found = path.reduce<unknown>((current, key) =>
    current && typeof current === "object" ? (current as Record<string, unknown>)[key] : undefined
  , value);
  return typeof found === "number" ? found : undefined;
}

function arrayAt(value: unknown, ...path: string[]): unknown[] {
  const found = path.reduce<unknown>((current, key) =>
    current && typeof current === "object" ? (current as Record<string, unknown>)[key] : undefined
  , value);
  return Array.isArray(found) ? found : [];
}

async function readResponseTextBounded(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) {
    return "";
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (total < maxBytes) {
    const { done, value } = await reader.read();
    if (done || !value) {
      break;
    }
    const remaining = maxBytes - total;
    chunks.push(value.slice(0, remaining));
    total += Math.min(value.byteLength, remaining);
  }
  await reader.cancel().catch(() => undefined);
  return new TextDecoder().decode(Buffer.concat(chunks));
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export const testing = {
  classifyImpact,
  identityForFingerprint,
  normalizeFingerprintInputs,
  parseNvdFindings,
  parseOsvFindings,
};
