import { wrapWebContent } from "openclaw/plugin-sdk/security-runtime";
import { fetchWithSsrFGuard } from "openclaw/plugin-sdk/ssrf-runtime";
import { randomUUID } from "node:crypto";
import { Type, type Static } from "typebox";

const DEFAULT_MAX_TEXT_CHARS = 20_000;
const MAX_TEXT_CHARS = 100_000;
const DEFAULT_EXCERPT_CHARS = 4_000;
const MAX_EXCERPT_CHARS = 20_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const FETCH_TIMEOUT_MS = 12_000;
const MAX_INDICATORS_PER_TYPE = 100;
const DEFAULT_ERROR_PROBE_CHARS = 1_200;
const MAX_ERROR_PROBE_CHARS = 4_000;

export const ExtractIndicatorsSchema = Type.Object(
  {
    text: Type.String({
      description: "Text to analyze locally for public-source indicators. No network access.",
    }),
    maxTextChars: Type.Optional(
      Type.Integer({
        description: "Maximum input characters to inspect.",
        minimum: 100,
        maximum: MAX_TEXT_CHARS,
      }),
    ),
  },
  { additionalProperties: false },
);

export const UrlSnapshotSchema = Type.Object(
  {
    url: Type.String({
      description: "Public HTTP(S) URL to fetch through OpenClaw's SSRF guard.",
    }),
    maxExcerptChars: Type.Optional(
      Type.Integer({
        description: "Maximum text excerpt characters to return.",
        minimum: 200,
        maximum: MAX_EXCERPT_CHARS,
      }),
    ),
    includeFingerprint: Type.Optional(
      Type.Boolean({
        description: "Include passive software/OS fingerprint hints from headers, page markers, and one bounded 404 probe.",
      }),
    ),
    maxErrorProbeChars: Type.Optional(
      Type.Integer({
        description: "Maximum 404 error-page text characters to include when passive fingerprinting is enabled.",
        minimum: 200,
        maximum: MAX_ERROR_PROBE_CHARS,
      }),
    ),
  },
  { additionalProperties: false },
);

type ExtractedIndicators = {
  urls: string[];
  domains: string[];
  ipv4: string[];
  emails: string[];
  phones: string[];
  handles: string[];
  hashes: string[];
};

type UrlSnapshotResult =
  | {
      ok: true;
      url: string;
      finalUrl: string;
      status: number;
      contentType?: string;
      title?: string;
      description?: string;
      canonicalUrl?: string;
      fingerprint?: PassiveFingerprintResult;
      excerpt: string;
      truncated: boolean;
    }
  | {
      ok: false;
      url?: string;
      error: string;
    };

type ExtractIndicatorsParams = Static<typeof ExtractIndicatorsSchema>;
type UrlSnapshotParams = Static<typeof UrlSnapshotSchema>;

export function extractIndicatorsForTool(params: ExtractIndicatorsParams): ExtractedIndicators {
  const maxTextChars = params.maxTextChars ?? DEFAULT_MAX_TEXT_CHARS;
  return extractIndicators(params.text.slice(0, maxTextChars));
}

export function snapshotUrlForTool(
  params: UrlSnapshotParams & { signal?: AbortSignal },
): Promise<UrlSnapshotResult> {
  return snapshotUrl({
    url: params.url,
    maxExcerptChars: params.maxExcerptChars ?? DEFAULT_EXCERPT_CHARS,
    includeFingerprint: params.includeFingerprint ?? true,
    maxErrorProbeChars: params.maxErrorProbeChars ?? DEFAULT_ERROR_PROBE_CHARS,
    signal: params.signal,
  });
}

type FingerprintEvidence = {
  kind: "software" | "framework" | "os";
  name: string;
  version?: string;
  confidence: "low" | "medium" | "high";
  source: string;
  evidence: string[];
};

type PassiveFingerprintResult = {
  fingerprints: FingerprintEvidence[];
  errorProbe?: {
    url: string;
    status: number;
    contentType?: string;
    title?: string;
    excerpt: string;
    truncated: boolean;
  };
  caveat: string;
};

function extractIndicators(text: string): ExtractedIndicators {
  const urls = collectMatches(text, /\bhttps?:\/\/[^\s<>"')\]}]+/gi, normalizeUrlText);
  const emails = collectMatches(
    text,
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    (value) => value.toLowerCase(),
  );
  const ipv4 = collectMatches(
    text,
    /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  );
  const handles = collectMatches(
    text,
    /(?<![\w@])@[A-Z0-9_][A-Z0-9_.-]{1,30}\b/gi,
    (value) => value.toLowerCase(),
  );
  const phones = collectMatches(
    text,
    /(?<![\w.+-])(?:\+1[\s.-]*)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}\b/g,
    normalizePhoneText,
  );
  const hashes = collectMatches(text, /\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b/gi, (
    value,
  ) => value.toLowerCase());
  const domains = collectDomains(text, urls, emails);
  return { urls, domains, ipv4, emails, phones, handles, hashes };
}

async function snapshotUrl(params: {
  url: string;
  maxExcerptChars: number;
  includeFingerprint: boolean;
  maxErrorProbeChars: number;
  signal?: AbortSignal;
}): Promise<UrlSnapshotResult> {
  const normalizedUrl = normalizePublicHttpUrl(params.url);
  if (!normalizedUrl) {
    return { ok: false, error: "Expected a public HTTP(S) URL." };
  }

  let guarded;
  try {
    guarded = await fetchWithSsrFGuard({
      url: normalizedUrl,
      init: {
        headers: {
          Accept: "text/html,text/plain,application/xhtml+xml,*/*;q=0.2",
          "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
        },
      },
      timeoutMs: FETCH_TIMEOUT_MS,
      signal: params.signal,
      auditContext: "openclaw-osint-url-snapshot",
    });
  } catch (error) {
    return { ok: false, url: normalizedUrl, error: formatError(error) };
  }

  const { response, finalUrl, release } = guarded;
  try {
    const contentType = response.headers.get("content-type") ?? undefined;
    const body = await readResponseTextBounded(response, MAX_RESPONSE_BYTES);
    const metadata = parseHtmlMetadata(body, finalUrl);
    const visibleText = htmlToVisibleText(body).slice(0, params.maxExcerptChars);
    const fingerprint = params.includeFingerprint
      ? await buildPassiveFingerprint({
        normalizedUrl,
        finalUrl,
        response,
        body,
        maxErrorProbeChars: params.maxErrorProbeChars,
        signal: params.signal,
      })
      : undefined;
    return {
      ok: true,
      url: normalizedUrl,
      finalUrl,
      status: response.status,
      ...(contentType ? { contentType } : {}),
      ...(metadata.title ? { title: wrapWebContent(metadata.title, "web_fetch") } : {}),
      ...(metadata.description
        ? { description: wrapWebContent(metadata.description, "web_fetch") }
        : {}),
      ...(metadata.canonicalUrl ? { canonicalUrl: metadata.canonicalUrl } : {}),
      ...(fingerprint ? { fingerprint } : {}),
      excerpt: wrapWebContent(visibleText, "web_fetch"),
      truncated: body.length >= MAX_RESPONSE_BYTES || visibleText.length >= params.maxExcerptChars,
    };
  } catch (error) {
    return { ok: false, url: normalizedUrl, error: formatError(error) };
  } finally {
    await release();
  }
}

async function buildPassiveFingerprint(params: {
  normalizedUrl: string;
  finalUrl: string;
  response: Response;
  body: string;
  maxErrorProbeChars: number;
  signal?: AbortSignal;
}): Promise<PassiveFingerprintResult> {
  const fingerprints = fingerprintFromHttpEvidence({
    headers: params.response.headers,
    html: params.body,
    source: "initial_response",
  });
  const errorProbe = await fetch404FingerprintProbe({
    baseUrl: params.finalUrl || params.normalizedUrl,
    maxChars: params.maxErrorProbeChars,
    signal: params.signal,
  });
  if (errorProbe) {
    fingerprints.push(...fingerprintFromHttpEvidence({
      headers: errorProbe.headers,
      html: errorProbe.body,
      source: "404_probe",
    }));
  }
  return {
    fingerprints: dedupeFingerprints(fingerprints),
    ...(errorProbe ? { errorProbe: toErrorProbeResult(errorProbe, params.maxErrorProbeChars) } : {}),
    caveat: "Passive fingerprints are hints, not proof. OS inference is weak unless directly exposed in a banner or error page.",
  };
}

async function fetch404FingerprintProbe(params: {
  baseUrl: string;
  maxChars: number;
  signal?: AbortSignal;
}): Promise<{ url: string; status: number; contentType?: string; headers: Headers; body: string } | undefined> {
  const probeUrl = build404ProbeUrl(params.baseUrl);
  if (!probeUrl) {
    return undefined;
  }
  let guarded;
  try {
    guarded = await fetchWithSsrFGuard({
      url: probeUrl,
      init: {
        headers: {
          Accept: "text/html,text/plain,application/xhtml+xml,*/*;q=0.2",
          "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
        },
      },
      timeoutMs: FETCH_TIMEOUT_MS,
      signal: params.signal,
      auditContext: "openclaw-osint-404-fingerprint",
    });
  } catch {
    return undefined;
  }
  const { response, finalUrl, release } = guarded;
  try {
    const contentType = response.headers.get("content-type") ?? undefined;
    const body = await readResponseTextBounded(response, Math.min(params.maxChars * 4, MAX_RESPONSE_BYTES));
    return {
      url: finalUrl,
      status: response.status,
      ...(contentType ? { contentType } : {}),
      headers: response.headers,
      body,
    };
  } catch {
    return undefined;
  } finally {
    await release();
  }
}

function build404ProbeUrl(baseUrl: string): string | undefined {
  try {
    const parsed = new URL(baseUrl);
    parsed.pathname = `/__openclaw_osint_404_${randomUUID().replace(/-/g, "")}`;
    parsed.search = "";
    parsed.hash = "";
    return normalizePublicHttpUrl(parsed.toString());
  } catch {
    return undefined;
  }
}

function fingerprintFromHttpEvidence(params: {
  headers: Headers | Record<string, string | undefined>;
  html: string;
  source: string;
}): FingerprintEvidence[] {
  const header = (name: string) =>
    params.headers instanceof Headers
      ? params.headers.get(name) ?? undefined
      : params.headers[name.toLowerCase()] ?? params.headers[name];
  const evidence: FingerprintEvidence[] = [];
  const headerValues = [
    ["Server", header("server"), "medium"],
    ["X-Powered-By", header("x-powered-by"), "medium"],
    ["X-Generator", header("x-generator"), "medium"],
    ["Via", header("via"), "low"],
    ["X-AspNet-Version", header("x-aspnet-version"), "medium"],
    ["X-AspNetMvc-Version", header("x-aspnetmvc-version"), "medium"],
    ["X-Runtime", header("x-runtime"), "low"],
    ["X-Nextjs-Cache", header("x-nextjs-cache"), "medium"],
    ["X-Vercel-Id", header("x-vercel-id"), "medium"],
    ["X-Render-Origin-Server", header("x-render-origin-server"), "medium"],
    ["X-Drupal-Cache", header("x-drupal-cache"), "medium"],
  ] as const;
  for (const [label, value, confidence] of headerValues) {
    addHeaderFingerprint(evidence, "software", label, value, params.source, confidence);
    if (value) {
      evidence.push(...fingerprintFromText(value, params.source));
    }
  }
  evidence.push(...fingerprintFromCookies(header("set-cookie"), params.source));
  const generator = findFirst(
    params.html,
    /<meta\b(?=[^>]*\bname=["']generator["'])(?=[^>]*\bcontent=["']([^"']*)["'])[^>]*>/i,
  );
  if (generator) {
    addHeaderFingerprint(evidence, "software", "meta generator", decodeHtmlEntities(generator), params.source, "high");
  }
  evidence.push(...fingerprintFromText(params.html, params.source));
  return evidence;
}

function addHeaderFingerprint(
  target: FingerprintEvidence[],
  kind: FingerprintEvidence["kind"],
  label: string,
  value: string | undefined,
  source: string,
  confidence: FingerprintEvidence["confidence"] = "medium",
): void {
  const cleaned = value?.replace(/\s+/g, " ").trim();
  if (!cleaned) {
    return;
  }
  const parsed = parseProductVersion(cleaned);
  target.push({
    kind,
    name: parsed.name || label,
    ...(parsed.version ? { version: parsed.version } : {}),
    confidence,
    source,
    evidence: [`${label}: ${cleaned}`],
  });
}

function fingerprintFromText(input: string, source: string): FingerprintEvidence[] {
  const text = input.slice(0, MAX_RESPONSE_BYTES);
  const checks: Array<[RegExp, FingerprintEvidence]> = [
    [/\bNode\.js\/([0-9][^\s<]*)/i, softwareEvidence("Node.js", source, "high")],
    [/\bnode:internal\/[a-z0-9_/-]+/i, softwareEvidence("Node.js", source, "high")],
    [/\bExpress\b/i, frameworkEvidence("Express", source, "medium")],
    [/\bCannot\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\/[^\s<]*/i, frameworkEvidence("Express", source, "high")],
    [/\buvicorn(?:\/([0-9][^\s<]*))?/i, softwareEvidence("Uvicorn", source, "high")],
    [/\bgunicorn(?:\/([0-9][^\s<]*))?/i, softwareEvidence("Gunicorn", source, "high")],
    [/\bStarlette\b/i, frameworkEvidence("Starlette", source, "high")],
    [/\bFastAPI\b/i, frameworkEvidence("FastAPI", source, "high")],
    [/\{\s*"detail"\s*:\s*"Not Found"\s*\}/i, frameworkEvidence("FastAPI/Starlette", source, "medium")],
    [/\bTraceback \(most recent call last\):[\s\S]{0,1200}\b(?:fastapi|starlette|uvicorn)\b/i, frameworkEvidence("FastAPI/Starlette/Uvicorn", source, "high")],
    [/\bWerkzeug\/([0-9][^\s<]*)/i, frameworkEvidence("Werkzeug", source, "high")],
    [/\bFlask\b/i, frameworkEvidence("Flask", source, "medium")],
    [/Not Found[\s\S]{0,200}The requested URL was not found on the server/i, frameworkEvidence("Flask/Werkzeug", source, "medium")],
    [/\bDjango\b/i, frameworkEvidence("Django", source, "high")],
    [/Using the URLconf defined in[\s\S]{0,400}Django tried these URL patterns/i, frameworkEvidence("Django", source, "high")],
    [/\bRuby on Rails\b|\bRails\b/i, frameworkEvidence("Ruby on Rails", source, "medium")],
    [/Action Controller:\s*Exception caught|Routing Error/i, frameworkEvidence("Ruby on Rails", source, "high")],
    [/\bLaravel\b/i, frameworkEvidence("Laravel", source, "medium")],
    [/Whoops, looks like something went wrong|Illuminate\\[A-Za-z\\]+/i, frameworkEvidence("Laravel", source, "high")],
    [/\bSpring Boot\b|\bWhitelabel Error Page\b/i, frameworkEvidence("Spring Boot", source, "high")],
    [/\bTomcat\/([0-9][^\s<]*)/i, softwareEvidence("Apache Tomcat", source, "high")],
    [/\bApache\/([0-9][^\s<]*)/i, softwareEvidence("Apache httpd", source, "high")],
    [/\bnginx\/([0-9][^\s<]*)/i, softwareEvidence("nginx", source, "high")],
    [/\bMicrosoft-IIS\/([0-9][^\s<]*)/i, softwareEvidence("Microsoft IIS", source, "high")],
    [/\bOpenResty\/([0-9][^\s<]*)/i, softwareEvidence("OpenResty", source, "high")],
    [/\bCaddy\b(?:\/([0-9][^\s<]*))?/i, softwareEvidence("Caddy", source, "medium")],
    [/\bLiteSpeed\b(?:\/([0-9][^\s<]*))?/i, softwareEvidence("LiteSpeed", source, "medium")],
    [/\bPHP\/([0-9][^\s<]*)/i, softwareEvidence("PHP", source, "high")],
    [/\bASP\.NET\b/i, frameworkEvidence("ASP.NET", source, "medium")],
    [/\bCloudflare\b/i, softwareEvidence("Cloudflare", source, "medium")],
    [/\bAkamaiGHost\b|\bAkamai\b/i, softwareEvidence("Akamai", source, "medium")],
    [/\bAmazonS3\b/i, softwareEvidence("Amazon S3 static hosting", source, "medium")],
    [/\bGoogle Frontend\b/i, softwareEvidence("Google Frontend", source, "medium")],
    [/\bVercel\b/i, softwareEvidence("Vercel", source, "medium")],
    [/\bNetlify\b/i, softwareEvidence("Netlify", source, "medium")],
    [/\bHeroku\b/i, softwareEvidence("Heroku", source, "medium")],
    [/\bRender\b/i, softwareEvidence("Render", source, "medium")],
    [/\bUbuntu\b/i, osEvidence("Ubuntu Linux", source)],
    [/\bDebian\b/i, osEvidence("Debian Linux", source)],
    [/\bCentOS\b/i, osEvidence("CentOS Linux", source)],
    [/\bAlmaLinux\b/i, osEvidence("AlmaLinux", source)],
    [/\bWindows Server\b/i, osEvidence("Windows Server", source)],
    [/\/wp-content\/|\/wp-includes\//i, frameworkEvidence("WordPress", source, "high")],
    [/\/_next\/static\//i, frameworkEvidence("Next.js", source, "high")],
    [/id=["']__next["']|__NEXT_DATA__/i, frameworkEvidence("Next.js", source, "high")],
    [/data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__/i, frameworkEvidence("React", source, "medium")],
    [/id=["']root["'][\s\S]{0,300}<script[^>]+\/static\/js\/main\.[^"']+\.js/i, frameworkEvidence("Create React App-style frontend", source, "medium")],
    [/ng-version=["'][^"']+["']/i, frameworkEvidence("Angular", source, "high")],
    [/data-v-[a-f0-9]{6,}|id=["']app["'][\s\S]{0,500}\/assets\/[^"']+\.js/i, frameworkEvidence("Vue/Vite-style frontend", source, "low")],
    [/\/build\/assets\/[^"']+\.js/i, frameworkEvidence("Laravel/Vite-style frontend", source, "low")],
    [/\/assets\/index-[A-Za-z0-9_-]+\.js/i, frameworkEvidence("Vite-style bundled frontend", source, "low")],
    [/\/sites\/default\/files\/|Drupal\.settings|data-drupal-selector/i, frameworkEvidence("Drupal", source, "high")],
    [/\/skin\/frontend\/|\/static\/version\d+\/frontend\//i, frameworkEvidence("Magento", source, "medium")],
  ];
  return checks.flatMap(([pattern, base]) => {
    const match = text.match(pattern);
    if (!match) {
      return [];
    }
    return [{
      ...base,
      ...(match[1] ? { version: match[1] } : {}),
      evidence: [textSnippetAround(text, match.index ?? 0)],
    }];
  });
}

function fingerprintFromCookies(value: string | undefined, source: string): FingerprintEvidence[] {
  if (!value) {
    return [];
  }
  const checks: Array<[RegExp, FingerprintEvidence]> = [
    [/\bconnect\.sid=/i, frameworkEvidence("Express session middleware", source, "medium")],
    [/\bnext-auth\./i, frameworkEvidence("NextAuth.js", source, "medium")],
    [/\bcsrftoken=/i, frameworkEvidence("Django", source, "low")],
    [/\bsessionid=/i, frameworkEvidence("Django-style session", source, "low")],
    [/\blaravel_session=/i, frameworkEvidence("Laravel", source, "medium")],
    [/\bXSRF-TOKEN=/i, frameworkEvidence("Laravel/Sanctum-style CSRF", source, "low")],
    [/\bPHPSESSID=/i, softwareEvidence("PHP", source, "medium")],
    [/\bASP\.NET_SessionId=/i, frameworkEvidence("ASP.NET", source, "medium")],
    [/\bJSESSIONID=/i, frameworkEvidence("Java servlet container", source, "medium")],
    [/\b__Host-next-auth\.csrf-token=/i, frameworkEvidence("NextAuth.js", source, "high")],
  ];
  return checks.flatMap(([pattern, base]) => {
    const match = value.match(pattern);
    if (!match) {
      return [];
    }
    return [{ ...base, evidence: [`Set-Cookie contains ${match[0].replace(/=.*/g, "=")}...`] }];
  });
}

function softwareEvidence(
  name: string,
  source: string,
  confidence: FingerprintEvidence["confidence"],
): FingerprintEvidence {
  return { kind: "software", name, confidence, source, evidence: [] };
}

function frameworkEvidence(
  name: string,
  source: string,
  confidence: FingerprintEvidence["confidence"],
): FingerprintEvidence {
  return { kind: "framework", name, confidence, source, evidence: [] };
}

function osEvidence(name: string, source: string): FingerprintEvidence {
  return { kind: "os", name, confidence: "low", source, evidence: [] };
}

function parseProductVersion(value: string): { name: string; version?: string } {
  const firstProduct = value.split(/\s+/)[0] ?? value;
  const match = firstProduct.match(/^([^/;()]+)\/([^;()\s]+)$/);
  if (match?.[1] && match[2]) {
    return { name: normalizeProductName(match[1]), version: match[2] };
  }
  return { name: normalizeProductName(firstProduct.replace(/[;()].*$/g, "")) };
}

function normalizeProductName(value: string): string {
  const cleaned = value.replace(/[-_]+/g, " ").trim();
  if (/^apache$/i.test(cleaned)) {
    return "Apache httpd";
  }
  if (/^microsoft iis$/i.test(cleaned)) {
    return "Microsoft IIS";
  }
  return cleaned || value;
}

function textSnippetAround(text: string, index: number): string {
  return text.slice(Math.max(0, index - 80), index + 180).replace(/\s+/g, " ").trim();
}

function dedupeFingerprints(items: readonly FingerprintEvidence[]): FingerprintEvidence[] {
  const byKey = new Map<string, FingerprintEvidence>();
  for (const item of items) {
    const key = `${item.kind}:${item.name.toLowerCase()}:${item.version ?? ""}`;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, item);
      continue;
    }
    byKey.set(key, {
      ...existing,
      confidence: strongerConfidence(existing.confidence, item.confidence),
      evidence: Array.from(new Set([...existing.evidence, ...item.evidence])).slice(0, 4),
      source: Array.from(new Set([existing.source, item.source])).join("+"),
    });
  }
  return Array.from(byKey.values()).slice(0, 20);
}

function strongerConfidence(
  left: FingerprintEvidence["confidence"],
  right: FingerprintEvidence["confidence"],
): FingerprintEvidence["confidence"] {
  const rank = { low: 0, medium: 1, high: 2 };
  return rank[right] > rank[left] ? right : left;
}

function toErrorProbeResult(
  probe: { url: string; status: number; contentType?: string; body: string },
  maxChars: number,
) {
  const metadata = parseHtmlMetadata(probe.body, probe.url);
  const visibleText = htmlToVisibleText(probe.body).slice(0, maxChars);
  return {
    url: probe.url,
    status: probe.status,
    ...(probe.contentType ? { contentType: probe.contentType } : {}),
    ...(metadata.title ? { title: wrapWebContent(metadata.title, "web_fetch") } : {}),
    excerpt: wrapWebContent(visibleText, "web_fetch"),
    truncated: probe.body.length >= Math.min(maxChars * 4, MAX_RESPONSE_BYTES) || visibleText.length >= maxChars,
  };
}

function collectDomains(text: string, urls: readonly string[], emails: readonly string[]): string[] {
  const urlDomains = urls
    .map((url) => {
      try {
        return new URL(url).hostname.toLowerCase();
      } catch {
        return "";
      }
    })
    .filter(Boolean);
  const emailDomains = emails
    .map((email) => email.split("@")[1]?.toLowerCase() ?? "")
    .filter(Boolean);
  const bareDomains = collectMatches(
    text,
    /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi,
    (value) => value.toLowerCase(),
  );
  return uniqueBounded([...urlDomains, ...emailDomains, ...bareDomains]);
}

function collectMatches(
  text: string,
  pattern: RegExp,
  normalize: (value: string) => string = (value) => value,
): string[] {
  return uniqueBounded(
    Array.from(text.matchAll(pattern))
      .map((match) => normalize(match[0] ?? ""))
      .filter(Boolean),
  );
}

function uniqueBounded(values: readonly string[]): string[] {
  return Array.from(new Set(values)).slice(0, MAX_INDICATORS_PER_TYPE);
}

function normalizeUrlText(value: string): string {
  return value.replace(/[.,;:!?]+$/g, "");
}

function normalizePhoneText(value: string): string {
  const digits = value.replace(/\D/g, "");
  if (digits.length === 10) {
    return `+1${digits}`;
  }
  if (digits.length === 11 && digits.startsWith("1")) {
    return `+${digits}`;
  }
  return "";
}

function normalizePublicHttpUrl(input: string): string | undefined {
  let parsed: URL;
  try {
    parsed = new URL(input.trim());
  } catch {
    return undefined;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return undefined;
  }
  parsed.hash = "";
  return parsed.toString();
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

function parseHtmlMetadata(input: string, baseUrl?: string) {
  const canonicalUrl = normalizeCanonicalUrl(
    decodeHtmlEntities(
      findFirst(
        input,
        /<link\b(?=[^>]*\brel=["']canonical["'])(?=[^>]*\bhref=["']([^"']*)["'])[^>]*>/i,
      ),
    ),
    baseUrl,
  );
  return {
    title: decodeHtmlEntities(findFirst(input, /<title[^>]*>([\s\S]*?)<\/title>/i)),
    description: decodeHtmlEntities(
      findFirst(
        input,
        /<meta\b(?=[^>]*\bname=["']description["'])(?=[^>]*\bcontent=["']([^"']*)["'])[^>]*>/i,
      ),
    ),
    canonicalUrl,
  };
}

function normalizeCanonicalUrl(input: string | undefined, baseUrl?: string): string | undefined {
  if (!input) {
    return undefined;
  }
  try {
    const parsed = baseUrl ? new URL(input, baseUrl) : new URL(input);
    return normalizePublicHttpUrl(parsed.toString());
  } catch {
    return undefined;
  }
}

function htmlToVisibleText(input: string): string {
  return decodeHtmlEntities(
    input
      .replace(/<script\b[\s\S]*?<\/script>/gi, " ")
      .replace(/<style\b[\s\S]*?<\/style>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
      .trim(),
  ) ?? "";
}

function findFirst(input: string, pattern: RegExp): string | undefined {
  return input.match(pattern)?.[1]?.replace(/\s+/g, " ").trim() || undefined;
}

function decodeHtmlEntities(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  return value
    .replace(/&#(\d+);/g, (_match, code: string) => String.fromCodePoint(Number(code)))
    .replace(/&#x([0-9a-f]+);/gi, (_match, code: string) =>
      String.fromCodePoint(Number.parseInt(code, 16)),
    )
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">");
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export const testing = {
  build404ProbeUrl,
  extractIndicators,
  fingerprintFromHttpEvidence,
  htmlToVisibleText,
  normalizeCanonicalUrl,
  normalizePhoneText,
  normalizePublicHttpUrl,
  parseHtmlMetadata,
};
