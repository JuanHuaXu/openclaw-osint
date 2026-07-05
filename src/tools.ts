import { wrapWebContent } from "openclaw/plugin-sdk/security-runtime";
import { fetchWithSsrFGuard } from "openclaw/plugin-sdk/ssrf-runtime";
import { Type, type Static } from "typebox";

const DEFAULT_MAX_TEXT_CHARS = 20_000;
const MAX_TEXT_CHARS = 100_000;
const DEFAULT_EXCERPT_CHARS = 4_000;
const MAX_EXCERPT_CHARS = 20_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const FETCH_TIMEOUT_MS = 12_000;
const MAX_INDICATORS_PER_TYPE = 100;

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
    signal: params.signal,
  });
}

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
      excerpt: wrapWebContent(visibleText, "web_fetch"),
      truncated: body.length >= MAX_RESPONSE_BYTES || visibleText.length >= params.maxExcerptChars,
    };
  } catch (error) {
    return { ok: false, url: normalizedUrl, error: formatError(error) };
  } finally {
    await release();
  }
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
  extractIndicators,
  htmlToVisibleText,
  normalizeCanonicalUrl,
  normalizePhoneText,
  normalizePublicHttpUrl,
  parseHtmlMetadata,
};
