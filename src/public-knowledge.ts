import { fetchWithSsrFGuard } from "openclaw/plugin-sdk/ssrf-runtime";

const PUBLIC_KNOWLEDGE_SOURCE = "wikimedia-public-knowledge";
const LOOKUP_TIMEOUT_MS = 12_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_WIKIPEDIA_EXTRACT_CHARS = 700;
const MAX_RELATED = 6;

export async function queryPublicKnowledgeContextForTool(
  params: { queries: readonly string[]; maxRelated?: number; signal?: AbortSignal },
) {
  const queries = unique(params.queries.map(normalizeQuery).filter((value): value is string => Boolean(value)));
  const maxRelated = Math.min(Math.max(params.maxRelated ?? 4, 1), MAX_RELATED);
  try {
    for (const query of queries) {
      const entity = await searchWikidataEntity(query, params.signal);
      if (!entity) {
        continue;
      }
      const entityData = await fetchWikidataEntity(entity.id, params.signal);
      const facts = wikidataFactsFromEntity(entityData);
      const relatedLabels = await fetchWikidataEntityLabels(facts.relatedOrganizations.slice(0, maxRelated), params.signal);
      const summaryTitle = facts.wikipediaTitle;
      const wikipedia = summaryTitle ? await fetchWikipediaSummary(summaryTitle, params.signal) : undefined;
      return {
        ok: true,
        source: PUBLIC_KNOWLEDGE_SOURCE,
        matched: entity,
        facts: {
          aliases: facts.aliases.slice(0, maxRelated),
          officialWebsites: facts.officialWebsites.slice(0, maxRelated),
          tickerSymbols: facts.tickerSymbols.slice(0, maxRelated),
          relatedOrganizations: relatedLabels.map((label) => ({
            ...label,
            relation: facts.relatedOrganizations.find((item) => item.id === label.id)?.relation ?? "related",
          })),
          ...(summaryTitle ? { wikipediaTitle: summaryTitle } : {}),
        },
        ...(wikipedia ? { wikipedia } : {}),
        caveat:
          "Wikidata and Wikipedia are context leads only. Verify reputation, ownership, filings, and complaints with primary sources.",
      };
    }
    return {
      ok: false,
      source: PUBLIC_KNOWLEDGE_SOURCE,
      status: "not_found",
      error: "No matching Wikidata entity found for public-knowledge context.",
    };
  } catch (error) {
    return { ok: false, source: PUBLIC_KNOWLEDGE_SOURCE, error: formatError(error) };
  }
}

export function publicKnowledgeQueriesForDomain(domain: string): string[] {
  const normalized = normalizeDomain(domain);
  if (!normalized) {
    return [];
  }
  const labels = normalized.split(".").filter(Boolean);
  const brand = labels.length > 2 && labels.at(-1)?.length === 2 && COMMON_SECOND_LEVEL_SUFFIXES.has(labels.at(-2) ?? "")
    ? labels.at(-3)
    : labels.length > 1
    ? labels.at(-2)
    : labels[0];
  return brand ? [brand.replace(/[-_]+/g, " ")] : [];
}

export function publicKnowledgeQueriesForBusiness(business: string): string[] {
  const normalized = normalizeQuery(business);
  if (!normalized) {
    return [];
  }
  const stripped = stripBusinessDesignators(normalized);
  return unique([
    normalized,
    ...(stripped ? [stripped] : []),
    ...(stripped && stripped !== normalized ? [`${stripped} Inc.`] : []),
  ]);
}

export function publicKnowledgeBusinessNames(value: unknown): string[] {
  if (!value || typeof value !== "object" || !("ok" in value) || value.ok !== true || !("facts" in value)) {
    return [];
  }
  const facts = value.facts as Record<string, unknown>;
  const related = Array.isArray(facts.relatedOrganizations)
    ? facts.relatedOrganizations.flatMap((item) =>
      item && typeof item === "object" && "label" in item && typeof item.label === "string" ? [item.label] : []
    )
    : [];
  const aliases = Array.isArray(facts.aliases) ? facts.aliases.filter((item): item is string => typeof item === "string") : [];
  return unique([...related, ...aliases]).slice(0, MAX_RELATED);
}

export function publicKnowledgeTickers(value: unknown): string[] {
  if (!value || typeof value !== "object" || !("ok" in value) || value.ok !== true || !("facts" in value)) {
    return [];
  }
  const facts = value.facts as Record<string, unknown>;
  return Array.isArray(facts.tickerSymbols)
    ? unique(facts.tickerSymbols.filter((item): item is string => typeof item === "string"))
    : [];
}

async function searchWikidataEntity(query: string, signal?: AbortSignal) {
  const url = new URL("https://www.wikidata.org/w/api.php");
  url.searchParams.set("action", "wbsearchentities");
  url.searchParams.set("search", query);
  url.searchParams.set("language", "en");
  url.searchParams.set("format", "json");
  url.searchParams.set("limit", "1");
  const guarded = await guardedJsonFetch(url.toString(), "openclaw-osint-wikidata-public-search", signal);
  const row = Array.isArray(guarded?.search) ? guarded.search[0] : undefined;
  const id = typeof row?.id === "string" ? row.id : undefined;
  const label = typeof row?.label === "string" ? row.label.trim() : "";
  const description = typeof row?.description === "string" ? row.description.trim() : undefined;
  return id && label ? { id, label, query, ...(description ? { description } : {}) } : undefined;
}

async function fetchWikidataEntity(id: string, signal?: AbortSignal) {
  return guardedJsonFetch(
    `https://www.wikidata.org/wiki/Special:EntityData/${encodeURIComponent(id)}.json`,
    "openclaw-osint-wikidata-public-entity",
    signal,
  );
}

async function fetchWikidataEntityLabels(ids: Array<{ id: string; relation: string }>, signal?: AbortSignal) {
  if (ids.length === 0) {
    return [];
  }
  const url = new URL("https://www.wikidata.org/w/api.php");
  url.searchParams.set("action", "wbgetentities");
  url.searchParams.set("ids", ids.map((item) => item.id).join("|"));
  url.searchParams.set("props", "labels");
  url.searchParams.set("languages", "en");
  url.searchParams.set("format", "json");
  const parsed = await guardedJsonFetch(url.toString(), "openclaw-osint-wikidata-public-labels", signal);
  return normalizeWikidataLabels(parsed);
}

async function fetchWikipediaSummary(title: string, signal?: AbortSignal) {
  const url = `https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(title)}?redirect=true`;
  const parsed = await guardedJsonFetch(url, "openclaw-osint-wikipedia-public-summary", signal);
  return normalizeWikipediaSummary(parsed, url);
}

async function guardedJsonFetch(url: string, auditContext: string, signal?: AbortSignal) {
  const guarded = await fetchWithSsrFGuard({
    url,
    init: {
      headers: {
        Accept: "application/json",
        "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
      },
    },
    timeoutMs: LOOKUP_TIMEOUT_MS,
    signal,
    auditContext,
  });
  const { response, release } = guarded;
  try {
    if (!response.ok) {
      throw new Error(`${auditContext} returned HTTP ${response.status}`);
    }
    return JSON.parse(await readResponseTextBounded(response, MAX_RESPONSE_BYTES));
  } finally {
    await release();
  }
}

function wikidataFactsFromEntity(parsed: unknown) {
  const entity = firstWikidataEntity(parsed);
  const source = entity && typeof entity === "object" ? entity as Record<string, unknown> : {};
  const claims = source.claims && typeof source.claims === "object" ? source.claims as Record<string, unknown> : {};
  return {
    aliases: englishAliases(source),
    officialWebsites: stringClaimValues(claims.P856),
    tickerSymbols: stringClaimValues(claims.P249),
    relatedOrganizations: uniqueRelatedOrganizations([
      ...entityIdsFromClaims(claims.P355, "subsidiary"),
      ...entityIdsFromClaims(claims.P749, "parent"),
      ...entityIdsFromClaims(claims.P127, "owner"),
    ]),
    wikipediaTitle: wikipediaTitleFromEntity(source),
  };
}

function englishAliases(entity: Record<string, unknown>): string[] {
  const aliases = entity.aliases && typeof entity.aliases === "object" && "en" in entity.aliases && Array.isArray(entity.aliases.en)
    ? entity.aliases.en
    : [];
  return unique(aliases.flatMap((alias) =>
    alias && typeof alias === "object" && "value" in alias && typeof alias.value === "string"
      ? [alias.value.trim()]
      : []
  ));
}

function stringClaimValues(value: unknown): string[] {
  const rows = Array.isArray(value) ? value : [];
  return unique(rows.flatMap((row) => {
    const value = row && typeof row === "object"
      && "mainsnak" in row
      && row.mainsnak
      && typeof row.mainsnak === "object"
      && "datavalue" in row.mainsnak
      && row.mainsnak.datavalue
      && typeof row.mainsnak.datavalue === "object"
      && "value" in row.mainsnak.datavalue
      && typeof row.mainsnak.datavalue.value === "string"
      ? row.mainsnak.datavalue.value.trim()
      : "";
    return value ? [value] : [];
  }));
}

function entityIdsFromClaims(value: unknown, relation: string): Array<{ id: string; relation: string }> {
  const rows = Array.isArray(value) ? value : [];
  return rows.flatMap((row) => {
    const id = row && typeof row === "object"
      && "mainsnak" in row
      && row.mainsnak
      && typeof row.mainsnak === "object"
      && "datavalue" in row.mainsnak
      && row.mainsnak.datavalue
      && typeof row.mainsnak.datavalue === "object"
      && "value" in row.mainsnak.datavalue
      && row.mainsnak.datavalue.value
      && typeof row.mainsnak.datavalue.value === "object"
      && "id" in row.mainsnak.datavalue.value
      && typeof row.mainsnak.datavalue.value.id === "string"
      ? row.mainsnak.datavalue.value.id
      : "";
    return id ? [{ id, relation }] : [];
  });
}

function uniqueRelatedOrganizations(items: Array<{ id: string; relation: string }>) {
  return items.filter((item, index) => items.findIndex((candidate) => candidate.id === item.id) === index);
}

function wikipediaTitleFromEntity(entity: Record<string, unknown>): string | undefined {
  const title = entity.sitelinks
      && typeof entity.sitelinks === "object"
      && "enwiki" in entity.sitelinks
      && entity.sitelinks.enwiki
      && typeof entity.sitelinks.enwiki === "object"
      && "title" in entity.sitelinks.enwiki
      && typeof entity.sitelinks.enwiki.title === "string"
    ? entity.sitelinks.enwiki.title.trim()
    : "";
  return title || undefined;
}

function normalizeWikipediaSummary(parsed: unknown, finalUrl: string) {
  const source = parsed && typeof parsed === "object" ? parsed as Record<string, unknown> : {};
  const title = typeof source.title === "string" ? source.title.trim() : "";
  const extract = typeof source.extract === "string"
    ? source.extract.replace(/\s+/g, " ").trim().slice(0, MAX_WIKIPEDIA_EXTRACT_CHARS)
    : "";
  const description = typeof source.description === "string" ? source.description.trim() : undefined;
  const pageUrl = source.content_urls
      && typeof source.content_urls === "object"
      && "desktop" in source.content_urls
      && source.content_urls.desktop
      && typeof source.content_urls.desktop === "object"
      && "page" in source.content_urls.desktop
      && typeof source.content_urls.desktop.page === "string"
    ? source.content_urls.desktop.page
    : finalUrl;
  return {
    title,
    ...(description ? { description } : {}),
    extract,
    url: pageUrl,
  };
}

function normalizeWikidataLabels(parsed: unknown): Array<{ id: string; label: string }> {
  const entities = parsed && typeof parsed === "object" && "entities" in parsed && parsed.entities && typeof parsed.entities === "object"
    ? parsed.entities as Record<string, unknown>
    : {};
  return Object.entries(entities).flatMap(([id, entity]) => {
    const label = entity
        && typeof entity === "object"
        && "labels" in entity
        && entity.labels
        && typeof entity.labels === "object"
        && "en" in entity.labels
        && entity.labels.en
        && typeof entity.labels.en === "object"
        && "value" in entity.labels.en
        && typeof entity.labels.en.value === "string"
      ? entity.labels.en.value.trim()
      : "";
    return label ? [{ id, label }] : [];
  });
}

function firstWikidataEntity(parsed: unknown): unknown {
  const entities = parsed && typeof parsed === "object" && "entities" in parsed && parsed.entities && typeof parsed.entities === "object"
    ? Object.values(parsed.entities)
    : [];
  return entities[0];
}

async function readResponseTextBounded(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) {
    return (await response.text()).slice(0, maxBytes);
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (total < maxBytes) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (!value) {
        continue;
      }
      const remaining = maxBytes - total;
      chunks.push(value.byteLength > remaining ? value.slice(0, remaining) : value);
      total += Math.min(value.byteLength, remaining);
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

function normalizeQuery(value: string): string | undefined {
  const cleaned = value.replace(/\s+/g, " ").trim();
  return cleaned.length >= 2 && cleaned.length <= 160 ? cleaned : undefined;
}

function normalizeDomain(input: string): string | undefined {
  const value = input.trim().toLowerCase().replace(/\.$/, "");
  return /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value) && value.includes(".") ? value : undefined;
}

function stripBusinessDesignators(value: string): string | undefined {
  const stripped = value.replace(/\b(?:incorporated|inc|corp|corporation|co|company|llc|ltd|limited|plc|holdings?|group)\b\.?/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
  return stripped && stripped !== value.trim() ? stripped : undefined;
}

function unique(values: readonly string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const COMMON_SECOND_LEVEL_SUFFIXES = new Set(["ac", "co", "com", "edu", "gov", "net", "org"]);

export const testing = {
  publicKnowledgeQueriesForBusiness,
  publicKnowledgeQueriesForDomain,
  publicKnowledgeBusinessNames,
  publicKnowledgeTickers,
  wikidataFactsFromEntity,
};
