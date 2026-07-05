import { createHash } from "node:crypto";
import { fetchWithSsrFGuard } from "openclaw/plugin-sdk/ssrf-runtime";
import { Type, type Static } from "typebox";
import { OsintCache, type OsintObservation } from "./cache.js";

const BUSINESS_REPUTATION_SOURCE = "business-reputation";
const FTC_RELEASE_NOTICES_SOURCE = "ftc-release-notices";
const BBB_SEARCH_SOURCE = "bbb-business-search";
const SEC_COMPANY_TICKERS_SOURCE = "sec-company-tickers";
const SEC_SUBMISSIONS_SOURCE = "sec-submissions";
const MARKET_FINANCIALS_SOURCE = "market-financials";
const YAHOO_CHART_SOURCE = "yahoo-finance-chart";
const SEC_COMPANY_FACTS_SOURCE = "sec-company-facts";
const UK_COMPANIES_HOUSE_SOURCE = "uk-companies-house";
const EU_BRIS_SOURCE = "eu-bris-business-registers";
const AU_ABN_LOOKUP_SOURCE = "au-abn-lookup";
const JP_GBIZINFO_SOURCE = "jp-gbizinfo";
const CN_GSXT_SOURCE = "cn-gsxt";
const TW_GCIS_SOURCE = "tw-gcis";
const TAIWAN_COMPANY_REGISTRATION_DATASET_ID = "5F64D864-61CB-4D0D-8AD9-492047CC1EA6";
const BUSINESS_REPUTATION_TTL_MS = 12 * 60 * 60 * 1000;
const SEC_COMPANY_TICKERS_TTL_MS = 24 * 60 * 60 * 1000;
const MARKET_FINANCIALS_TTL_MS = 15 * 60 * 1000;
const LOOKUP_TIMEOUT_MS = 12_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const SEC_COMPANY_FACTS_MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_RESULTS = 5;
const MAX_RESULTS = 10;

export const BusinessReputationLookupSchema = Type.Object(
  {
    business: Type.String({
      description: "Company or organization name from public WHOIS/RDAP/BGP evidence.",
    }),
    domain: Type.Optional(
      Type.String({
        description:
          "Optional related domain for business-source query hints. This is context only, not proof of ownership.",
      }),
    ),
    ticker: Type.Optional(
      Type.String({
        description: "Optional public ticker symbol to improve SEC EDGAR matching.",
      }),
    ),
    registryId: Type.Optional(
      Type.String({
        description:
          "Optional jurisdictional business identifier such as a Taiwan UBN, Japan corporate number, China USCC, ABN, ACN, or company number.",
      }),
    ),
    maxResults: Type.Optional(
      Type.Integer({
        description: "Maximum FTC/BBB result leads to return. Defaults to 5, capped at 10.",
        minimum: 1,
        maximum: MAX_RESULTS,
      }),
    ),
    refresh: Type.Optional(Type.Boolean({ description: "Bypass fresh local cache." })),
  },
  { additionalProperties: false },
);

type BusinessReputationLookupParams = Static<typeof BusinessReputationLookupSchema>;

type SourceStatus = {
  source: string;
  status: "checked" | "missing_key" | "lead_only" | "error";
  detail?: string;
};

export async function queryBusinessReputationForTool(
  params: BusinessReputationLookupParams & { signal?: AbortSignal; cache?: OsintCache },
) {
  const business = normalizeBusinessName(params.business);
  if (!business) {
    return { ok: false, source: BUSINESS_REPUTATION_SOURCE, error: "Expected a public business or organization name." };
  }
  const domain = params.domain ? normalizeDomain(params.domain) : undefined;
  const ticker = params.ticker ? normalizeTicker(params.ticker) : undefined;
  const registryId = params.registryId ? normalizeRegistryId(params.registryId) : undefined;
  const maxResults = Math.min(Math.max(params.maxResults ?? DEFAULT_MAX_RESULTS, 1), MAX_RESULTS);
  const target = [business, domain, ticker, registryId].filter(Boolean).join("|");
  const cache = params.cache ?? new OsintCache();
  const closeCache = !params.cache;
  try {
    const fresh = params.refresh ? undefined : cache.getFreshSource(BUSINESS_REPUTATION_SOURCE, target);
    if (fresh) {
      return {
        ...JSON.parse(fresh.rawJson),
        cacheStatus: "hit",
        fetchedAt: fresh.fetchedAt,
        expiresAt: fresh.expiresAt,
      };
    }

    const fetchedAt = Date.now();
    const [ftcReleaseNotices, bbbSearch, financialDisclosures, marketFinancials, regionalDisclosures] = await Promise.all([
      queryFtcReleaseNotices(business, maxResults, params.signal),
      queryBbbBusinessSearch({ business, domain, maxResults, signal: params.signal }),
      querySecFinancialDisclosures({
        business,
        ticker,
        maxResults,
        signal: params.signal,
        cache,
        refresh: Boolean(params.refresh),
      }),
      queryMarketFinancials({
        business,
        ticker,
        maxResults,
        signal: params.signal,
        cache,
        refresh: Boolean(params.refresh),
      }),
      queryRegionalBusinessDisclosures({
        business,
        domain,
        registryId,
        maxResults,
        signal: params.signal,
      }),
    ]);
    const professionalProfileLeads = buildProfessionalProfileLeads(business, domain);
    const workplaceReviewLeads = buildWorkplaceReviewLeads(business, domain);
    const searchLeads = buildSearchLeads(business, domain);
    const result = {
      ok: true,
      source: BUSINESS_REPUTATION_SOURCE,
      business,
      ...(domain ? { domain } : {}),
      ...(ticker ? { ticker } : {}),
      ...(registryId ? { registryId } : {}),
      cacheStatus: "refreshed",
      fetchedAt,
      expiresAt: fetchedAt + BUSINESS_REPUTATION_TTL_MS,
      ftcReleaseNotices,
      bbbSearch,
      professionalProfileLeads,
      workplaceReviewLeads,
      financialDisclosures,
      marketFinancials,
      regionalDisclosures,
      searchLeads,
      sourceStatuses: [
        sourceStatusFromResult(FTC_RELEASE_NOTICES_SOURCE, ftcReleaseNotices),
        sourceStatusFromResult(BBB_SEARCH_SOURCE, bbbSearch),
        sourceStatusFromResult(SEC_SUBMISSIONS_SOURCE, financialDisclosures),
        sourceStatusFromResult(MARKET_FINANCIALS_SOURCE, marketFinancials),
        sourceStatusFromResult(UK_COMPANIES_HOUSE_SOURCE, regionalDisclosures.ukCompaniesHouse),
        sourceStatusFromResult(EU_BRIS_SOURCE, regionalDisclosures.euBusinessRegisters),
        sourceStatusFromResult(AU_ABN_LOOKUP_SOURCE, regionalDisclosures.auAbnLookup),
        sourceStatusFromResult(JP_GBIZINFO_SOURCE, regionalDisclosures.asiaBusinessRegisters.japan),
        sourceStatusFromResult(CN_GSXT_SOURCE, regionalDisclosures.asiaBusinessRegisters.china),
        sourceStatusFromResult(TW_GCIS_SOURCE, regionalDisclosures.asiaBusinessRegisters.taiwan),
      ],
      caveat:
        "Business lookups are reputation, registry, market-data, and disclosure leads, not identity proof, investment advice, or a complete complaint history. FTC Consumer Sentinel business complaint data is not public; BBB, LinkedIn, and Glassdoor results depend on public page coverage and availability. Market snapshots are time-sensitive and computed ratios are approximate. SEC, Companies House, BRIS, ABN Lookup, and Asia registry coverage depends on jurisdiction, public API availability, and configured credentials.",
    };
    const rawJson = JSON.stringify(result);
    cache.putSource({
      source: BUSINESS_REPUTATION_SOURCE,
      target,
      fetchedAt,
      expiresAt: fetchedAt + BUSINESS_REPUTATION_TTL_MS,
      rawJson,
      rawBytes: Buffer.byteLength(rawJson),
      status: "ok",
    });
    cache.replaceObservations(
      BUSINESS_REPUTATION_SOURCE,
      target,
      observationsFromBusinessLookup(target, result, fetchedAt),
    );
    return result;
  } catch (error) {
    return { ok: false, source: BUSINESS_REPUTATION_SOURCE, business, error: formatError(error) };
  } finally {
    if (closeCache) {
      cache.close();
    }
  }
}

async function queryFtcReleaseNotices(business: string, maxResults: number, signal?: AbortSignal) {
  if (!process.env.FTC_API_KEY?.trim()) {
    return {
      ok: false,
      source: FTC_RELEASE_NOTICES_SOURCE,
      status: "missing_key",
      error: "FTC_API_KEY is required for FTC release-notice API checks; official FTC search leads are still returned.",
    };
  }
  const url = ftcReleaseNoticeApiUrl(business, maxResults);
  try {
    const guarded = await fetchWithSsrFGuard({
      url,
      init: {
        headers: {
          Accept: "application/vnd.api+json,application/json;q=0.9,*/*;q=0.1",
          "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
        },
      },
      timeoutMs: LOOKUP_TIMEOUT_MS,
      signal,
      auditContext: "openclaw-osint-ftc-release-notices",
    });
    const { response, release, finalUrl } = guarded;
    try {
      if (!response.ok) {
        return { ok: false, source: FTC_RELEASE_NOTICES_SOURCE, url: finalUrl, error: `FTC API returned HTTP ${response.status}` };
      }
      const parsed = JSON.parse(await readResponseTextBounded(response, MAX_RESPONSE_BYTES));
      return {
        ok: true,
        source: FTC_RELEASE_NOTICES_SOURCE,
        url: finalUrl,
        count: typeof parsed?.meta?.count === "number" ? parsed.meta.count : undefined,
        results: normalizeFtcReleaseNoticeRows(parsed, maxResults),
      };
    } finally {
      await release();
    }
  } catch (error) {
    return { ok: false, source: FTC_RELEASE_NOTICES_SOURCE, url, error: formatError(error) };
  }
}

async function queryBbbBusinessSearch(params: {
  business: string;
  domain?: string;
  maxResults: number;
  signal?: AbortSignal;
}) {
  const url = bbbSearchUrl(params.business, params.domain);
  try {
    const guarded = await fetchWithSsrFGuard({
      url,
      init: {
        headers: {
          Accept: "text/html,application/xhtml+xml,*/*;q=0.2",
          "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
        },
      },
      timeoutMs: LOOKUP_TIMEOUT_MS,
      signal: params.signal,
      auditContext: "openclaw-osint-bbb-business-search",
    });
    const { response, release, finalUrl } = guarded;
    try {
      if (!response.ok) {
        return { ok: false, source: BBB_SEARCH_SOURCE, url: finalUrl, error: `BBB search returned HTTP ${response.status}` };
      }
      const html = await readResponseTextBounded(response, MAX_RESPONSE_BYTES);
      return {
        ok: true,
        source: BBB_SEARCH_SOURCE,
        url: finalUrl,
        profileLeads: parseBbbProfileLinks(html, params.maxResults),
      };
    } finally {
      await release();
    }
  } catch (error) {
    return { ok: false, source: BBB_SEARCH_SOURCE, url, error: formatError(error) };
  }
}

async function querySecFinancialDisclosures(params: {
  business: string;
  ticker?: string;
  maxResults: number;
  signal?: AbortSignal;
  cache: OsintCache;
  refresh: boolean;
}) {
  try {
    const company = await resolveSecCompany(params);
    if (!company) {
      return {
        ok: false,
        source: SEC_SUBMISSIONS_SOURCE,
        status: "not_found",
        error: "No SEC company ticker match found for this business.",
      };
    }
    const target = company.cik;
    const fresh = params.refresh ? undefined : params.cache.getFreshSource(SEC_SUBMISSIONS_SOURCE, target);
    if (fresh) {
      const parsed = JSON.parse(fresh.rawJson);
      return {
        ok: true,
        source: SEC_SUBMISSIONS_SOURCE,
        cacheStatus: "hit",
        matchedCompany: company,
        fetchedAt: fresh.fetchedAt,
        expiresAt: fresh.expiresAt,
        ...parsed,
      };
    }
    const url = `https://data.sec.gov/submissions/CIK${company.cik}.json`;
    const guarded = await fetchWithSsrFGuard({
      url,
      init: {
        headers: {
          Accept: "application/json",
          "User-Agent": "OpenClaw OSINT contact=openclaw.ai",
        },
      },
      timeoutMs: LOOKUP_TIMEOUT_MS,
      signal: params.signal,
      auditContext: "openclaw-osint-sec-submissions",
    });
    const { response, release, finalUrl } = guarded;
    try {
      if (!response.ok) {
        return { ok: false, source: SEC_SUBMISSIONS_SOURCE, url: finalUrl, matchedCompany: company, error: `SEC submissions returned HTTP ${response.status}` };
      }
      const parsed = JSON.parse(await readResponseTextBounded(response, MAX_RESPONSE_BYTES));
      const normalized = normalizeSecSubmissions(parsed, company, params.maxResults, finalUrl);
      const rawJson = JSON.stringify(normalized);
      const fetchedAt = Date.now();
      params.cache.putSource({
        source: SEC_SUBMISSIONS_SOURCE,
        target,
        fetchedAt,
        expiresAt: fetchedAt + BUSINESS_REPUTATION_TTL_MS,
        rawJson,
        rawBytes: Buffer.byteLength(rawJson),
        status: "ok",
      });
      return {
        ok: true,
        source: SEC_SUBMISSIONS_SOURCE,
        cacheStatus: "refreshed",
        fetchedAt,
        expiresAt: fetchedAt + BUSINESS_REPUTATION_TTL_MS,
        ...normalized,
      };
    } finally {
      await release();
    }
  } catch (error) {
    return { ok: false, source: SEC_SUBMISSIONS_SOURCE, error: formatError(error) };
  }
}

async function queryMarketFinancials(params: {
  business: string;
  ticker?: string;
  maxResults: number;
  signal?: AbortSignal;
  cache: OsintCache;
  refresh: boolean;
}) {
  try {
    const company = await resolveSecCompany(params);
    const ticker = params.ticker ?? company?.ticker;
    if (!ticker) {
      return {
        ok: false,
        source: MARKET_FINANCIALS_SOURCE,
        status: "not_found",
        error: "No public ticker match found for market-data lookup.",
      };
    }
    const target = ticker.toUpperCase();
    const fresh = params.refresh ? undefined : params.cache.getFreshSource(MARKET_FINANCIALS_SOURCE, target);
    if (fresh) {
      return {
        ...JSON.parse(fresh.rawJson),
        cacheStatus: "hit",
        fetchedAt: fresh.fetchedAt,
        expiresAt: fresh.expiresAt,
      };
    }
    const [quoteSnapshot, secCompanyFacts] = await Promise.all([
      queryYahooChartSnapshot(target, params.signal),
      company
        ? querySecCompanyFacts({
          company,
          maxResults: params.maxResults,
          signal: params.signal,
          cache: params.cache,
          refresh: params.refresh,
        })
        : Promise.resolve({
          ok: false,
          source: SEC_COMPANY_FACTS_SOURCE,
          status: "not_found",
          error: "No SEC company match found for official company-facts enrichment.",
        }),
    ]);
    const computed = computeMarketMetrics(quoteSnapshot, secCompanyFacts);
    const fetchedAt = Date.now();
    const result = {
      ok: quoteSnapshot.ok === true || secCompanyFacts.ok === true,
      source: MARKET_FINANCIALS_SOURCE,
      ticker: target,
      ...(company ? { matchedCompany: company } : {}),
      cacheStatus: "refreshed",
      fetchedAt,
      expiresAt: fetchedAt + MARKET_FINANCIALS_TTL_MS,
      quoteSnapshot,
      secCompanyFacts,
      computed,
      caveat:
        "Market data is time-sensitive. Quote data comes from Yahoo Finance chart metadata when available. Fundamentals come from SEC company facts when a public-filer match exists. P/E and market cap are computed only when the required inputs are present and should be treated as approximate context, not investment advice.",
    };
    const rawJson = JSON.stringify(result);
    params.cache.putSource({
      source: MARKET_FINANCIALS_SOURCE,
      target,
      fetchedAt,
      expiresAt: fetchedAt + MARKET_FINANCIALS_TTL_MS,
      rawJson,
      rawBytes: Buffer.byteLength(rawJson),
      status: result.ok ? "ok" : "error",
    });
    return result;
  } catch (error) {
    return { ok: false, source: MARKET_FINANCIALS_SOURCE, error: formatError(error) };
  }
}

async function queryRegionalBusinessDisclosures(params: {
  business: string;
  domain?: string;
  registryId?: string;
  maxResults: number;
  signal?: AbortSignal;
}) {
  const [ukCompaniesHouse, auAbnLookup, asiaBusinessRegisters] = await Promise.all([
    queryUkCompaniesHouse(params),
    queryAuAbnLookup(params),
    queryAsianBusinessDisclosures(params),
  ]);
  return {
    ukCompaniesHouse,
    euBusinessRegisters: buildEuBusinessRegisterLeads(params.business, params.domain),
    auAbnLookup,
    asiaBusinessRegisters,
  };
}

async function queryUkCompaniesHouse(params: {
  business: string;
  domain?: string;
  maxResults: number;
  signal?: AbortSignal;
}) {
  const apiKey = process.env.COMPANIES_HOUSE_API_KEY?.trim() || process.env.UK_COMPANIES_HOUSE_API_KEY?.trim();
  const searchUrl = companiesHouseSearchUrl(params.business, params.maxResults);
  if (!apiKey) {
    return {
      ok: false,
      source: UK_COMPANIES_HOUSE_SOURCE,
      status: "missing_key",
      url: "https://find-and-update.company-information.service.gov.uk/search",
      searchUrl,
      error: "COMPANIES_HOUSE_API_KEY is required for API-backed UK Companies House lookup; official search leads are still returned.",
    };
  }
  try {
    const guarded = await fetchWithSsrFGuard({
      url: searchUrl,
      init: {
        headers: {
          Accept: "application/json",
          Authorization: `Basic ${Buffer.from(`${apiKey}:`).toString("base64")}`,
          "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
        },
      },
      timeoutMs: LOOKUP_TIMEOUT_MS,
      signal: params.signal,
      auditContext: "openclaw-osint-companies-house",
    });
    const { response, release, finalUrl } = guarded;
    try {
      if (!response.ok) {
        return { ok: false, source: UK_COMPANIES_HOUSE_SOURCE, url: finalUrl, error: `Companies House returned HTTP ${response.status}` };
      }
      const parsed = JSON.parse(await readResponseTextBounded(response, MAX_RESPONSE_BYTES));
      return {
        ok: true,
        source: UK_COMPANIES_HOUSE_SOURCE,
        url: finalUrl,
        results: normalizeCompaniesHouseSearchRows(parsed, params.maxResults),
      };
    } finally {
      await release();
    }
  } catch (error) {
    return { ok: false, source: UK_COMPANIES_HOUSE_SOURCE, url: searchUrl, error: formatError(error) };
  }
}

async function queryAuAbnLookup(params: {
  business: string;
  domain?: string;
  maxResults: number;
  signal?: AbortSignal;
}) {
  const guid = process.env.ABN_LOOKUP_GUID?.trim() || process.env.AU_ABN_LOOKUP_GUID?.trim();
  const searchUrl = abnLookupSearchUrl(params.business);
  const apiUrl = abnLookupApiUrl(params.business, params.maxResults, guid);
  if (!guid) {
    return {
      ok: false,
      source: AU_ABN_LOOKUP_SOURCE,
      status: "missing_key",
      url: searchUrl,
      error: "ABN_LOOKUP_GUID is required for API-backed Australian ABN Lookup; official website search is still returned.",
    };
  }
  try {
    const guarded = await fetchWithSsrFGuard({
      url: apiUrl,
      init: {
        headers: {
          Accept: "application/json,text/javascript,*/*;q=0.1",
          "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
        },
      },
      timeoutMs: LOOKUP_TIMEOUT_MS,
      signal: params.signal,
      auditContext: "openclaw-osint-abn-lookup",
    });
    const { response, release, finalUrl } = guarded;
    try {
      if (!response.ok) {
        return { ok: false, source: AU_ABN_LOOKUP_SOURCE, url: finalUrl, error: `ABN Lookup returned HTTP ${response.status}` };
      }
      const parsed = parseJsonOrJsonp(await readResponseTextBounded(response, MAX_RESPONSE_BYTES));
      return {
        ok: true,
        source: AU_ABN_LOOKUP_SOURCE,
        url: finalUrl,
        results: normalizeAbnLookupRows(parsed, params.maxResults),
      };
    } finally {
      await release();
    }
  } catch (error) {
    return { ok: false, source: AU_ABN_LOOKUP_SOURCE, url: searchUrl, error: formatError(error) };
  }
}

function buildSearchLeads(business: string, domain?: string) {
  const query = domain ? `${business} ${domain}` : business;
  return [
    {
      source: "ftc-site-search",
      category: "official_search_lead",
      url: `https://www.ftc.gov/search?search=${encodeURIComponent(query)}`,
      purpose: "Search FTC.gov content, actions, guidance, and releases for the business name.",
    },
    {
      source: "ftc-legal-library-search",
      category: "official_search_lead",
      url: `https://www.ftc.gov/legal-library/browse?search=${encodeURIComponent(query)}`,
      purpose: "Search FTC legal-library materials for enforcement or legal documents.",
    },
    {
      source: "bbb-business-directory",
      category: "directory_search_lead",
      url: bbbSearchUrl(business, domain),
      purpose: "Search BBB business profiles, ratings, reviews, and complaints where BBB has coverage.",
    },
    {
      source: "uk-companies-house-search",
      category: "official_register_search_lead",
      url: `https://find-and-update.company-information.service.gov.uk/search?q=${encodeURIComponent(business)}`,
      purpose: "Search the official UK Companies House register for UK companies.",
    },
    {
      source: "eu-bris-business-register-search",
      category: "official_register_search_lead",
      url: euBrisSearchUrl(business),
      purpose: "Search the EU/EEA BRIS business-register gateway; results are routed to national registers.",
    },
    {
      source: "au-abn-lookup-search",
      category: "official_register_search_lead",
      url: abnLookupSearchUrl(business),
      purpose: "Search Australian Business Register ABN Lookup by ABN, ACN, or name.",
    },
    {
      source: "jp-corporate-number-search",
      category: "official_register_search_lead",
      url: japanCorporateNumberSearchUrl(business),
      purpose: "Search Japan National Tax Agency Corporate Number Publication Site by name or corporate number.",
    },
    {
      source: "jp-gbizinfo-search",
      category: "official_register_search_lead",
      url: japanGbizInfoSearchUrl(business),
      purpose: "Search Japan gBizINFO corporate activity disclosures; API-backed use requires a gBizINFO token.",
    },
    {
      source: "cn-gsxt-search",
      category: "official_register_search_lead",
      url: chinaGsxtSearchUrl(business),
      purpose: "Search China's official National Enterprise Credit Information Publicity System; public access is interactive and may require CAPTCHA.",
    },
    {
      source: "tw-findbiz-search",
      category: "official_register_search_lead",
      url: taiwanFindbizUrl(business),
      purpose: "Search Taiwan Ministry of Economic Affairs company and business registration by name or Unified Business Number.",
    },
  ];
}

function buildProfessionalProfileLeads(business: string, domain?: string) {
  const query = domain ? `${business} ${domain}` : business;
  return [
    {
      source: "linkedin-company-public-search",
      category: "professional_profile_search_lead",
      url: `https://www.linkedin.com/search/results/companies/?keywords=${encodeURIComponent(query)}`,
      purpose: "Find public LinkedIn company pages and professional presence. This is a lead only; no credentialed scraping is performed.",
    },
    {
      source: "linkedin-company-url-pattern",
      category: "professional_profile_pattern_lead",
      url: `https://www.linkedin.com/company/${slugifyBusinessName(business)}/`,
      purpose: "Likely LinkedIn public company URL pattern to manually verify.",
    },
  ];
}

function buildWorkplaceReviewLeads(business: string, domain?: string) {
  const query = domain ? `${business} ${domain}` : business;
  return [
    {
      source: "glassdoor-company-search",
      category: "workplace_review_search_lead",
      url: `https://www.glassdoor.com/Reviews/company-reviews.htm?suggestCount=0&suggestChosen=false&clickSource=searchBtn&typedKeyword=${encodeURIComponent(query)}&sc.keyword=${encodeURIComponent(query)}`,
      purpose: "Find public Glassdoor company review and workplace-profile pages. This is a lead only; no credentialed scraping is performed.",
    },
  ];
}

function sourceStatusFromResult(source: string, result: unknown): SourceStatus {
  if (result && typeof result === "object" && "ok" in result && result.ok === true) {
    return { source, status: "checked" };
  }
  if (result && typeof result === "object" && "status" in result && result.status === "missing_key") {
    return {
      source,
      status: "missing_key",
      detail: "API key is not configured; official search leads are returned instead.",
    };
  }
  if (result && typeof result === "object" && "status" in result && result.status === "lead_only") {
    return {
      source,
      status: "lead_only",
      detail: "No stable unauthenticated JSON API is configured; official search leads are returned.",
    };
  }
  if (result && typeof result === "object" && "status" in result && result.status === "not_found") {
    return { source, status: "error", detail: "No matching public-company disclosure record found." };
  }
  const error = result && typeof result === "object" && "error" in result && typeof result.error === "string"
    ? result.error
    : undefined;
  return { source, status: "error", ...(error ? { detail: error } : {}) };
}

function observationsFromBusinessLookup(target: string, result: Awaited<ReturnType<typeof queryBusinessReputationForTool>>, observedAt: number): OsintObservation[] {
  if (!result || typeof result !== "object" || result.ok !== true) {
    return [];
  }
  const observations: OsintObservation[] = [];
  for (const notice of result.ftcReleaseNotices.ok === true ? result.ftcReleaseNotices.results : []) {
    observations.push({
      id: stableObservationId(BUSINESS_REPUTATION_SOURCE, target, "ftc_release_notice", notice.title),
      source: BUSINESS_REPUTATION_SOURCE,
      target,
      type: "ftc_release_notice",
      value: notice.title,
      confidence: 0.78,
      admissionScore: 0.72,
      storageTier: "thin",
      observedAt,
      sourceRef: notice.url,
      metadata: { date: notice.date },
    });
  }
  for (const profile of result.bbbSearch.ok === true ? result.bbbSearch.profileLeads : []) {
    observations.push({
      id: stableObservationId(BUSINESS_REPUTATION_SOURCE, target, "bbb_profile_lead", profile.url),
      source: BUSINESS_REPUTATION_SOURCE,
      target,
      type: "bbb_profile_lead",
      value: profile.url,
      confidence: 0.65,
      admissionScore: 0.6,
      storageTier: "thin",
      observedAt,
      sourceRef: profile.url,
    });
  }
  for (const filing of result.financialDisclosures.ok === true ? result.financialDisclosures.recentFilings : []) {
    observations.push({
      id: stableObservationId(BUSINESS_REPUTATION_SOURCE, target, "sec_filing", filing.accessionNumber),
      source: BUSINESS_REPUTATION_SOURCE,
      target,
      type: "sec_filing",
      value: `${filing.form} ${filing.filingDate}`,
      confidence: 0.9,
      admissionScore: 0.82,
      storageTier: "thin",
      observedAt,
      sourceRef: filing.url,
      metadata: { form: filing.form, filingDate: filing.filingDate },
    });
  }
  for (const company of result.regionalDisclosures.ukCompaniesHouse.ok === true ? result.regionalDisclosures.ukCompaniesHouse.results : []) {
    observations.push({
      id: stableObservationId(BUSINESS_REPUTATION_SOURCE, target, "uk_company", company.companyNumber),
      source: BUSINESS_REPUTATION_SOURCE,
      target,
      type: "uk_company",
      value: company.title,
      confidence: 0.82,
      admissionScore: 0.76,
      storageTier: "thin",
      observedAt,
      sourceRef: company.url,
      metadata: { companyNumber: company.companyNumber, companyStatus: company.companyStatus },
    });
  }
  for (const business of result.regionalDisclosures.auAbnLookup.ok === true ? result.regionalDisclosures.auAbnLookup.results : []) {
    observations.push({
      id: stableObservationId(BUSINESS_REPUTATION_SOURCE, target, "au_abn", business.abn),
      source: BUSINESS_REPUTATION_SOURCE,
      target,
      type: "au_abn",
      value: business.name,
      confidence: 0.78,
      admissionScore: 0.72,
      storageTier: "thin",
      observedAt,
      sourceRef: business.url,
      metadata: { abn: business.abn, stateCode: business.stateCode, postcode: business.postcode },
    });
  }
  for (const company of result.regionalDisclosures.asiaBusinessRegisters.taiwan.ok === true ? result.regionalDisclosures.asiaBusinessRegisters.taiwan.results : []) {
    observations.push({
      id: stableObservationId(BUSINESS_REPUTATION_SOURCE, target, "tw_company", company.unifiedBusinessNumber),
      source: BUSINESS_REPUTATION_SOURCE,
      target,
      type: "tw_company",
      value: company.companyName,
      confidence: 0.82,
      admissionScore: 0.76,
      storageTier: "thin",
      observedAt,
      sourceRef: company.url,
      metadata: {
        unifiedBusinessNumber: company.unifiedBusinessNumber,
        status: company.status,
        registerOrganization: company.registerOrganization,
      },
    });
  }
  return observations;
}

function ftcReleaseNoticeApiUrl(business: string, maxResults: number): string {
  const url = new URL("https://api.ftc.gov/v0/node/rn");
  url.searchParams.set("api_key", process.env.FTC_API_KEY?.trim() ?? "");
  url.searchParams.set("page[limit]", String(maxResults));
  url.searchParams.set("filter[title][condition][path]", "title");
  url.searchParams.set("filter[title][condition][operator]", "CONTAINS");
  url.searchParams.set("filter[title][condition][value]", business);
  return url.toString();
}

function bbbSearchUrl(business: string, domain?: string): string {
  const url = new URL("https://www.bbb.org/search");
  url.searchParams.set("find_text", business);
  url.searchParams.set("find_country", "USA");
  return url.toString();
}

function buildEuBusinessRegisterLeads(business: string, domain?: string) {
  return {
    ok: false,
    source: EU_BRIS_SOURCE,
    status: "lead_only",
    leads: [
      {
        source: "eu-justice-bris",
        category: "official_register_search_lead",
        url: euBrisSearchUrl(business),
        purpose: "Search EU/EEA company register records through the e-Justice BRIS gateway.",
      },
      {
        source: "eu-national-registers",
        category: "official_register_search_lead",
        url: "https://e-justice.europa.eu/106/EN/business_registers_in_eu_countries",
        purpose: "Choose the relevant EU national business register when BRIS does not expose enough detail.",
      },
    ],
    ...(domain ? { domainContext: domain } : {}),
    caveat: "BRIS is an interconnection/search gateway, not a simple public JSON disclosure API.",
  };
}

async function queryAsianBusinessDisclosures(params: {
  business: string;
  domain?: string;
  registryId?: string;
  maxResults: number;
  signal?: AbortSignal;
}) {
  const taiwan = await queryTaiwanGcis(params);
  return {
    japan: buildJapanBusinessRegisterLeads(params.business, params.domain),
    china: buildChinaBusinessRegisterLeads(params.business, params.domain),
    taiwan,
  };
}

function buildJapanBusinessRegisterLeads(business: string, domain?: string) {
  return {
    ok: false,
    source: JP_GBIZINFO_SOURCE,
    status: "lead_only",
    leads: [
      {
        source: "jp-national-tax-agency-corporate-number",
        category: "official_register_search_lead",
        url: japanCorporateNumberSearchUrl(business),
        purpose: "Search Japan National Tax Agency Corporate Number Publication Site by corporate number, name, or address.",
      },
      {
        source: "jp-gbizinfo",
        category: "official_disclosure_search_lead",
        url: japanGbizInfoSearchUrl(business),
        purpose: "Search Japan gBizINFO corporate activity disclosures and certifications.",
      },
      {
        source: "jp-gbizinfo-api-docs",
        category: "official_api_lead",
        url: "https://content.info.gbiz.go.jp/api/index.html",
        purpose: "gBizINFO REST API documentation; API-backed use requires a token issued after application.",
      },
    ],
    ...(domain ? { domainContext: domain } : {}),
    caveat: "Japan official register leads are returned without scraping. gBizINFO API-backed lookup requires a token and is not attempted without one.",
  };
}

function buildChinaBusinessRegisterLeads(business: string, domain?: string) {
  return {
    ok: false,
    source: CN_GSXT_SOURCE,
    status: "lead_only",
    leads: [
      {
        source: "cn-gsxt",
        category: "official_register_search_lead",
        url: chinaGsxtSearchUrl(business),
        purpose: "Search China's National Enterprise Credit Information Publicity System by name or Unified Social Credit Code.",
      },
    ],
    ...(domain ? { domainContext: domain } : {}),
    caveat: "China GSXT is an official interactive portal and commonly uses CAPTCHA or browser checks; no stable unauthenticated JSON API is assumed.",
  };
}

async function queryTaiwanGcis(params: {
  business: string;
  registryId?: string;
  maxResults: number;
  signal?: AbortSignal;
}) {
  if (!params.registryId || !/^\d{8}$/.test(params.registryId)) {
    return {
      ok: false,
      source: TW_GCIS_SOURCE,
      status: "lead_only",
      url: taiwanFindbizUrl(params.registryId ?? params.business),
      apiUrl: "https://data.gcis.nat.gov.tw/od/data/api",
      error: "Taiwan GCIS API lookup requires an 8-digit Unified Business Number in registryId; official search leads are still returned.",
    };
  }
  const url = taiwanGcisApiUrl(params.registryId, params.maxResults);
  try {
    const guarded = await fetchWithSsrFGuard({
      url,
      init: {
        headers: {
          Accept: "application/json,*/*;q=0.1",
          "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
        },
      },
      timeoutMs: LOOKUP_TIMEOUT_MS,
      signal: params.signal,
      auditContext: "openclaw-osint-tw-gcis",
    });
    const { response, release, finalUrl } = guarded;
    try {
      if (!response.ok) {
        return { ok: false, source: TW_GCIS_SOURCE, url: finalUrl, error: `Taiwan GCIS returned HTTP ${response.status}` };
      }
      const parsed = JSON.parse(await readResponseTextBounded(response, MAX_RESPONSE_BYTES));
      return {
        ok: true,
        source: TW_GCIS_SOURCE,
        url: finalUrl,
        registryId: params.registryId,
        results: normalizeTaiwanGcisRows(parsed, params.maxResults),
      };
    } finally {
      await release();
    }
  } catch (error) {
    return { ok: false, source: TW_GCIS_SOURCE, url, error: formatError(error) };
  }
}

function companiesHouseSearchUrl(business: string, maxResults: number): string {
  const url = new URL("https://api.company-information.service.gov.uk/search/companies");
  url.searchParams.set("q", business);
  url.searchParams.set("items_per_page", String(maxResults));
  return url.toString();
}

function abnLookupSearchUrl(business: string): string {
  return `https://abr.business.gov.au/Search/ResultsActive?SearchText=${encodeURIComponent(business)}`;
}

function abnLookupApiUrl(business: string, maxResults: number, guid?: string): string {
  const url = new URL("https://abr.business.gov.au/json/MatchingNames.aspx");
  url.searchParams.set("name", business);
  url.searchParams.set("maxResults", String(maxResults));
  url.searchParams.set("guid", guid ?? "");
  return url.toString();
}

async function queryYahooChartSnapshot(ticker: string, signal?: AbortSignal) {
  const url = yahooChartUrl(ticker);
  try {
    const guarded = await fetchWithSsrFGuard({
      url,
      init: {
        headers: {
          Accept: "application/json,*/*;q=0.1",
          "User-Agent": "Mozilla/5.0 (compatible; OpenClaw OSINT; +https://openclaw.ai)",
        },
      },
      timeoutMs: LOOKUP_TIMEOUT_MS,
      signal,
      auditContext: "openclaw-osint-yahoo-chart",
    });
    const { response, release, finalUrl } = guarded;
    try {
      if (!response.ok) {
        return { ok: false, source: YAHOO_CHART_SOURCE, url: finalUrl, error: `Yahoo chart returned HTTP ${response.status}` };
      }
      const parsed = JSON.parse(await readResponseTextBounded(response, MAX_RESPONSE_BYTES));
      return normalizeYahooChartSnapshot(parsed, finalUrl);
    } finally {
      await release();
    }
  } catch (error) {
    return { ok: false, source: YAHOO_CHART_SOURCE, url, error: formatError(error) };
  }
}

async function querySecCompanyFacts(params: {
  company: { cik: string; ticker: string; title: string };
  maxResults: number;
  signal?: AbortSignal;
  cache: OsintCache;
  refresh: boolean;
}) {
  const target = params.company.cik;
  const fresh = params.refresh ? undefined : params.cache.getFreshSource(SEC_COMPANY_FACTS_SOURCE, target);
  if (fresh) {
    return {
      ...JSON.parse(fresh.rawJson),
      cacheStatus: "hit",
      fetchedAt: fresh.fetchedAt,
      expiresAt: fresh.expiresAt,
    };
  }
  const url = `https://data.sec.gov/api/xbrl/companyfacts/CIK${params.company.cik}.json`;
  try {
    const guarded = await fetchWithSsrFGuard({
      url,
      init: {
        headers: {
          Accept: "application/json",
          "User-Agent": "OpenClaw OSINT contact=openclaw.ai",
        },
      },
      timeoutMs: LOOKUP_TIMEOUT_MS,
      signal: params.signal,
      auditContext: "openclaw-osint-sec-company-facts",
    });
    const { response, release, finalUrl } = guarded;
    try {
      if (!response.ok) {
        return { ok: false, source: SEC_COMPANY_FACTS_SOURCE, url: finalUrl, error: `SEC company facts returned HTTP ${response.status}` };
      }
      const parsed = JSON.parse(await readResponseTextBounded(response, SEC_COMPANY_FACTS_MAX_RESPONSE_BYTES));
      const normalized = normalizeSecCompanyFacts(parsed, params.company, params.maxResults, finalUrl);
      const rawJson = JSON.stringify(normalized);
      const fetchedAt = Date.now();
      params.cache.putSource({
        source: SEC_COMPANY_FACTS_SOURCE,
        target,
        fetchedAt,
        expiresAt: fetchedAt + BUSINESS_REPUTATION_TTL_MS,
        rawJson,
        rawBytes: Buffer.byteLength(rawJson),
        status: "ok",
      });
      return {
        ...normalized,
        cacheStatus: "refreshed",
        fetchedAt,
        expiresAt: fetchedAt + BUSINESS_REPUTATION_TTL_MS,
      };
    } finally {
      await release();
    }
  } catch (error) {
    return { ok: false, source: SEC_COMPANY_FACTS_SOURCE, url, error: formatError(error) };
  }
}

function yahooChartUrl(ticker: string): string {
  const url = new URL(`https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(ticker)}`);
  url.searchParams.set("range", "1d");
  url.searchParams.set("interval", "1d");
  return url.toString();
}

function euBrisSearchUrl(business: string): string {
  return `https://e-justice.europa.eu/489/EN/business_registers__search_for_a_company_in_the_eu?searchText=${encodeURIComponent(business)}`;
}

function japanCorporateNumberSearchUrl(business: string): string {
  const url = new URL("https://www.houjin-bangou.nta.go.jp/en/henkorireki-johoto.html");
  url.searchParams.set("selHouzinNo", business);
  return url.toString();
}

function japanGbizInfoSearchUrl(business: string): string {
  const url = new URL("https://info.gbiz.go.jp/hojin/ichiran");
  url.searchParams.set("hojinName", business);
  return url.toString();
}

function chinaGsxtSearchUrl(business: string): string {
  const url = new URL("https://www.gsxt.gov.cn/corp-query-homepage.html");
  url.searchParams.set("keyword", business);
  return url.toString();
}

function taiwanFindbizUrl(value: string): string {
  const url = new URL("https://findbiz.nat.gov.tw/fts/query/QueryBar/queryInit.do");
  url.searchParams.set("fhl", "en");
  url.searchParams.set("request_locale", "en");
  url.searchParams.set("qryCond", value);
  return url.toString();
}

function taiwanGcisApiUrl(registryId: string, maxResults: number): string {
  const url = new URL(`https://data.gcis.nat.gov.tw/od/data/api/${TAIWAN_COMPANY_REGISTRATION_DATASET_ID}`);
  url.searchParams.set("$format", "json");
  url.searchParams.set("$filter", `Business_Accounting_NO eq ${registryId}`);
  url.searchParams.set("$skip", "0");
  url.searchParams.set("$top", String(maxResults));
  return url.toString();
}

function normalizeCompaniesHouseSearchRows(parsed: unknown, limit: number) {
  const items = parsed && typeof parsed === "object" && "items" in parsed && Array.isArray(parsed.items)
    ? parsed.items
    : [];
  return items.slice(0, limit).flatMap((item) => {
    if (!item || typeof item !== "object") {
      return [];
    }
    const value = item as Record<string, unknown>;
    const title = typeof value.title === "string" ? value.title : "";
    const companyNumber = typeof value.company_number === "string" ? value.company_number : "";
    if (!title || !companyNumber) {
      return [];
    }
    return [{
      title,
      companyNumber,
      companyStatus: typeof value.company_status === "string" ? value.company_status : undefined,
      companyType: typeof value.company_type === "string" ? value.company_type : undefined,
      dateOfCreation: typeof value.date_of_creation === "string" ? value.date_of_creation : undefined,
      url: `https://find-and-update.company-information.service.gov.uk/company/${encodeURIComponent(companyNumber)}`,
    }];
  });
}

function normalizeAbnLookupRows(parsed: unknown, limit: number) {
  const names = parsed && typeof parsed === "object" && "Names" in parsed && Array.isArray(parsed.Names)
    ? parsed.Names
    : parsed && typeof parsed === "object" && "names" in parsed && Array.isArray(parsed.names)
      ? parsed.names
      : [];
  return names.slice(0, limit).flatMap((item) => {
    if (!item || typeof item !== "object") {
      return [];
    }
    const value = item as Record<string, unknown>;
    const abn = stringValue(value.Abn ?? value.abn ?? value.ABN);
    const name = stringValue(value.Name ?? value.name ?? value.mainName ?? value.MainName);
    if (!abn || !name) {
      return [];
    }
    return [{
      abn,
      name,
      stateCode: stringValue(value.State ?? value.stateCode ?? value.StateCode),
      postcode: stringValue(value.Postcode ?? value.postcode),
      url: `https://abr.business.gov.au/ABN/View/${encodeURIComponent(abn.replace(/\s+/g, ""))}`,
    }];
  });
}

function normalizeTaiwanGcisRows(parsed: unknown, limit: number) {
  const rows = Array.isArray(parsed) ? parsed : [];
  return rows.slice(0, limit).flatMap((item) => {
    if (!item || typeof item !== "object") {
      return [];
    }
    const value = item as Record<string, unknown>;
    const unifiedBusinessNumber = stringValue(value.Business_Accounting_NO);
    const companyName = stringValue(value.Company_Name);
    if (!unifiedBusinessNumber || !companyName) {
      return [];
    }
    return [{
      unifiedBusinessNumber,
      companyName,
      status: stringValue(value.Company_Status_Desc),
      capitalStockAmount: numberValue(value.Capital_Stock_Amount),
      paidInCapitalAmount: numberValue(value.Paid_In_Capital_Amount),
      location: stringValue(value.Company_Location),
      registerOrganization: stringValue(value.Register_Organization_Desc),
      setupDate: stringValue(value.Company_Setup_Date),
      changedAt: stringValue(value.Change_Of_Approval_Data),
      url: taiwanFindbizUrl(unifiedBusinessNumber),
    }];
  });
}

function parseJsonOrJsonp(text: string): unknown {
  const trimmed = text.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    return JSON.parse(trimmed);
  }
  const match = trimmed.match(/^[^(]*\((.*)\)\s*;?$/s);
  if (!match?.[1]) {
    throw new Error("Expected JSON or JSONP response");
  }
  return JSON.parse(match[1]);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function factValue(value: unknown): number | undefined {
  return value && typeof value === "object" && "value" in value ? numberValue(value.value) : undefined;
}

function secondsToIso(value: number | undefined): string | undefined {
  return value === undefined ? undefined : new Date(value * 1000).toISOString();
}

function roundMetric(value: number): number {
  return Math.round(value * 100) / 100;
}

async function resolveSecCompany(params: {
  business: string;
  ticker?: string;
  signal?: AbortSignal;
  cache: OsintCache;
  refresh: boolean;
}) {
  const companies = await loadSecCompanyTickers(params);
  const ticker = params.ticker?.toUpperCase();
  if (ticker) {
    const byTicker = companies.find((company) => company.ticker.toUpperCase() === ticker);
    if (byTicker) {
      return byTicker;
    }
  }
  const target = canonicalBusinessName(params.business);
  return companies.find((company) => canonicalBusinessName(company.title) === target) ??
    companies.find((company) => canonicalBusinessName(company.title).includes(target));
}

async function loadSecCompanyTickers(params: {
  signal?: AbortSignal;
  cache: OsintCache;
  refresh: boolean;
}) {
  const fresh = params.refresh ? undefined : params.cache.getFreshSource(SEC_COMPANY_TICKERS_SOURCE, "company_tickers");
  if (fresh) {
    return normalizeSecCompanyTickerRows(JSON.parse(fresh.rawJson));
  }
  const url = "https://www.sec.gov/files/company_tickers.json";
  const guarded = await fetchWithSsrFGuard({
    url,
    init: {
      headers: {
        Accept: "application/json",
        "User-Agent": "OpenClaw OSINT contact=openclaw.ai",
      },
    },
    timeoutMs: LOOKUP_TIMEOUT_MS,
    signal: params.signal,
    auditContext: "openclaw-osint-sec-company-tickers",
  });
  const { response, release } = guarded;
  try {
    if (!response.ok) {
      throw new Error(`SEC company tickers returned HTTP ${response.status}`);
    }
    const rawJson = await readResponseTextBounded(response, MAX_RESPONSE_BYTES);
    const fetchedAt = Date.now();
    params.cache.putSource({
      source: SEC_COMPANY_TICKERS_SOURCE,
      target: "company_tickers",
      fetchedAt,
      expiresAt: fetchedAt + SEC_COMPANY_TICKERS_TTL_MS,
      rawJson,
      rawBytes: Buffer.byteLength(rawJson),
      status: "ok",
    });
    return normalizeSecCompanyTickerRows(JSON.parse(rawJson));
  } finally {
    await release();
  }
}

function normalizeSecCompanyTickerRows(parsed: unknown) {
  const rows = parsed && typeof parsed === "object" ? Object.values(parsed) : [];
  return rows.flatMap((row) => {
    if (!row || typeof row !== "object") {
      return [];
    }
    const value = row as Record<string, unknown>;
    const cik = typeof value.cik_str === "number" ? String(value.cik_str).padStart(10, "0") : undefined;
    const ticker = typeof value.ticker === "string" ? value.ticker : undefined;
    const title = typeof value.title === "string" ? value.title : undefined;
    return cik && ticker && title ? [{ cik, ticker, title }] : [];
  });
}

function normalizeSecSubmissions(parsed: unknown, company: { cik: string; ticker: string; title: string }, maxResults: number, url: string) {
  const recent = parsed && typeof parsed === "object" && "filings" in parsed &&
      parsed.filings && typeof parsed.filings === "object" && "recent" in parsed.filings &&
      parsed.filings.recent && typeof parsed.filings.recent === "object"
    ? parsed.filings.recent as Record<string, unknown>
    : {};
  const forms = Array.isArray(recent.form) ? recent.form : [];
  const filingDates = Array.isArray(recent.filingDate) ? recent.filingDate : [];
  const accessionNumbers = Array.isArray(recent.accessionNumber) ? recent.accessionNumber : [];
  const primaryDocuments = Array.isArray(recent.primaryDocument) ? recent.primaryDocument : [];
  const recentFilings = forms.slice(0, maxResults).flatMap((form, index) => {
    const accessionNumber = typeof accessionNumbers[index] === "string" ? accessionNumbers[index] : "";
    const primaryDocument = typeof primaryDocuments[index] === "string" ? primaryDocuments[index] : "";
    const filingDate = typeof filingDates[index] === "string" ? filingDates[index] : "";
    if (typeof form !== "string" || !accessionNumber || !filingDate) {
      return [];
    }
    const accessionCompact = accessionNumber.replace(/-/g, "");
    return [{
      form,
      filingDate,
      accessionNumber,
      ...(primaryDocument ? { primaryDocument } : {}),
      url: primaryDocument
        ? `https://www.sec.gov/Archives/edgar/data/${Number(company.cik)}/${accessionCompact}/${primaryDocument}`
        : `https://www.sec.gov/Archives/edgar/data/${Number(company.cik)}/${accessionCompact}/`,
    }];
  });
  return {
    matchedCompany: company,
    submissionsUrl: url,
    recentFilings,
    companyFactsUrl: `https://data.sec.gov/api/xbrl/companyfacts/CIK${company.cik}.json`,
    secCompanyPage: `https://www.sec.gov/edgar/browse/?CIK=${company.ticker}`,
  };
}

function normalizeYahooChartSnapshot(parsed: unknown, url: string) {
  const result = parsed && typeof parsed === "object" && "chart" in parsed &&
      parsed.chart && typeof parsed.chart === "object" && "result" in parsed.chart &&
      Array.isArray(parsed.chart.result)
    ? parsed.chart.result[0]
    : undefined;
  const meta = result && typeof result === "object" && "meta" in result && result.meta && typeof result.meta === "object"
    ? result.meta as Record<string, unknown>
    : {};
  const symbol = stringValue(meta.symbol);
  if (!symbol) {
    return { ok: false, source: YAHOO_CHART_SOURCE, url, error: "Yahoo chart response did not include symbol metadata." };
  }
  const price = numberValue(meta.regularMarketPrice);
  const previousClose = numberValue(meta.chartPreviousClose);
  return {
    ok: true,
    source: YAHOO_CHART_SOURCE,
    url,
    symbol,
    name: stringValue(meta.longName) ?? stringValue(meta.shortName),
    exchange: stringValue(meta.fullExchangeName) ?? stringValue(meta.exchangeName),
    currency: stringValue(meta.currency),
    regularMarketPrice: price,
    previousClose,
    regularMarketChange: price !== undefined && previousClose !== undefined ? roundMetric(price - previousClose) : undefined,
    regularMarketChangePercent: price !== undefined && previousClose ? roundMetric(((price - previousClose) / previousClose) * 100) : undefined,
    regularMarketTime: secondsToIso(numberValue(meta.regularMarketTime)),
    dayHigh: numberValue(meta.regularMarketDayHigh),
    dayLow: numberValue(meta.regularMarketDayLow),
    fiftyTwoWeekHigh: numberValue(meta.fiftyTwoWeekHigh),
    fiftyTwoWeekLow: numberValue(meta.fiftyTwoWeekLow),
    regularMarketVolume: numberValue(meta.regularMarketVolume),
  };
}

function normalizeSecCompanyFacts(parsed: unknown, company: { cik: string; ticker: string; title: string }, maxResults: number, url: string) {
  const facts = parsed && typeof parsed === "object" && "facts" in parsed && parsed.facts && typeof parsed.facts === "object"
    ? parsed.facts as Record<string, unknown>
    : {};
  const usGaap = facts["us-gaap"] && typeof facts["us-gaap"] === "object" ? facts["us-gaap"] as Record<string, unknown> : {};
  const dei = facts.dei && typeof facts.dei === "object" ? facts.dei as Record<string, unknown> : {};
  const concepts = { ...usGaap, ...dei };
  const revenue = latestCompanyFact(concepts, ["Revenues", "RevenueFromContractWithCustomerExcludingAssessedTax"], ["USD"]);
  const netIncome = latestCompanyFact(concepts, ["NetIncomeLoss"], ["USD"]);
  const epsDiluted = latestCompanyFact(concepts, ["EarningsPerShareDiluted"], ["USD/shares"]);
  const sharesOutstanding = latestCompanyFact(concepts, ["EntityCommonStockSharesOutstanding"], ["shares"]);
  return {
    ok: true,
    source: SEC_COMPANY_FACTS_SOURCE,
    url,
    matchedCompany: company,
    latestFacts: {
      ...(revenue ? { revenue } : {}),
      ...(netIncome ? { netIncome } : {}),
      ...(epsDiluted ? { epsDiluted } : {}),
      ...(sharesOutstanding ? { sharesOutstanding } : {}),
    },
    recentFacts: [revenue, netIncome, epsDiluted, sharesOutstanding].filter(Boolean).slice(0, maxResults),
  };
}

function latestCompanyFact(concepts: Record<string, unknown>, tags: readonly string[], units: readonly string[]) {
  const candidates = [];
  for (const tag of tags) {
    const concept = concepts[tag];
    if (!concept || typeof concept !== "object" || !("units" in concept) || !concept.units || typeof concept.units !== "object") {
      continue;
    }
    for (const unit of units) {
      const rows = (concept.units as Record<string, unknown>)[unit];
      if (!Array.isArray(rows)) {
        continue;
      }
      candidates.push(...rows.flatMap((row) => {
        if (!row || typeof row !== "object") {
          return [];
        }
        const value = row as Record<string, unknown>;
        const val = numberValue(value.val);
        const end = stringValue(value.end);
        const filed = stringValue(value.filed);
        if (val === undefined || !end) {
          return [];
        }
        return [{
          tag,
          unit,
          value: val,
          end,
          filed,
          form: stringValue(value.form),
          fiscalYear: numberValue(value.fy),
          fiscalPeriod: stringValue(value.fp),
        }];
      }));
    }
  }
  return candidates.sort((a, b) => (b.filed ?? b.end).localeCompare(a.filed ?? a.end))[0];
}

function computeMarketMetrics(quoteSnapshot: unknown, secCompanyFacts: unknown) {
  const quote = quoteSnapshot && typeof quoteSnapshot === "object" ? quoteSnapshot as Record<string, unknown> : {};
  const facts = secCompanyFacts && typeof secCompanyFacts === "object" && "latestFacts" in secCompanyFacts &&
      secCompanyFacts.latestFacts && typeof secCompanyFacts.latestFacts === "object"
    ? secCompanyFacts.latestFacts as Record<string, unknown>
    : {};
  const price = numberValue(quote.regularMarketPrice);
  const eps = factValue(facts.epsDiluted);
  const shares = factValue(facts.sharesOutstanding);
  return {
    ...(price !== undefined && eps && eps > 0 ? { peRatioApprox: roundMetric(price / eps) } : {}),
    ...(price !== undefined && shares && shares > 0 ? { marketCapApprox: Math.round(price * shares) } : {}),
    basis: "P/E uses Yahoo chart regularMarketPrice divided by latest SEC diluted EPS fact. Market cap uses Yahoo chart regularMarketPrice multiplied by latest SEC shares outstanding fact.",
  };
}

function normalizeFtcReleaseNoticeRows(parsed: unknown, limit: number) {
  const rows = parsed && typeof parsed === "object" && "data" in parsed && Array.isArray(parsed.data)
    ? parsed.data
    : [];
  return rows.slice(0, limit).flatMap((row) => {
    const attrs = row && typeof row === "object" && "attributes" in row && row.attributes && typeof row.attributes === "object"
      ? row.attributes as Record<string, unknown>
      : undefined;
    const title = typeof attrs?.title === "string" ? attrs.title.trim() : "";
    if (!title) {
      return [];
    }
    const date = typeof attrs?.created === "string" ? attrs.created : typeof attrs?.changed === "string" ? attrs.changed : undefined;
    const pathAlias = typeof attrs?.path === "object" && attrs.path && "alias" in attrs.path && typeof attrs.path.alias === "string"
      ? attrs.path.alias
      : undefined;
    return [{
      title,
      ...(date ? { date } : {}),
      url: pathAlias ? `https://www.ftc.gov${pathAlias}` : "https://www.ftc.gov/",
    }];
  });
}

function parseBbbProfileLinks(html: string, limit: number) {
  return unique(
    Array.from(html.matchAll(/\bhref=["']([^"']*\/profile\/[^"']+)["']/gi))
      .map((match) => match[1] ?? "")
      .map((href) => new URL(href, "https://www.bbb.org").toString()),
  ).slice(0, limit).map((url) => ({ url }));
}

function normalizeBusinessName(input: string): string | undefined {
  const cleaned = input.replace(/\s+/g, " ").trim();
  if (cleaned.length < 2 || cleaned.length > 160) {
    return undefined;
  }
  if (/^https?:\/\//i.test(cleaned) || /[@<>]/.test(cleaned)) {
    return undefined;
  }
  return cleaned;
}

function normalizeTicker(input: string): string | undefined {
  const value = input.trim().toUpperCase();
  return /^[A-Z][A-Z0-9.-]{0,9}$/.test(value) ? value : undefined;
}

function normalizeRegistryId(input: string): string | undefined {
  const value = input.replace(/\s+/g, "").trim().toUpperCase();
  return /^[A-Z0-9-]{2,40}$/.test(value) ? value : undefined;
}

function normalizeDomain(input: string): string | undefined {
  const value = input.trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/?#]/, 1)[0] ?? "";
  if (value.length > 253 || !value.includes(".") || value.includes("..")) {
    return undefined;
  }
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value)) {
    return undefined;
  }
  return value.replace(/\.$/, "");
}

async function readResponseTextBounded(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) {
    return "";
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

function stableObservationId(source: string, target: string, type: string, value: string): string {
  return createHash("sha256").update(`${source}\0${target}\0${type}\0${value}`).digest("hex").slice(0, 24);
}

function unique(values: readonly string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

function canonicalBusinessName(value: string): string {
  return value.toLowerCase()
    .replace(/&/g, " and ")
    .replace(/\b(?:incorporated|inc|corp|corporation|co|company|llc|ltd|limited|plc|holdings|holding)\b\.?/g, " ")
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function slugifyBusinessName(value: string): string {
  return value.toLowerCase()
    .replace(/&/g, " and ")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export const testing = {
  buildChinaBusinessRegisterLeads,
  buildEuBusinessRegisterLeads,
  buildJapanBusinessRegisterLeads,
  buildProfessionalProfileLeads,
  buildWorkplaceReviewLeads,
  canonicalBusinessName,
  chinaGsxtSearchUrl,
  japanCorporateNumberSearchUrl,
  japanGbizInfoSearchUrl,
  computeMarketMetrics,
  latestCompanyFact,
  normalizeAbnLookupRows,
  normalizeBusinessName,
  normalizeCompaniesHouseSearchRows,
  normalizeFtcReleaseNoticeRows,
  normalizeRegistryId,
  normalizeSecCompanyTickerRows,
  normalizeSecCompanyFacts,
  normalizeSecSubmissions,
  normalizeTaiwanGcisRows,
  normalizeYahooChartSnapshot,
  parseJsonOrJsonp,
  parseBbbProfileLinks,
  taiwanFindbizUrl,
  taiwanGcisApiUrl,
  yahooChartUrl,
};
