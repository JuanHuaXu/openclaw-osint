import { createHash } from "node:crypto";
import { fetchWithSsrFGuard } from "openclaw/plugin-sdk/ssrf-runtime";
import { Type, type Static } from "typebox";
import { OsintCache } from "./cache.js";

const FTC_SOURCE = "ftc-dnc";
const SPAMHAUS_SOURCE = "spamhaus-drop";
const FTC_TIMEOUT_MS = 12_000;
const SPAMHAUS_TIMEOUT_MS = 12_000;
const ABUSEIPDB_TIMEOUT_MS = 12_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const FTC_TTL_MS = 6 * 60 * 60 * 1000;
const SPAMHAUS_TTL_MS = 12 * 60 * 60 * 1000;

export const PhoneReputationSchema = Type.Object(
  {
    phone: Type.String({
      description: "Phone number to check against bounded public spam/robocall reputation data.",
    }),
    days: Type.Optional(
      Type.Integer({
        description: "Recent FTC complaint window to inspect. Defaults to 14 days.",
        minimum: 1,
        maximum: 30,
      }),
    ),
    refresh: Type.Optional(Type.Boolean({ description: "Bypass fresh local cache." })),
  },
  { additionalProperties: false },
);

export const InfraReputationSchema = Type.Object(
  {
    ip: Type.String({
      description: "IPv4 address to check against infrastructure abuse reputation sources.",
    }),
    refresh: Type.Optional(Type.Boolean({ description: "Bypass fresh local cache." })),
  },
  { additionalProperties: false },
);

export const BotIdentityAssessSchema = Type.Object(
  {
    subject: Type.String({ description: "Bot, account, service, or indicator being assessed." }),
    platformBot: Type.Optional(Type.Boolean({ description: "Platform metadata says this is a bot/app/webhook." })),
    officialServiceSource: Type.Optional(
      Type.Boolean({ description: "A public official source ties the subject to a service or organization." }),
    ),
    phoneComplaintCount: Type.Optional(
      Type.Integer({ description: "FTC or comparable spam/robocall complaint count.", minimum: 0 }),
    ),
    phoneRobocallCount: Type.Optional(
      Type.Integer({ description: "Complaints marked as robocall/recorded-message.", minimum: 0 }),
    ),
    spamhausListed: Type.Optional(Type.Boolean({ description: "Infrastructure IP is listed by Spamhaus DROP." })),
    abuseConfidenceScore: Type.Optional(
      Type.Integer({ description: "AbuseIPDB abuse confidence score, 0-100.", minimum: 0, maximum: 100 }),
    ),
  },
  { additionalProperties: false },
);

type PhoneReputationParams = Static<typeof PhoneReputationSchema>;
type InfraReputationParams = Static<typeof InfraReputationSchema>;
type BotIdentityAssessParams = Static<typeof BotIdentityAssessSchema>;

type FtcComplaint = {
  id: string;
  phone?: string;
  createdDate: string;
  violationDate: string;
  subject: string;
  robocall: boolean;
};

type ReputationEvidence = {
  source: string;
  claim: string;
  confidence: number;
  verified: boolean;
  details?: Record<string, unknown>;
};

type SourceStatus = {
  source: string;
  status: "checked" | "missing_key" | "not_applicable" | "error";
  detail?: string;
};

export async function queryPhoneReputationForTool(
  params: PhoneReputationParams & { signal?: AbortSignal; cache?: OsintCache },
) {
  const phone = normalizeUsPhone(params.phone);
  if (!phone) {
    return {
      ok: false,
      source: FTC_SOURCE,
      error: "FTC phone reputation currently supports US phone numbers only.",
    };
  }
  const apiKey = process.env.FTC_API_KEY?.trim();
  const days = Math.min(Math.max(params.days ?? 14, 1), 30);
  if (!apiKey) {
    return formatPhoneResult(phone, [], {
      sourceStatuses: [
        {
          source: "local_normalization",
          status: "checked",
          detail: "US phone number was normalized locally.",
        },
        {
          source: FTC_SOURCE,
          status: "missing_key",
          detail: "FTC_API_KEY is required for FTC DNC complaint lookup.",
        },
      ],
      days,
    });
  }

  const target = `phone-us-sha256:${sha256Hex(phone.national)}`;
  const cache = params.cache ?? new OsintCache();
  const closeCache = !params.cache;
  try {
    const fresh = params.refresh ? undefined : cache.getFreshSource(FTC_SOURCE, target);
    if (fresh) {
      return formatPhoneResult(phone, JSON.parse(fresh.rawJson) as FtcComplaint[], {
        cacheStatus: "hit",
        fetchedAt: fresh.fetchedAt,
        expiresAt: fresh.expiresAt,
        days,
        sourceStatuses: [
          { source: "local_normalization", status: "checked" },
          { source: FTC_SOURCE, status: "checked", detail: "FTC DNC complaints served from local cache." },
        ],
      });
    }

    const fetchedAt = Date.now();
    const complaints = await fetchFtcComplaints(phone, days, apiKey, params.signal);
    const rawJson = JSON.stringify(complaints.map(({ phone: _phone, ...complaint }) => complaint));
    cache.putSource({
      source: FTC_SOURCE,
      target,
      fetchedAt,
      expiresAt: fetchedAt + FTC_TTL_MS,
      rawJson,
      rawBytes: Buffer.byteLength(rawJson),
      status: "ok",
    });
    return formatPhoneResult(phone, complaints, {
      cacheStatus: "refreshed",
      fetchedAt,
      expiresAt: fetchedAt + FTC_TTL_MS,
      days,
      sourceStatuses: [
        { source: "local_normalization", status: "checked" },
        { source: FTC_SOURCE, status: "checked", detail: "FTC DNC complaints refreshed from API." },
      ],
    });
  } catch (error) {
    return { ok: false, source: FTC_SOURCE, error: formatError(error) };
  } finally {
    if (closeCache) {
      cache.close();
    }
  }
}

export async function queryInfraReputationForTool(
  params: InfraReputationParams & { signal?: AbortSignal; cache?: OsintCache },
) {
  const ip = normalizeIpv4(params.ip);
  if (!ip) {
    return { ok: false, error: "Expected an IPv4 address." };
  }
  const cache = params.cache ?? new OsintCache();
  const closeCache = !params.cache;
  try {
    const drop = await checkSpamhausDrop(ip, {
      cache,
      refresh: Boolean(params.refresh),
      signal: params.signal,
    });
    const abuse = await checkAbuseIpdb(ip, params.signal);
    const evidence: ReputationEvidence[] = [
      {
        source: SPAMHAUS_SOURCE,
        claim: drop.listed
          ? "IPv4 address is inside a Spamhaus DROP netblock."
          : "IPv4 address was not found in the cached Spamhaus DROP netblocks.",
        confidence: drop.listed ? 0.9 : 0.2,
        verified: true,
        details: {
          cacheStatus: drop.cacheStatus,
          ...(drop.cidr ? { cidr: drop.cidr } : {}),
        },
      },
      ...(abuse ? [abuse] : []),
    ];
    return {
      ok: true,
      ip,
      ownerClassHint: classifyInfra(evidence),
      evidence,
    };
  } catch (error) {
    return { ok: false, error: formatError(error) };
  } finally {
    if (closeCache) {
      cache.close();
    }
  }
}

export function assessBotIdentityForTool(params: BotIdentityAssessParams) {
  const evidence: ReputationEvidence[] = [];
  if (params.platformBot) {
    evidence.push({
      source: "platform_metadata",
      claim: "Platform metadata identifies the subject as a bot, app, or webhook.",
      confidence: 0.95,
      verified: true,
    });
  }
  if (params.officialServiceSource) {
    evidence.push({
      source: "official_public_source",
      claim: "An official public source ties the subject to a service or organization.",
      confidence: 0.9,
      verified: true,
    });
  }
  if ((params.phoneComplaintCount ?? 0) > 0) {
    evidence.push({
      source: FTC_SOURCE,
      claim: "Phone number has public unwanted-call complaint reports.",
      confidence: Math.min(0.75, 0.35 + (params.phoneComplaintCount ?? 0) * 0.03),
      verified: false,
      details: {
        complaintCount: params.phoneComplaintCount,
        robocallCount: params.phoneRobocallCount ?? 0,
      },
    });
  }
  if (params.spamhausListed) {
    evidence.push({
      source: SPAMHAUS_SOURCE,
      claim: "Infrastructure is listed in Spamhaus DROP.",
      confidence: 0.9,
      verified: true,
    });
  }
  if ((params.abuseConfidenceScore ?? 0) >= 25) {
    evidence.push({
      source: "abuseipdb",
      claim: "Infrastructure has a non-zero AbuseIPDB abuse confidence score.",
      confidence: Math.min(0.95, (params.abuseConfidenceScore ?? 0) / 100),
      verified: false,
      details: { abuseConfidenceScore: params.abuseConfidenceScore },
    });
  }

  const score = evidence.reduce((sum, item) => Math.max(sum, item.confidence), 0);
  const ownerClass = params.platformBot || params.officialServiceSource || params.spamhausListed
    ? "bot_or_service_likely"
    : (params.phoneComplaintCount ?? 0) > 0 || (params.abuseConfidenceScore ?? 0) >= 25
    ? "service_or_spam_infra_possible"
    : "unknown_owner";
  return {
    ok: true,
    subject: params.subject,
    ownerClass,
    confidence: Number(score.toFixed(2)),
    allowedActions:
      ownerClass === "unknown_owner"
        ? ["normalize", "reputation_lookup"]
        : ["normalize", "reputation_lookup", "public_service_attribution"],
    blockedActions: ["human_identity_resolution", "address_lookup", "social_dossier_generation"],
    evidence,
    caveat:
      "Reputation evidence can classify risk or service-likeness; it does not identify a private human owner.",
  };
}

async function fetchFtcComplaints(
  phone: { national: string; areaCode: string },
  days: number,
  apiKey: string,
  signal?: AbortSignal,
): Promise<FtcComplaint[]> {
  const to = new Date();
  const from = new Date(to.getTime() - days * 24 * 60 * 60 * 1000);
  const url = new URL("https://api.ftc.gov/v0/dnc-complaints");
  url.searchParams.set("created_date_from", quoteDate(from));
  url.searchParams.set("created_date_to", quoteDate(to));
  url.searchParams.set("area_code", phone.areaCode);
  url.searchParams.set("items_per_page", "50");
  const guarded = await fetchWithSsrFGuard({
    url: url.toString(),
    init: {
      headers: {
        Accept: "application/json",
        "X-Api-Key": apiKey,
      },
    },
    timeoutMs: FTC_TIMEOUT_MS,
    signal,
    auditContext: "openclaw-osint-ftc-dnc",
  });
  const { response, release } = guarded;
  try {
    if (!response.ok) {
      throw new Error(`FTC DNC returned HTTP ${response.status}`);
    }
    return parseFtcComplaints(await readResponseTextBounded(response, MAX_RESPONSE_BYTES)).filter(
      (complaint) => complaint.phone === phone.national,
    );
  } finally {
    await release();
  }
}

async function checkSpamhausDrop(
  ip: string,
  params: { cache: OsintCache; refresh: boolean; signal?: AbortSignal },
): Promise<{ listed: boolean; cacheStatus: "hit" | "refreshed"; cidr?: string }> {
  const fresh = params.refresh ? undefined : params.cache.getFreshSource(SPAMHAUS_SOURCE, "drop-ipv4");
  const fetchedAt = Date.now();
  let rawList = fresh?.rawJson;
  let cacheStatus: "hit" | "refreshed" = "hit";
  if (!rawList) {
    rawList = await fetchSpamhausDrop(params.signal);
    params.cache.putSource({
      source: SPAMHAUS_SOURCE,
      target: "drop-ipv4",
      fetchedAt,
      expiresAt: fetchedAt + SPAMHAUS_TTL_MS,
      rawJson: rawList,
      rawBytes: Buffer.byteLength(rawList),
      status: "ok",
    });
    cacheStatus = "refreshed";
  }
  const cidr = findContainingCidr(ip, parseSpamhausDrop(rawList));
  return { listed: Boolean(cidr), cacheStatus, ...(cidr ? { cidr } : {}) };
}

async function fetchSpamhausDrop(signal?: AbortSignal): Promise<string> {
  const guarded = await fetchWithSsrFGuard({
    url: "https://www.spamhaus.org/drop/drop.txt",
    init: { headers: { Accept: "text/plain" } },
    timeoutMs: SPAMHAUS_TIMEOUT_MS,
    signal,
    auditContext: "openclaw-osint-spamhaus-drop",
  });
  const { response, release } = guarded;
  try {
    if (!response.ok) {
      throw new Error(`Spamhaus DROP returned HTTP ${response.status}`);
    }
    return await readResponseTextBounded(response, MAX_RESPONSE_BYTES);
  } finally {
    await release();
  }
}

async function checkAbuseIpdb(ip: string, signal?: AbortSignal): Promise<ReputationEvidence | undefined> {
  const apiKey = process.env.ABUSEIPDB_API_KEY?.trim();
  if (!apiKey) {
    return undefined;
  }
  const url = new URL("https://api.abuseipdb.com/api/v2/check");
  url.searchParams.set("ipAddress", ip);
  url.searchParams.set("maxAgeInDays", "90");
  const guarded = await fetchWithSsrFGuard({
    url: url.toString(),
    init: {
      headers: {
        Accept: "application/json",
        Key: apiKey,
      },
    },
    timeoutMs: ABUSEIPDB_TIMEOUT_MS,
    signal,
    auditContext: "openclaw-osint-abuseipdb",
  });
  const { response, release } = guarded;
  try {
    if (!response.ok) {
      throw new Error(`AbuseIPDB returned HTTP ${response.status}`);
    }
    const parsed = JSON.parse(await readResponseTextBounded(response, MAX_RESPONSE_BYTES)) as {
      data?: { abuseConfidenceScore?: number; totalReports?: number; usageType?: string; isp?: string };
    };
    const data = parsed.data ?? {};
    const score = Number(data.abuseConfidenceScore ?? 0);
    return {
      source: "abuseipdb",
      claim: score > 0
        ? "IP address has AbuseIPDB report history."
        : "IP address has no AbuseIPDB abuse confidence score.",
      confidence: Math.min(0.95, score / 100),
      verified: false,
      details: {
        abuseConfidenceScore: score,
        totalReports: Number(data.totalReports ?? 0),
        ...(data.usageType ? { usageType: data.usageType } : {}),
        ...(data.isp ? { isp: data.isp } : {}),
      },
    };
  } finally {
    await release();
  }
}

function formatPhoneResult(
  phone: { e164: string; national: string },
  complaints: readonly FtcComplaint[],
  meta: {
    cacheStatus?: "hit" | "refreshed";
    fetchedAt?: number;
    expiresAt?: number;
    days: number;
    sourceStatuses: readonly SourceStatus[];
  },
) {
  const robocallCount = complaints.filter((complaint) => complaint.robocall).length;
  return {
    ok: true,
    source: FTC_SOURCE,
    attribution:
      "Local normalization is keyless. FTC data is from Do Not Call reported-call complaints when FTC_API_KEY is configured; reports are unverified.",
    phone: phone.e164,
    ...(meta.cacheStatus ? { cacheStatus: meta.cacheStatus } : {}),
    ...(meta.fetchedAt ? { fetchedAt: meta.fetchedAt } : {}),
    ...(meta.expiresAt ? { expiresAt: meta.expiresAt } : {}),
    windowDays: meta.days,
    sourceStatuses: meta.sourceStatuses,
    complaintCount: complaints.length,
    robocallCount,
    confidence: complaints.length === 0 ? 0.1 : Math.min(0.75, 0.35 + complaints.length * 0.03),
    ownerClassHint: complaints.length > 0 ? "service_or_spam_infra_possible" : "unknown_owner",
    complaints: complaints.slice(0, 10).map((complaint) => ({
      id: complaint.id,
      createdDate: complaint.createdDate,
      violationDate: complaint.violationDate,
      subject: complaint.subject,
      robocall: complaint.robocall,
    })),
    caveat:
      "FTC reports are consumer complaints and are not verified; phone numbers may be spoofed or reassigned.",
  };
}

function parseFtcComplaints(rawJson: string): FtcComplaint[] {
  const parsed = JSON.parse(rawJson) as { data?: Array<{ id?: string; attributes?: Record<string, unknown> }> };
  return (parsed.data ?? []).flatMap((row) => {
    const attrs = row.attributes ?? {};
    const phone = String(attrs["company-phone-number"] ?? "").replace(/\D/g, "");
    if (!phone) {
      return [];
    }
    return [{
      id: String(row.id ?? ""),
      phone,
      createdDate: String(attrs["created-date"] ?? ""),
      violationDate: String(attrs["violation-date"] ?? ""),
      subject: String(attrs.subject ?? ""),
      robocall: String(attrs["recorded-message-or-robocall"] ?? "").toUpperCase() === "Y",
    }];
  });
}

function parseSpamhausDrop(input: string): string[] {
  return input
    .split(/\r?\n/g)
    .map((line) => line.split(";", 1)[0]?.trim() ?? "")
    .filter((line) => /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(line));
}

function findContainingCidr(ip: string, cidrs: readonly string[]): string | undefined {
  const value = ipv4ToInt(ip);
  for (const cidr of cidrs) {
    const [base, bitsText] = cidr.split("/", 2);
    const bits = Number(bitsText);
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    if ((value & mask) === (ipv4ToInt(base ?? "") & mask)) {
      return cidr;
    }
  }
  return undefined;
}

function classifyInfra(evidence: readonly ReputationEvidence[]): string {
  if (evidence.some((item) => item.source === SPAMHAUS_SOURCE && item.confidence >= 0.9)) {
    return "bot_or_service_likely";
  }
  const abuseScore = evidence.find((item) => item.source === "abuseipdb")?.details?.abuseConfidenceScore;
  return typeof abuseScore === "number" && abuseScore >= 25 ? "service_or_spam_infra_possible" : "unknown_owner";
}

function normalizeUsPhone(input: string): { e164: string; national: string; areaCode: string } | undefined {
  const digits = input.replace(/\D/g, "");
  const national = digits.length === 11 && digits.startsWith("1") ? digits.slice(1) : digits;
  if (national.length !== 10) {
    return undefined;
  }
  return { e164: `+1${national}`, national, areaCode: national.slice(0, 3) };
}

function normalizeIpv4(input: string): string | undefined {
  const parts = input.trim().split(".");
  if (parts.length !== 4) {
    return undefined;
  }
  const octets = parts.map((part) => Number(part));
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return undefined;
  }
  return octets.join(".");
}

function ipv4ToInt(input: string): number {
  const ip = normalizeIpv4(input);
  if (!ip) {
    return 0;
  }
  return ip.split(".").reduce((value, part) => ((value << 8) + Number(part)) >>> 0, 0);
}

function quoteDate(date: Date): string {
  const value = date.toISOString().slice(0, 19).replace("T", " ");
  return `"${value}"`;
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
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

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export const testing = {
  assessBotIdentityForTool,
  findContainingCidr,
  normalizeIpv4,
  normalizeUsPhone,
  parseFtcComplaints,
  parseSpamhausDrop,
  queryPhoneReputationForTool,
};
