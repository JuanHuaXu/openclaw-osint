import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { promises as dns } from "node:dns";
import { isIP } from "node:net";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const DEFAULT_TIMEOUT_MS = 12_000;
const MAX_BODY_BYTES = 1024 * 1024;
const TCPDUMP_PACKET_LIMIT = 200;
const TCPDUMP_LOG_SAMPLE = 20;

export type TargetFetchResult = {
  ok: true;
  url: string;
  finalUrl: string;
  status: number;
  headers: Headers;
  body: string;
  networkCapture?: NetworkCaptureSummary;
} | {
  ok: false;
  url?: string;
  error: string;
};

export type NetworkCaptureSummary = {
  backend: "podman";
  namespace: string;
  interface: "eth0";
  packetsCaptured: number;
  packetsReceivedByFilter: number;
  packetsDroppedByKernel: number;
  dnsQueries: string[];
  tcp?: {
    remoteIp: string;
    remotePort: number;
    synToSynAckMs?: number;
    retransmits: number;
  };
  payloadBytes: {
    outbound: number;
    inbound: number;
  };
  sample: string[];
  caveat: string;
};

export async function fetchTargetWithOptionalCapture(params: {
  url: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<TargetFetchResult | undefined> {
  if ((process.env.OPENCLAW_OSINT_TARGET_FETCH_BACKEND ?? "local").toLowerCase() !== "podman") {
    return undefined;
  }
  const normalizedUrl = normalizeHttpUrl(params.url);
  if (!normalizedUrl) {
    return { ok: false, error: "Expected a public HTTP(S) URL." };
  }
  const publicTargetError = await assertPublicTarget(normalizedUrl);
  if (publicTargetError) {
    return { ok: false, url: normalizedUrl, error: publicTargetError };
  }
  return fetchWithPodmanCapture({
    url: normalizedUrl,
    timeoutMs: params.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    signal: params.signal,
  });
}

async function fetchWithPodmanCapture(params: {
  url: string;
  timeoutMs: number;
  signal?: AbortSignal;
}): Promise<TargetFetchResult> {
  const podman = process.env.OPENCLAW_OSINT_PODMAN_BIN || "podman";
  const suffix = randomUUID().replace(/-/g, "").slice(0, 12);
  const network = `openclaw-osint-${suffix}`;
  const worker = `osint-fetch-${suffix}`;
  const sidecar = `osint-pcap-${suffix}`;
  const timeoutSeconds = Math.max(2, Math.ceil(params.timeoutMs / 1000));
  try {
    await run(podman, ["network", "create", network], params.signal);
    await run(podman, [
      "run",
      "-d",
      "--rm",
      "--name",
      worker,
      "--network",
      network,
      "--entrypoint",
      "sleep",
      "docker.io/curlimages/curl:latest",
      String(timeoutSeconds + 30),
    ], params.signal);
    await run(podman, [
      "run",
      "-d",
      "--name",
      sidecar,
      "--network",
      `container:${worker}`,
      "--cap-add=NET_RAW",
      "--cap-add=NET_ADMIN",
      "docker.io/nicolaka/netshoot:latest",
      "tcpdump",
      "-tt",
      "-i",
      "eth0",
      "-nn",
      "-c",
      String(TCPDUMP_PACKET_LIMIT),
      "(tcp port 443 or tcp port 80 or udp port 53)",
    ], params.signal);
    await sleep(500);
    const meta = await run(podman, [
      "exec",
      worker,
      "curl",
      "-sS",
      "--max-time",
      String(timeoutSeconds),
      "--proto",
      "=http,https",
      "--max-redirs",
      "0",
      "--dump-header",
      "/tmp/openclaw-headers",
      "--output",
      "/tmp/openclaw-body",
      "--write-out",
      "OPENCLAW_CURL_META\\n%{http_code}\\n%{url_effective}\\n%{content_type}\\n",
      params.url,
    ], params.signal);
    await sleep(700);
    const headersRaw = await run(podman, ["exec", worker, "cat", "/tmp/openclaw-headers"], params.signal);
    const body = await run(podman, ["exec", worker, "head", "-c", String(MAX_BODY_BYTES), "/tmp/openclaw-body"], params.signal);
    await run(podman, ["stop", sidecar], params.signal).catch(() => undefined);
    const tcpdumpLog = await run(podman, ["logs", sidecar], params.signal)
      .then((result) => result.stdout)
      .catch((error) => formatError(error));
    const headers = parseCurlHeaders(headersRaw.stdout);
    const parsedMeta = parseCurlMeta(meta.stdout, params.url, headers);
    return {
      ok: true,
      url: params.url,
      finalUrl: parsedMeta.finalUrl,
      status: parsedMeta.status,
      headers,
      body: body.stdout,
      networkCapture: parseTcpdumpSummary(tcpdumpLog, sidecar),
    };
  } catch (error) {
    return { ok: false, url: params.url, error: formatError(error) };
  } finally {
    await run(podman, ["rm", "-f", sidecar, worker]).catch(() => undefined);
    await run(podman, ["network", "rm", network]).catch(() => undefined);
  }
}

function parseCurlHeaders(raw: string): Headers {
  const headers = new Headers();
  for (const line of raw.split(/\r?\n/)) {
    const index = line.indexOf(":");
    if (index <= 0) {
      continue;
    }
    headers.append(line.slice(0, index).trim(), line.slice(index + 1).trim());
  }
  return headers;
}

function parseCurlMeta(raw: string, fallbackUrl: string, headers: Headers) {
  const marker = "OPENCLAW_CURL_META";
  const lines = raw.slice(raw.lastIndexOf(marker) + marker.length).trim().split(/\r?\n/);
  const status = Number.parseInt(lines[0] || "", 10);
  const finalUrl = normalizeHttpUrl(lines[1] || "") ?? fallbackUrl;
  if (!headers.get("content-type") && lines[2]) {
    headers.set("content-type", lines[2]);
  }
  return {
    status: Number.isFinite(status) ? status : 0,
    finalUrl,
  };
}

function parseTcpdumpSummary(raw: string, namespace: string): NetworkCaptureSummary {
  const lines = raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const packetLines = lines.filter((line) => /^\d+\.\d+\s+IP /.test(line));
  const dnsQueries = Array.from(new Set(packetLines.flatMap((line) => {
    const match = line.match(/\b(?:A|AAAA|HTTPS|CNAME)\?\s+([^ ]+)/);
    return match?.[1] ? [match[1].replace(/\.$/, "")] : [];
  }))).slice(0, 20);
  const syn = packetLines.find((line) => /Flags \[S\]/.test(line));
  const synAck = packetLines.find((line) => /Flags \[S\.\]/.test(line));
  const tcpMatch = syn?.match(/^(\d+\.\d+)\s+IP\s+([^ ]+)\s+>\s+([^:]+):/);
  const synAckTime = synAck?.match(/^(\d+\.\d+)/)?.[1];
  const remote = tcpMatch?.[3] ? parseEndpoint(tcpMatch[3]) : undefined;
  const synToSynAckMs = tcpMatch?.[1] && synAckTime
    ? Math.max(0, Math.round((Number(synAckTime) - Number(tcpMatch[1])) * 1000))
    : undefined;
  const payloadBytes = packetLines.reduce((sum, line) => {
    const length = Number.parseInt(line.match(/\blength\s+(\d+)/)?.[1] || "0", 10);
    if (!Number.isFinite(length) || length <= 0) {
      return sum;
    }
    return /IP\s+10\.\d+\.\d+\.\d+\.\d+\s+>/.test(line)
      ? { ...sum, outbound: sum.outbound + length }
      : { ...sum, inbound: sum.inbound + length };
  }, { outbound: 0, inbound: 0 });
  return {
    backend: "podman",
    namespace,
    interface: "eth0",
    packetsCaptured: summaryCount(lines, /packets captured/) || packetLines.length,
    packetsReceivedByFilter: summaryCount(lines, /packets received by filter/),
    packetsDroppedByKernel: summaryCount(lines, /packets dropped by kernel/),
    dnsQueries,
    ...(remote
      ? {
        tcp: {
          remoteIp: remote.host,
          remotePort: remote.port,
          ...(synToSynAckMs !== undefined ? { synToSynAckMs } : {}),
          retransmits: countRetransmits(packetLines),
        },
      }
      : {}),
    payloadBytes,
    sample: packetLines.slice(0, TCPDUMP_LOG_SAMPLE),
    caveat: "Capture is scoped to the isolated Podman worker namespace and summarized from tcpdump output.",
  };
}

function parseEndpoint(endpoint: string): { host: string; port: number } | undefined {
  const match = endpoint.match(/^(.+)\.(\d+)$/);
  if (!match?.[1] || !match[2]) {
    return undefined;
  }
  return { host: match[1], port: Number.parseInt(match[2], 10) };
}

function summaryCount(lines: readonly string[], pattern: RegExp): number {
  const line = lines.find((value) => pattern.test(value));
  return Number.parseInt(line?.match(/^(\d+)/)?.[1] || "0", 10) || 0;
}

function countRetransmits(lines: readonly string[]): number {
  const seen = new Set<string>();
  let repeats = 0;
  for (const line of lines) {
    const key = line.match(/IP\s+([^ ]+)\s+>\s+([^:]+):.*seq\s+([^,\s]+)/)?.slice(1).join("|");
    if (!key) {
      continue;
    }
    if (seen.has(key)) {
      repeats += 1;
    }
    seen.add(key);
  }
  return repeats;
}

async function assertPublicTarget(url: string): Promise<string | undefined> {
  const parsed = new URL(url);
  const host = parsed.hostname.toLowerCase();
  if (isBlockedHostname(host) || isIP(host) && isBlockedIp(host)) {
    return "Blocked private/internal/special-use target.";
  }
  try {
    const records = await dns.lookup(host, { all: true, verbatim: true });
    const blocked = records.find((record) => isBlockedIp(record.address));
    return blocked ? `Blocked target: resolves to private/internal/special-use IP ${blocked.address}` : undefined;
  } catch (error) {
    return `DNS preflight failed: ${formatError(error)}`;
  }
}

function normalizeHttpUrl(input: string): string | undefined {
  try {
    const parsed = new URL(input.trim());
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return undefined;
    }
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return undefined;
  }
}

function isBlockedHostname(host: string): boolean {
  return host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal");
}

function isBlockedIp(address: string): boolean {
  return isIP(address) === 6 ? isBlockedIpv6(address) : isBlockedIpv4(address);
}

function isBlockedIpv4(address: string): boolean {
  const value = ipv4ToNumber(address);
  const blockedRanges: Array<[string, number]> = [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ];
  return blockedRanges.some(([base, bits]) => sameIpv4Prefix(value, ipv4ToNumber(base), bits));
}

function ipv4ToNumber(address: string): number {
  return address.split(".").reduce((value, part) => (value << 8) + Number(part), 0) >>> 0;
}

function sameIpv4Prefix(value: number, base: number, bits: number): boolean {
  return (value & (0xffffffff << (32 - bits))) === (base & (0xffffffff << (32 - bits)));
}

function isBlockedIpv6(address: string): boolean {
  const lower = address.toLowerCase();
  return lower === "::1" ||
    lower === "::" ||
    lower.startsWith("fc") ||
    lower.startsWith("fd") ||
    lower.startsWith("fe80:") ||
    lower.startsWith("::ffff:127.") ||
    lower.startsWith("::ffff:10.") ||
    lower.startsWith("2001:db8:");
}

async function run(command: string, args: readonly string[], signal?: AbortSignal) {
  return execFileAsync(command, [...args], {
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
    signal,
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function formatError(error: unknown): string {
  if (error && typeof error === "object" && "stderr" in error && typeof error.stderr === "string") {
    return error.stderr.trim() || String(error);
  }
  return error instanceof Error ? error.message : String(error);
}

export const testing = {
  parseTcpdumpSummary,
};
