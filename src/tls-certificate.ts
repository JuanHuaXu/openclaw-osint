import { createHash } from "node:crypto";
import { promises as dns } from "node:dns";
import { isIP } from "node:net";
import tls from "node:tls";
import { Type, type Static } from "typebox";

const DEFAULT_PORT = 443;
const DEFAULT_TIMEOUT_MS = 8_000;
const MAX_TIMEOUT_MS = 15_000;
const MAX_CHAIN_DEPTH = 10;

export const TlsCertificateChainSchema = Type.Object(
  {
    host: Type.String({
      description: "Public TLS hostname to inspect.",
    }),
    port: Type.Optional(
      Type.Integer({
        description: "TLS port. Defaults to 443.",
        minimum: 1,
        maximum: 65535,
      }),
    ),
    timeoutMs: Type.Optional(
      Type.Integer({
        description: "Connection timeout in milliseconds. Defaults to 8000, capped at 15000.",
        minimum: 1000,
        maximum: MAX_TIMEOUT_MS,
      }),
    ),
  },
  { additionalProperties: false },
);

type TlsCertificateChainParams = Static<typeof TlsCertificateChainSchema>;

type PeerCertificate = ReturnType<tls.TLSSocket["getPeerCertificate"]> & {
  issuerCertificate?: PeerCertificate;
  raw?: Buffer;
};

export async function queryTlsCertificateChainForTool(params: TlsCertificateChainParams) {
  const host = normalizePublicHost(params.host);
  if (!host) {
    return { ok: false, error: "Expected a public DNS hostname." };
  }
  const port = params.port ?? DEFAULT_PORT;
  const timeoutMs = Math.min(params.timeoutMs ?? DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS);
  try {
    const resolvedAddresses = await resolvePublicAddresses(host);
    const result = await connectAndReadCertificate(host, port, timeoutMs);
    return {
      ok: true,
      host,
      port,
      authorized: result.authorized,
      authorizationError: result.authorizationError,
      protocol: result.protocol,
      cipher: result.cipher,
      resolvedAddresses,
      chain: result.chain,
      operatorCommand: `openssl s_client -connect ${host}:${port} -servername ${host} -showcerts </dev/null`,
      caveat:
        "Certificate metadata is observed from this machine's network path. The operator command is a reproduction hint and is not executed by the plugin.",
    };
  } catch (error) {
    return { ok: false, host, port, error: formatError(error) };
  }
}

async function resolvePublicAddresses(host: string) {
  const records = await dns.lookup(host, { all: true, verbatim: true });
  if (records.length === 0) {
    throw new Error("Hostname did not resolve.");
  }
  const blocked = records.find((record) => isBlockedIp(record.address));
  if (blocked) {
    throw new Error(`Blocked hostname: resolves to private/internal/special-use IP ${blocked.address}`);
  }
  return records.map((record) => ({ address: record.address, family: record.family }));
}

function connectAndReadCertificate(host: string, port: number, timeoutMs: number) {
  return new Promise<{
    authorized: boolean;
    authorizationError?: string;
    protocol?: string;
    cipher?: ReturnType<tls.TLSSocket["getCipher"]>;
    chain: ReturnType<typeof collectCertificateChain>;
  }>((resolve, reject) => {
    const socket = tls.connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
      timeout: timeoutMs,
    });
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      if (error) {
        reject(error);
      }
    };
    socket.once("secureConnect", () => {
      const authorizationError = socket.authorizationError;
      const certificate = socket.getPeerCertificate(true) as PeerCertificate;
      const chain = collectCertificateChain(certificate);
      const result = {
        authorized: socket.authorized,
        ...(authorizationError ? { authorizationError: String(authorizationError) } : {}),
        ...(socket.getProtocol() ? { protocol: socket.getProtocol() ?? undefined } : {}),
        cipher: socket.getCipher(),
        chain,
      };
      settled = true;
      socket.end();
      resolve(result);
    });
    socket.once("timeout", () => finish(new Error("TLS certificate lookup timed out")));
    socket.once("error", (error) => finish(error));
  });
}

function collectCertificateChain(certificate: PeerCertificate) {
  const chain = [];
  const seen = new Set<string>();
  let current: PeerCertificate | undefined = certificate;
  for (let depth = 0; current && depth < MAX_CHAIN_DEPTH; depth += 1) {
    const fingerprint = current.fingerprint256 || sha256Hex(current.raw);
    if (!fingerprint || seen.has(fingerprint)) {
      break;
    }
    seen.add(fingerprint);
    chain.push(formatCertificate(current, depth));
    current = current.issuerCertificate && current.issuerCertificate !== current
      ? current.issuerCertificate
      : undefined;
  }
  return chain;
}

function formatCertificate(certificate: PeerCertificate, depth: number) {
  return {
    depth,
    subject: compactNameObject(certificate.subject),
    issuer: compactNameObject(certificate.issuer),
    subjectAltNames: parseSubjectAltNames(certificate.subjectaltname),
    validFrom: certificate.valid_from,
    validTo: certificate.valid_to,
    serialNumber: certificate.serialNumber,
    fingerprint256: certificate.fingerprint256,
    fingerprint512: certificate.fingerprint512,
    publicKeyBits: certificate.bits,
    rawSha256: sha256Hex(certificate.raw),
  };
}

function parseSubjectAltNames(value?: string): string[] {
  if (!value) {
    return [];
  }
  return value.split(/,\s*/g).map((entry) => entry.trim()).filter(Boolean).slice(0, 50);
}

function compactNameObject(value: unknown): Record<string, string> {
  if (!value || typeof value !== "object") {
    return {};
  }
  const result: Record<string, string> = {};
  for (const [key, raw] of Object.entries(value)) {
    if (typeof raw === "string") {
      result[key] = raw;
    }
  }
  return result;
}

function normalizePublicHost(input: string): string | undefined {
  const trimmed = input.trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/?#]/, 1)[0] ?? "";
  const host = trimmed.replace(/\.$/, "");
  if (!host || host.length > 253 || host.includes("..") || isIP(host)) {
    return undefined;
  }
  if (isBlockedHostname(host)) {
    return undefined;
  }
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host) || !host.includes(".")) {
    return undefined;
  }
  return host;
}

function isBlockedHostname(host: string): boolean {
  return host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal");
}

function isBlockedIp(address: string): boolean {
  return isIP(address) === 6 ? isBlockedIpv6(address) : isBlockedIpv4(address);
}

function isBlockedIpv4(address: string): boolean {
  const value = ipv4ToNumber(address);
  return [
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
  ].some(([base, prefix]) => ipv4InCidr(value, ipv4ToNumber(String(base)), Number(prefix)));
}

function isBlockedIpv6(address: string): boolean {
  const normalized = address.toLowerCase();
  return (
    normalized === "::1" ||
    normalized === "::" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80") ||
    normalized.startsWith("2001:db8") ||
    normalized.startsWith("ff")
  );
}

function ipv4InCidr(value: number, base: number, prefix: number): boolean {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (base & mask);
}

function ipv4ToNumber(address: string): number {
  return address.split(".").reduce((value, part) => ((value << 8) + Number(part)) >>> 0, 0);
}

function sha256Hex(value?: Buffer): string | undefined {
  return value ? createHash("sha256").update(value).digest("hex") : undefined;
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export const testing = {
  collectCertificateChain,
  isBlockedIpv4,
  isBlockedIpv6,
  normalizePublicHost,
  parseSubjectAltNames,
};
