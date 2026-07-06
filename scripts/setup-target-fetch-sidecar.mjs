#!/usr/bin/env node
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const podman = process.env.OPENCLAW_OSINT_PODMAN_BIN || "podman";
const curlImage = process.env.OPENCLAW_OSINT_CURL_IMAGE || "docker.io/curlimages/curl:latest";
const tcpdumpImage = process.env.OPENCLAW_OSINT_TCPDUMP_IMAGE || "docker.io/nicolaka/netshoot:latest";
const smokeUrl = process.env.OPENCLAW_OSINT_SIDECAR_SMOKE_URL || "https://example.com/";
const suffix = randomUUID().replace(/-/g, "").slice(0, 12);
const network = `openclaw-osint-setup-${suffix}`;
const worker = `osint-setup-fetch-${suffix}`;
const sidecar = `osint-setup-pcap-${suffix}`;

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

async function main() {
  printPlatformNotes();
  await step("checking Podman", [podman, ["--version"]]);
  await step("checking Podman engine", [podman, ["info"]], { quiet: true });
  await step(`pulling ${curlImage}`, [podman, ["pull", curlImage]]);
  await step(`pulling ${tcpdumpImage}`, [podman, ["pull", tcpdumpImage]]);
  const tcpdumpLog = await runSmoke();
  const packetLines = tcpdumpLog.split(/\r?\n/).filter((line) => /^\d+\.\d+\s+IP /.test(line.trim()));
  if (packetLines.length === 0) {
    throw new Error("sidecar smoke failed: tcpdump did not observe packets from the worker namespace");
  }
  console.log(`\nsidecar smoke passed: observed ${packetLines.length} packet line(s)`);
  console.log("\nEnable OpenClaw with:");
  console.log('  OPENCLAW_OSINT_TARGET_FETCH_BACKEND="podman"');
  console.log(`  OPENCLAW_OSINT_PODMAN_BIN="${podman}"`);
}

function printPlatformNotes() {
  console.log("OpenClaw OSINT target-fetch sidecar setup\n");
  console.log("Platform notes:");
  console.log("- macOS: install/start Podman Desktop or `brew install podman && podman machine init --now`.");
  console.log("- WSL2: install podman inside the distro, or use Docker-compatible Podman if your distro provides it.");
  console.log("- Linux: install podman from your distro packages and ensure rootless containers can start.");
  console.log("");
}

async function runSmoke() {
  try {
    await step("creating isolated network", [podman, ["network", "create", network]]);
    await step("starting worker container", [podman, [
      "run",
      "-d",
      "--rm",
      "--name",
      worker,
      "--network",
      network,
      "--entrypoint",
      "sleep",
      curlImage,
      "30",
    ]]);
    await step("starting tcpdump sidecar", [podman, [
      "run",
      "-d",
      "--name",
      sidecar,
      "--network",
      `container:${worker}`,
      "--cap-add=NET_RAW",
      "--cap-add=NET_ADMIN",
      tcpdumpImage,
      "tcpdump",
      "-tt",
      "-i",
      "eth0",
      "-nn",
      "-c",
      "40",
      "(tcp port 443 or tcp port 80 or udp port 53)",
    ]]);
    await sleep(500);
    await step(`fetching ${smokeUrl} inside worker`, [podman, [
      "exec",
      worker,
      "curl",
      "-sS",
      "--max-time",
      "8",
      "--proto",
      "=http,https",
      "--max-redirs",
      "0",
      "--output",
      "/tmp/openclaw-osint-sidecar-smoke",
      smokeUrl,
    ]]);
    await sleep(700);
    await run(podman, ["stop", sidecar]).catch(() => undefined);
    const logs = await run(podman, ["logs", sidecar]).catch((error) => ({ stdout: "", stderr: formatError(error) }));
    return `${logs.stdout}\n${logs.stderr}`;
  } finally {
    await run(podman, ["rm", "-f", sidecar, worker]).catch(() => undefined);
    await run(podman, ["network", "rm", network]).catch(() => undefined);
  }
}

async function step(label, [command, args], options = {}) {
  process.stdout.write(`- ${label} ... `);
  const result = await run(command, args);
  console.log("ok");
  const text = `${result.stdout}${result.stderr}`.trim();
  if (text && !options.quiet) {
    console.log(indent(text));
  }
  return result;
}

async function run(command, args) {
  return execFileAsync(command, args, {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
}

function indent(text) {
  return text.split(/\r?\n/).map((line) => `  ${line}`).join("\n");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function formatError(error) {
  if (error && typeof error === "object" && "stderr" in error && typeof error.stderr === "string") {
    return error.stderr.trim() || String(error);
  }
  return error instanceof Error ? error.message : String(error);
}
