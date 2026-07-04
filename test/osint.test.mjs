import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { OsintCache } from "../dist/src/cache.js";
import { testing as crtshTesting } from "../dist/src/crtsh.js";
import { testing } from "../dist/src/tools.js";

describe("openclaw osint tools", () => {
  it("extracts common indicators without network access", () => {
    const indicators = testing.extractIndicators(`
      Contact admin@example.com and @OpenClawHQ.
      Visit https://example.com/path?q=1, then inspect 203.0.113.42.
      Hash: e3b0c44298fc1c149afbf4c8996fb924
    `);

    assert.deepEqual(indicators.urls, ["https://example.com/path?q=1"]);
    assert.deepEqual(indicators.domains, ["example.com"]);
    assert.deepEqual(indicators.ipv4, ["203.0.113.42"]);
    assert.deepEqual(indicators.emails, ["admin@example.com"]);
    assert.deepEqual(indicators.handles, ["@openclawhq"]);
    assert.deepEqual(indicators.hashes, ["e3b0c44298fc1c149afbf4c8996fb924"]);
  });

  it("accepts only http and https URLs for snapshots", () => {
    assert.equal(testing.normalizePublicHttpUrl("https://example.com/path#frag"), "https://example.com/path");
    assert.equal(testing.normalizePublicHttpUrl("file:///etc/passwd"), undefined);
    assert.equal(testing.normalizePublicHttpUrl("not a url"), undefined);
  });

  it("extracts HTML metadata and visible text", () => {
    const html = `
      <html><head>
        <title>A &amp; B</title>
        <meta name="description" content="Desc &quot;quoted&quot;">
        <link rel="canonical" href="https://example.com/page">
        <style>body { color: red; }</style>
      </head><body><script>alert(1)</script><h1>Hello &amp; welcome</h1></body></html>
    `;

    assert.deepEqual(testing.parseHtmlMetadata(html), {
      title: "A & B",
      description: 'Desc "quoted"',
      canonicalUrl: "https://example.com/page",
    });
    assert.equal(testing.htmlToVisibleText(html), "A & B Hello & welcome");
  });

  it("normalizes canonical URLs without accepting script schemes", () => {
    assert.equal(
      testing.normalizeCanonicalUrl("/page", "https://example.com/root"),
      "https://example.com/page",
    );
    assert.equal(
      testing.normalizeCanonicalUrl("javascript:alert(1)", "https://example.com/root"),
      undefined,
    );
  });

  it("normalizes crt.sh rows into scoped observations", () => {
    const rows = crtshTesting.parseCrtshRows(JSON.stringify([
      {
        id: 123,
        common_name: "*.example.com",
        name_value: "*.example.com\napi.example.com\nother.test",
        issuer_name: "Example CA",
      },
    ]));
    const observations = crtshTesting.observationsFromCrtshRows("example.com", rows, 1_700_000_000_000);

    assert.deepEqual(
      observations.map((observation) => observation.value),
      ["example.com", "api.example.com"],
    );
    assert.equal(observations[0].sourceRef, "crtsh:123");
    assert.equal(observations[0].storageTier, "full");
  });

  it("persists source records and observations in the SQLite cache", () => {
    const dir = mkdtempSync(join(tmpdir(), "openclaw-osint-test-"));
    const cache = new OsintCache(join(dir, "osint.sqlite"));
    try {
      cache.putSource({
        source: "crtsh",
        target: "example.com",
        fetchedAt: 1000,
        expiresAt: Date.now() + 60_000,
        rawJson: "[]",
        rawBytes: 2,
        status: "ok",
      });
      cache.replaceObservations("crtsh", "example.com", [
        {
          id: "obs-1",
          source: "crtsh",
          target: "example.com",
          type: "domain",
          value: "api.example.com",
          confidence: 0.82,
          admissionScore: 0.82,
          storageTier: "full",
          observedAt: 1000,
          sourceRef: "crtsh:1",
        },
      ]);

      assert.equal(cache.getFreshSource("crtsh", "example.com")?.rawJson, "[]");
      assert.equal(cache.listObservations("crtsh", "example.com", 10)[0]?.value, "api.example.com");
      assert.deepEqual(cache.getStatus("crtsh"), {
        source: "crtsh",
        sourceRecords: 1,
        observations: 1,
        rawBytes: 2,
        oldestFetchedAt: 1000,
        newestFetchedAt: 1000,
      });
    } finally {
      cache.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
