import assert from "node:assert/strict";
import { describe, it } from "node:test";
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
});
