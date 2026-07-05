import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { OsintCache } from "../dist/src/cache.js";
import { testing as crtshTesting } from "../dist/src/crtsh.js";
import { testing as domainNetworkTesting } from "../dist/src/domain-network.js";
import { testing as hibpTesting } from "../dist/src/hibp.js";
import { testing as reputationTesting } from "../dist/src/reputation.js";
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

  it("parses bgp.tools WHOIS rows", () => {
    assert.deepEqual(
      domainNetworkTesting.parseBgpToolsWhois(`
        AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name
        13335   | 1.1.1.1          | 1.1.1.0/24          | US | ARIN     | 0001-01-01 | Cloudflare, Inc.
      `),
      {
        asn: "13335",
        ip: "1.1.1.1",
        prefix: "1.1.1.0/24",
        countryCode: "US",
        registry: "ARIN",
        allocated: "0001-01-01",
        asName: "Cloudflare, Inc.",
      },
    );
  });

  it("keeps traceroute as an operator-side plan", () => {
    const plan = domainNetworkTesting.traceroutePlan("example.com", [
      { address: "203.0.113.42" },
    ]);

    assert.equal(plan.automated, false);
    assert.equal(plan.commands.includes("traceroute example.com"), true);
    assert.equal(plan.commands.includes("traceroute 203.0.113.42"), true);
  });

  it("correlates DNS, BGP, and traceroute plan into network paths", () => {
    const dns = [{ family: 4, address: "104.20.23.154", ttl: 300 }];
    const bgp = [
      {
        asn: "13335",
        ip: "104.20.23.154",
        prefix: "104.20.16.0/20",
        countryCode: "US",
        registry: "ARIN",
        allocated: "0001-01-01",
        asName: "Cloudflare, Inc.",
      },
    ];
    const trace = domainNetworkTesting.traceroutePlan("example.com", dns);

    assert.deepEqual(domainNetworkTesting.summarizeNetworkIntel(dns, bgp, true), {
      resolvedIpCount: 1,
      dnsFamilies: [4],
      bgpResolvedCount: 1,
      bgpErrorCount: 0,
      asnCount: 1,
      primaryAsns: ["AS13335 Cloudflare, Inc."],
      networkShape: "cdn_or_anycast_likely",
      tracerouteAvailable: "operator_plan_only",
    });
    assert.deepEqual(domainNetworkTesting.correlateNetworkPaths(dns, bgp, trace), [
      {
        ip: "104.20.23.154",
        dns: { family: 4, ttl: 300 },
        bgp: {
          asn: "13335",
          prefix: "104.20.16.0/20",
          asName: "Cloudflare, Inc.",
          countryCode: "US",
          registry: "ARIN",
          allocated: "0001-01-01",
        },
        trace: {
          automated: false,
          status: "not_run",
          operatorCommand: "traceroute 104.20.23.154",
        },
        assessment: {
          role: "edge_or_cdn_endpoint",
          confidence: 0.75,
        },
      },
    ]);
  });

  it("normalizes HIBP email input without accepting malformed addresses", () => {
    assert.equal(hibpTesting.normalizeEmail(" USER@Example.COM "), "user@example.com");
    assert.equal(hibpTesting.normalizeEmail("not-an-email"), undefined);
  });

  it("normalizes only SHA-1 or NTLM password hashes", () => {
    assert.deepEqual(
      hibpTesting.normalizePasswordHash(
        "21BD12DC183F740EE76F27B78EB39C8AD972A757",
        "auto",
      ),
      {
        algorithm: "sha1",
        prefix: "21BD1",
        suffix: "2DC183F740EE76F27B78EB39C8AD972A757",
      },
    );
    assert.deepEqual(
      hibpTesting.normalizePasswordHash("8846F7EAEE8FB117AD06BDD830B7586C", "ntlm"),
      {
        algorithm: "ntlm",
        prefix: "8846F",
        suffix: "7EAEE8FB117AD06BDD830B7586C",
      },
    );
    assert.equal(hibpTesting.normalizePasswordHash("plaintext-password", "auto"), undefined);
    assert.equal(
      hibpTesting.normalizePasswordHash("8846F7EAEE8FB117AD06BDD830B7586C", "sha1"),
      undefined,
    );
  });

  it("parses pwned password suffix ranges", () => {
    const suffixes = hibpTesting.parsePwnedPasswordSuffixes(`
      2DC183F740EE76F27B78EB39C8AD972A757:42
      00000000000000000000000000000000000:0
      not-a-suffix
    `);

    assert.equal(suffixes.get("2DC183F740EE76F27B78EB39C8AD972A757"), 42);
    assert.equal(suffixes.get("00000000000000000000000000000000000"), 0);
    assert.equal(suffixes.has("NOT-A-SUFFIX"), false);
  });

  it("summarizes HIBP breach JSON without HTML descriptions", () => {
    const breaches = hibpTesting.parseHibpBreaches(JSON.stringify([
      {
        Name: "ExampleBreach",
        Title: "Example Breach",
        Domain: "example.com",
        Description: "<strong>do not replay</strong>",
        DataClasses: ["Email addresses", "Passwords"],
        IsVerified: true,
      },
    ]));

    assert.deepEqual(hibpTesting.publicBreachSummary(breaches[0]), {
      name: "ExampleBreach",
      title: "Example Breach",
      domain: "example.com",
      breachDate: "",
      addedDate: "",
      modifiedDate: "",
      dataClasses: ["Email addresses", "Passwords"],
      isVerified: true,
      isFabricated: false,
      isSensitive: false,
      isRetired: false,
      isSpamList: false,
    });
  });

  it("normalizes US phone numbers for FTC reputation lookup", () => {
    assert.deepEqual(reputationTesting.normalizeUsPhone("+1 (202) 555-0123"), {
      e164: "+12025550123",
      national: "2025550123",
      areaCode: "202",
    });
    assert.equal(reputationTesting.normalizeUsPhone("+44 20 7946 0958"), undefined);
  });

  it("returns keyless phone normalization when FTC key is unavailable", async () => {
    const oldKey = process.env.FTC_API_KEY;
    delete process.env.FTC_API_KEY;
    try {
      const result = await reputationTesting.queryPhoneReputationForTool({
        phone: "+1 (202) 555-0123",
      });

      assert.equal(result.ok, true);
      assert.equal(result.phone, "+12025550123");
      assert.equal(result.complaintCount, 0);
      assert.equal(
        result.sourceLeads.some(
          (lead) => lead.source === "textnow.com" && lead.category === "disposable_or_voip_footprint",
        ),
        true,
      );
      assert.equal(
        result.sourceLeads.some(
          (lead) => lead.source === "truecaller.com" && lead.automation === "blocked",
        ),
        true,
      );
      assert.equal(
        result.sourceStatuses.some(
          (source) => source.source === "ftc-dnc" && source.status === "missing_key",
        ),
        true,
      );
    } finally {
      if (oldKey === undefined) {
        delete process.env.FTC_API_KEY;
      } else {
        process.env.FTC_API_KEY = oldKey;
      }
    }
  });

  it("builds bot-reputation phone source leads without automating person search", () => {
    const leads = reputationTesting.buildPhoneOsintSourceLeads({
      e164: "+12025550123",
      national: "2025550123",
    });

    assert.equal(leads.some((lead) => lead.source === "scamcallfighters.com"), true);
    assert.equal(leads.some((lead) => lead.source === "receive-sms-online.com"), true);
    assert.equal(
      leads
        .filter((lead) => lead.category === "person_search_blocked")
        .every((lead) => lead.automation === "blocked"),
      true,
    );
  });

  it("correlates phone checks with supplied organization domains without ownership claims", async () => {
    const oldKey = process.env.FTC_API_KEY;
    delete process.env.FTC_API_KEY;
    try {
      const result = await reputationTesting.queryPhoneReputationForTool({
        phone: "+1 (202) 555-0123",
        organizationDomain: "not a domain",
      });

      assert.equal(result.ok, true);
      assert.equal(result.networkCorrelation.status, "error");
      assert.match(result.networkCorrelation.basis, /not phone-number ownership/);
    } finally {
      if (oldKey === undefined) {
        delete process.env.FTC_API_KEY;
      } else {
        process.env.FTC_API_KEY = oldKey;
      }
    }
  });

  it("parses FTC complaint records without treating reports as verified identity", () => {
    const complaints = reputationTesting.parseFtcComplaints(JSON.stringify({
      data: [
        {
          id: "abc",
          attributes: {
            "company-phone-number": "2025550123",
            "created-date": "2026-07-01 12:00:00",
            "violation-date": "2026-07-01 11:00:00",
            subject: "Computer & technical support",
            "recorded-message-or-robocall": "Y",
          },
        },
      ],
    }));

    assert.deepEqual(complaints, [
      {
        id: "abc",
        phone: "2025550123",
        createdDate: "2026-07-01 12:00:00",
        violationDate: "2026-07-01 11:00:00",
        subject: "Computer & technical support",
        robocall: true,
      },
    ]);
  });

  it("matches IPv4 addresses against Spamhaus-style CIDR lists", () => {
    const cidrs = reputationTesting.parseSpamhausDrop(`
      ; comment
      203.0.113.0/24 ; example
      bad line
    `);
    assert.deepEqual(cidrs, ["203.0.113.0/24"]);
    assert.equal(reputationTesting.findContainingCidr("203.0.113.42", cidrs), "203.0.113.0/24");
    assert.equal(reputationTesting.findContainingCidr("198.51.100.42", cidrs), undefined);
  });

  it("assesses bot/service likelihood without permitting human doxxing actions", () => {
    const result = reputationTesting.assessBotIdentityForTool({
      subject: "example-service",
      platformBot: true,
      phoneComplaintCount: 4,
      phoneRobocallCount: 2,
    });

    assert.equal(result.ownerClass, "bot_or_service_likely");
    assert.equal(result.blockedActions.includes("human_identity_resolution"), true);
    assert.equal(result.allowedActions.includes("public_service_attribution"), true);
  });
});
