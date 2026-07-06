import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { OsintCache } from "../dist/src/cache.js";
import { testing as businessTesting } from "../dist/src/business.js";
import { testing as cdnTesting } from "../dist/src/cdn.js";
import { testing as cveTesting } from "../dist/src/cve.js";
import { testing as crtshTesting } from "../dist/src/crtsh.js";
import { testing as domainAuthorityTesting } from "../dist/src/domain-authority.js";
import { testing as domainNetworkTesting } from "../dist/src/domain-network.js";
import { testing as hibpTesting } from "../dist/src/hibp.js";
import { testing as ipAssignmentTesting } from "../dist/src/ip-assignment.js";
import { pipelineReconForTool, testing as pipelineTesting } from "../dist/src/pipeline.js";
import { testing as publicKnowledgeTesting } from "../dist/src/public-knowledge.js";
import { testing as reputationTesting } from "../dist/src/reputation.js";
import { testing as shodanTesting } from "../dist/src/shodan.js";
import { testing as tlsCertificateTesting } from "../dist/src/tls-certificate.js";
import { testing as targetFetchTesting } from "../dist/src/target-fetch.js";
import { testing } from "../dist/src/tools.js";

describe("openclaw osint tools", () => {
  it("extracts common indicators without network access", () => {
    const indicators = testing.extractIndicators(`
      Contact admin@example.com and @OpenClawHQ.
      Visit https://example.com/path?q=1, then inspect 203.0.113.42.
      Call +1 (202) 555-0100, but do not treat lockbit123.com as a phone.
      Hash: e3b0c44298fc1c149afbf4c8996fb924
    `);

    assert.deepEqual(indicators.urls, ["https://example.com/path?q=1"]);
    assert.deepEqual(indicators.domains, ["example.com", "lockbit123.com"]);
    assert.deepEqual(indicators.ipv4, ["203.0.113.42"]);
    assert.deepEqual(indicators.emails, ["admin@example.com"]);
    assert.deepEqual(indicators.phones, ["+12025550100"]);
    assert.deepEqual(indicators.handles, ["@openclawhq"]);
    assert.deepEqual(indicators.hashes, ["e3b0c44298fc1c149afbf4c8996fb924"]);
  });

  it("accepts only http and https URLs for snapshots", () => {
    assert.equal(testing.normalizePublicHttpUrl("https://example.com/path#frag"), "https://example.com/path");
    assert.equal(testing.normalizePublicHttpUrl("file:///etc/passwd"), undefined);
    assert.equal(testing.normalizePublicHttpUrl("not a url"), undefined);
  });

  it("extracts passive software and OS fingerprints from headers and 404 bodies", () => {
    const fingerprints = testing.fingerprintFromHttpEvidence({
      headers: {
        server: "Apache/2.4.58 (Ubuntu)",
        "x-powered-by": "PHP/8.2.12",
      },
      html: `
        <html><head><title>404 Not Found</title></head>
        <body><h1>Not Found</h1><address>Apache Server at example.com Port 443</address></body></html>
      `,
      source: "404_probe",
    });

    assert.equal(fingerprints.some((item) => item.name === "Apache httpd" && item.version === "2.4.58"), true);
    assert.equal(fingerprints.some((item) => item.name === "PHP" && item.version === "8.2.12"), true);
    assert.equal(fingerprints.some((item) => item.kind === "os" && item.name === "Ubuntu Linux"), true);
  });

  it("profiles Node, Express, Uvicorn, and FastAPI-style passive evidence", () => {
    const fingerprints = testing.fingerprintFromHttpEvidence({
      headers: {
        server: "uvicorn",
        "x-powered-by": "Express",
        "set-cookie": "connect.sid=s%3Atest; Path=/; HttpOnly",
      },
      html: `
        Cannot GET /assets/deadbeef.css
        {"detail":"Not Found"}
        at Layer.handle [as handle_request] (node:internal/modules/cjs/loader:123:45)
      `,
      source: "404_probe",
    });

    assert.equal(fingerprints.some((item) => item.kind === "software" && item.name === "Uvicorn"), true);
    assert.equal(fingerprints.some((item) => item.kind === "framework" && item.name === "Express"), true);
    assert.equal(fingerprints.some((item) => item.kind === "software" && item.name === "Node.js"), true);
    assert.equal(fingerprints.some((item) => item.kind === "framework" && item.name === "FastAPI/Starlette"), true);
    assert.equal(fingerprints.some((item) => item.kind === "framework" && item.name === "Express session middleware"), true);
  });

  it("reads Headers-like objects from guarded fetch runtimes for fingerprints", () => {
    const fingerprints = testing.fingerprintFromHttpEvidence({
      headers: {
        get(name) {
          return name.toLowerCase() === "server" ? "gunicorn/19.9.0" : undefined;
        },
      },
      html: "",
      source: "initial_response",
    });

    assert.equal(fingerprints.some((item) => item.name === "gunicorn" && item.version === "19.9.0"), true);
  });

  it("profiles Astro, Preact, and app-version frontend evidence", () => {
    const fingerprints = testing.fingerprintFromHttpEvidence({
      headers: {},
      html: `
        <link rel="stylesheet" href="/_astro/Base.hash.css">
        <script>self.Astro = self.Astro || {};</script>
        <astro-island data-preact-island-id="1" component-url="/_astro/Widget.hash.js"></astro-island>
        <div class="terminal-line">DemoOS v1.2.3</div>
      `,
      source: "initial_response",
    });

    assert.equal(fingerprints.some((item) => item.kind === "framework" && item.name === "Astro"), true);
    assert.equal(fingerprints.some((item) => item.kind === "framework" && item.name === "Preact"), true);
    assert.equal(fingerprints.some((item) => item.kind === "software" && item.name === "DemoOS" && item.version === "1.2.3"), true);
  });

  it("maps concrete fingerprints to bounded CVE identities", () => {
    const fingerprints = cveTesting.normalizeFingerprintInputs({
      fingerprints: [
        { name: "nginx", version: "1.29.8", confidence: "high" },
        { name: "Next.js", version: "15.3.4", confidence: "high" },
        { name: "Caddy", confidence: "medium" },
      ],
    });

    assert.deepEqual(fingerprints.map((item) => `${item.name}@${item.version ?? ""}`), [
      "nginx@1.29.8",
      "Next.js@15.3.4",
      "Caddy@",
    ]);
    assert.deepEqual(cveTesting.identityForFingerprint(fingerprints[0]), [{
      source: "nvd",
      type: "cpe",
      cpe: "cpe:2.3:a:nginx:nginx:1.29.8:*:*:*:*:*:*:*",
    }]);
    assert.deepEqual(cveTesting.identityForFingerprint(fingerprints[1]), [{
      source: "osv",
      type: "package",
      ecosystem: "npm",
      packageName: "next",
    }]);
    assert.deepEqual(cveTesting.identityForFingerprint(fingerprints[2]), []);
  });

  it("classifies RCE and adjacent vulnerability shapes", () => {
    assert.deepEqual(cveTesting.classifyImpact("Remote code execution via command injection."), ["rce"]);
    assert.deepEqual(cveTesting.classifyImpact("Denial of service crash from NULL pointer."), ["crash"]);
    assert.deepEqual(cveTesting.classifyImpact("Out-of-bounds read causes information disclosure."), ["bleed"]);
    assert.deepEqual(cveTesting.classifyImpact("Authentication bypass and SSRF enable internal hop."), ["hop"]);
  });

  it("parses NVD and OSV findings into impact-filterable rows", () => {
    const nvd = cveTesting.parseNvdFindings({
      vulnerabilities: [{
        cve: {
          id: "CVE-2099-0001",
          descriptions: [{ lang: "en", value: "A flaw allows remote code execution in Example." }],
          metrics: {
            cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL" } }],
          },
          references: [{ url: "https://example.test/cve", source: "vendor", tags: ["Exploit"] }],
          cisaExploitAdd: "2099-01-02",
        },
      }],
    });
    const osv = cveTesting.parseOsvFindings({
      vulns: [{
        id: "GHSA-test",
        summary: "Path traversal can lead to sensitive information disclosure.",
        references: [{ url: "https://example.test/ghsa" }],
      }],
    });

    assert.equal(nvd[0].id, "CVE-2099-0001");
    assert.deepEqual(nvd[0].impactTags, ["rce"]);
    assert.equal(nvd[0].severity, "CRITICAL");
    assert.equal(nvd[0].cvss, 9.8);
    assert.equal(nvd[0].knownExploited, true);
    assert.deepEqual(nvd[0].references, ["https://example.test/cve (vendor; Exploit)"]);
    assert.equal(osv[0].id, "GHSA-test");
    assert.deepEqual(osv[0].impactTags, ["bleed", "hop"]);
  });

  it("builds randomized same-origin 404 probe URLs", () => {
    const first = testing.build404ProbeUrl("https://example.com/app/page?q=1#top");
    const second = testing.build404ProbeUrl("https://example.com/app/page?q=1#top");

    assert.match(first, /^https:\/\/example\.com\/(?:assets\/[a-f0-9]{16}\.(?:css|js)|static\/[a-f0-9]{16}\.png|media\/[a-f0-9]{16}\.webp|favicon-[a-f0-9]{16}\.ico|robots-[a-f0-9]{16}\.txt)$/);
    assert.match(second, /^https:\/\/example\.com\/(?:assets\/[a-f0-9]{16}\.(?:css|js)|static\/[a-f0-9]{16}\.png|media\/[a-f0-9]{16}\.webp|favicon-[a-f0-9]{16}\.ico|robots-[a-f0-9]{16}\.txt)$/);
    assert.equal(first.includes("openclaw"), false);
    assert.equal(second.includes("openclaw"), false);
    assert.notEqual(first, second);
  });

  it("summarizes tcpdump output from an isolated target fetch", () => {
    const summary = targetFetchTesting.parseTcpdumpSummary(`
      tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
      listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
      1783308214.612615 IP 10.89.0.2.36128 > 10.89.0.1.53: 55773+ A? example.com. (29)
      1783308214.614504 IP 10.89.0.2.34982 > 104.20.23.154.443: Flags [S], seq 3645541713, win 65480, length 0
      1783308214.620353 IP 104.20.23.154.443 > 10.89.0.2.34982: Flags [S.], seq 4051852710, ack 3645541714, length 0
      1783308214.622115 IP 10.89.0.2.34982 > 104.20.23.154.443: Flags [P.], seq 1:1563, ack 1, length 1562
      1783308214.631009 IP 104.20.23.154.443 > 10.89.0.2.34982: Flags [P.], seq 1:2897, ack 1563, length 2896
      20 packets captured
      31 packets received by filter
      0 packets dropped by kernel
    `, "osint-pcap-test");

    assert.equal(summary.backend, "podman");
    assert.equal(summary.namespace, "osint-pcap-test");
    assert.deepEqual(summary.dnsQueries, ["example.com"]);
    assert.equal(summary.tcp.remoteIp, "104.20.23.154");
    assert.equal(summary.tcp.remotePort, 443);
    assert.equal(summary.tcp.synToSynAckMs, 6);
    assert.equal(summary.payloadBytes.outbound, 1562);
    assert.equal(summary.payloadBytes.inbound, 2896);
    assert.equal(summary.packetsCaptured, 20);
    assert.equal(summary.packetsDroppedByKernel, 0);
  });

  it("runs light pipeline recon as extraction only", async () => {
    const result = await pipelineReconForTool({
      effort: "light",
      text: "Visit https://example.com and contact admin@example.com from 203.0.113.42.",
    });

    assert.deepEqual(result.stages, ["extract_indicators"]);
    assert.deepEqual(result.indicators.urls, ["https://example.com"]);
    assert.deepEqual(result.indicators.emails, ["admin@example.com"]);
    assert.deepEqual(result.results, {});
  });

  it("accepts target as a pipeline input alias", async () => {
    const result = await pipelineReconForTool({
      effort: "light",
      target: "https://example.com alias@example.com",
    });

    assert.equal(result.ok, true);
    assert.deepEqual(result.indicators.urls, ["https://example.com"]);
    assert.deepEqual(result.indicators.emails, ["alias@example.com"]);
  });

  it("returns a structured pipeline error when no input is supplied", async () => {
    const result = await pipelineReconForTool({
      effort: "light",
    });

    assert.equal(result.ok, false);
    assert.equal(result.source, "osint-pipeline");
    assert.match(result.error, /Expected text or target/);
  });

  it("runs medium pipeline recon without high-effort lookups", async () => {
    const result = await pipelineReconForTool({
      effort: "medium",
      maxLookups: 1,
      text: "Visit file:///etc/passwd then https://localhost/path.",
    });

    assert.deepEqual(result.stages, ["extract_indicators", "url_snapshot", "domain_network_intel"]);
    assert.equal(result.results.urlSnapshots.length, 1);
    assert.equal(result.results.domainNetwork.length, 1);
    assert.equal("crtshDomains" in result.results, false);
    assert.equal("hibpEmails" in result.results, false);
  });

  it("runs high pipeline infra reputation on domain-discovered IPs", async () => {
    const dir = mkdtempSync(join(tmpdir(), "openclaw-osint-pipeline-"));
    const cache = new OsintCache(join(dir, "osint.sqlite"));
    try {
      cache.putSource({
        source: "shodan-internetdb",
        target: "93.184.216.34",
        fetchedAt: Date.now(),
        expiresAt: Date.now() + 60_000,
        rawJson: JSON.stringify({
          ok: true,
          source: "shodan-internetdb",
          ip: "93.184.216.34",
          found: true,
          ports: [80, 443],
          hostnames: ["edge.example.net"],
          cpes: [],
          tags: [],
          vulnerabilities: [],
          summary: { openPortCount: 2, vulnerabilityCount: 0, hostnameCount: 1 },
        }),
        rawBytes: 2,
        status: "ok",
      });
      cache.putSource({
        source: "bgp-tools-whois",
        target: "93.184.216.34",
        fetchedAt: Date.now(),
        expiresAt: Date.now() + 60_000,
        rawJson: JSON.stringify({
          asn: "15133",
          ip: "93.184.216.34",
          prefix: "93.184.216.0/24",
          countryCode: "US",
          registry: "ARIN",
          allocated: "0001-01-01",
          asName: "EDGECAST",
        }),
        rawBytes: 2,
        status: "ok",
      });
      for (const business of ["Cloudflare, Inc.", "EDGECAST"]) {
        cache.putSource({
          source: "business-reputation",
          target: `${business}|example.com`,
          fetchedAt: Date.now(),
          expiresAt: Date.now() + 60_000,
          rawJson: JSON.stringify({
            ok: true,
            source: "business-reputation",
            business,
            domain: "example.com",
            ftcReleaseNotices: { ok: true, source: "ftc-release-notices", results: [] },
            bbbSearch: { ok: true, source: "bbb-business-search", profileLeads: [] },
            searchLeads: [],
            sourceStatuses: [],
            caveat: "cached test result",
          }),
          rawBytes: 2,
          status: "ok",
        });
      }
      const result = await pipelineReconForTool({
        effort: "high",
        maxLookups: 1,
        text: "93.184.216.34 https://example.com contact abuse@mail.example.net",
        cache,
        skipHighExpansion: true,
      });

      assert.equal(result.results.domainNetwork[0].ok, true);
      assert.equal(result.results.domainAuthority.length, 1);
      assert.equal(result.stages.includes("crtsh_domain"), false);
      assert.equal("crtshDomains" in result.results, false);
      assert.equal(result.results.deferredSources[0].tool, "osint_crtsh_domain");
      assert.equal(result.results.infraReputation.length, 1);
      assert.equal(result.results.infraReputation[0].ip, "93.184.216.34");
      assert.equal(result.results.shodanHost.length, 1);
      assert.deepEqual(result.results.shodanHost[0].ports, [80, 443]);
      assert.equal(result.results.cdnDdosProtection.length, 1);
      assert.equal(result.results.fingerprintCves.ok, true);
      assert.equal(typeof result.results.fingerprintCves.summary.fingerprintsChecked, "number");
      assert.equal(result.results.businessReputationSummary.length, 1);
      assert.equal(Array.isArray(result.keyFindings.businessCoverage), true);
      assert.equal(result.keyFindings.execution.phoneReputationRan, false);
      assert.equal(result.keyFindings.execution.outputTruncationMarkerPresent, false);
      assert.equal(result.results.businessReputation.length, 1);
      assert.equal(["Cloudflare, Inc.", "EDGECAST"].includes(result.results.businessReputation[0].business), true);
      assert.equal("bbbSearch" in result.results.businessReputation[0], false);
      assert.deepEqual(result.results.phoneReputation, []);
      assert.equal(result.results.derivedIndicators.hosts.includes("example.com"), true);
      assert.equal(result.results.derivedIndicators.hosts.includes("mail.example.net"), true);
      assert.equal(result.results.derivedIndicators.hosts.includes("edge.example.net"), true);
      assert.equal(JSON.stringify(result).match(/derivedIndicators/g)?.length, 1);
    } finally {
      cache.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("compacts high pipeline output before returning oversized tool results", async () => {
    const result = pipelineTesting.fitPipelineOutputBudget({
      ok: true,
      effort: "high",
      limits: { maxLookups: 4 },
      results: {
        urlSnapshots: [{
          ok: true,
          url: "https://example.com",
          finalUrl: "https://example.com/",
          status: 200,
          excerpt: "noisy page ".repeat(4000),
        }],
        tlsCertificates: [{
          ok: true,
          host: "example.com",
          chain: [{
            subject: "CN=example.com",
            issuer: "CN=Example CA",
            subjectAltNames: Array.from({ length: 200 }, (_value, index) => `alt-${index}.example.com`),
          }],
        }],
      },
    });
    const serialized = JSON.stringify(result);

    assert.equal(result.limits.outputCompacted, true);
    assert.equal(["compacted", "summary_only"].includes(result.limits.outputMode), true);
    assert.equal(result.limits.outputTruncationMarkerPresent, false);
    assert.equal(serialized.includes("noisy page noisy page"), false);
    assert.equal(serialized.length < result.limits.originalChars, true);
    assert.equal(pipelineTesting.measurePipelineOutputChars(result) <= result.limits.outputTargetChars, true);
    assert.doesNotThrow(() => JSON.parse(serialized));
  });

  it("derives bounded reputation indicators from RDAP contacts", () => {
    const indicators = domainAuthorityTesting.deriveIndicatorsFromRdap({
      entities: [
        {
          vcardArray: [
            "vcard",
            [
              ["email", {}, "text", "abuse@example.com"],
              ["tel", {}, "uri", "tel:+1.202.555.0100"],
            ],
          ],
        },
      ],
      remarks: [{ description: ["secondary noc@example.com +1 202 555 0101"] }],
    }, 1);

    assert.deepEqual(indicators.emails, ["abuse@example.com"]);
    assert.deepEqual(indicators.phones, ["+1.202.555.0100"]);
    assert.equal(domainAuthorityTesting.inferRegisteredDomain("www.example.com"), "example.com");
    assert.deepEqual(domainAuthorityTesting.domainCandidates("deep.service.example.co.uk"), [
      "deep.service.example.co.uk",
      "service.example.co.uk",
      "example.co.uk",
      "co.uk",
    ]);
  });

  it("normalizes business reputation lookup rows and BBB profile leads", () => {
    assert.equal(businessTesting.normalizeBusinessName(" Example Corp  Inc. "), "Example Corp Inc.");
    assert.equal(businessTesting.normalizeBusinessName("https://example.com"), undefined);
    assert.equal(businessTesting.canonicalBusinessName("Example Holdings, Inc."), "example");
    const ftcRows = businessTesting.normalizeFtcReleaseNoticeRows({
      data: [
        {
          attributes: {
            title: "FTC Action Against Example Corp",
            created: "2026-01-02T00:00:00+00:00",
            path: { alias: "/news-events/news/press-releases/example" },
          },
        },
      ],
    }, 5);
    assert.deepEqual(ftcRows, [{
      title: "FTC Action Against Example Corp",
      date: "2026-01-02T00:00:00+00:00",
      url: "https://www.ftc.gov/news-events/news/press-releases/example",
    }]);
    const ftcUrl = new URL(businessTesting.ftcReleaseNoticeApiUrl("Example Corp", 5));
    assert.equal(ftcUrl.searchParams.has("api_key"), false);
    assert.equal(ftcUrl.searchParams.get("filter[title][condition][value]"), "Example Corp");
    const bbbLinks = businessTesting.parseBbbProfileLinks(`
      <a href="/us/ca/example/profile/internet/example-corp-123">one</a>
      <a href="https://www.bbb.org/us/ca/example/profile/internet/example-corp-123">dup</a>
    `, 5);
    assert.deepEqual(bbbLinks, [{ url: "https://www.bbb.org/us/ca/example/profile/internet/example-corp-123" }]);
    assert.equal(
      businessTesting.buildProfessionalProfileLeads("Example Corp", "example.com")[0].source,
      "linkedin-company-public-search",
    );
    assert.equal(
      businessTesting.buildWorkplaceReviewLeads("Example Corp", "example.com")[0].source,
      "glassdoor-company-search",
    );
    assert.deepEqual(businessTesting.buildRelatedBusinessTargets("Yahoo Holdings Inc.", "www.yahoo.com"), [
      { business: "Yahoo Holdings Inc.", basis: "input" },
      { business: "Yahoo", basis: "legal_designator_stripped" },
      { business: "Yahoo Inc.", basis: "legal_variant" },
    ]);
    assert.deepEqual(businessTesting.summarizeBbbCoverage(
      "Yahoo Holdings Inc.",
      { ok: true, profileLeads: [] },
      [
        {
          business: "Yahoo",
          basis: "legal_designator_stripped",
          bbbSearch: { ok: true, profileLeads: [{ url: "https://www.bbb.org/us/example/yahoo" }] },
        },
      ],
    ), {
      exactBusiness: "Yahoo Holdings Inc.",
      exactProfileCount: 0,
      relatedProfileCount: 1,
      hasExactProfile: false,
      hasRelatedProfiles: true,
      exactProfiles: [],
      relatedProfiles: [{
        business: "Yahoo",
        basis: "legal_designator_stripped",
        url: "https://www.bbb.org/us/example/yahoo",
      }],
      summary:
        "BBB returned no exact profile lead for Yahoo Holdings Inc., but did return 1 related profile lead(s) for related business names.",
    });
    assert.equal(businessTesting.domainBusinessName("service.example.co.uk"), "Example");
    assert.equal(
      new URL(businessTesting.wikidataSearchUrl("Yahoo Inc.")).searchParams.get("action"),
      "wbsearchentities",
    );
    assert.deepEqual(businessTesting.wikidataRelatedIdsFromEntity({
      entities: {
        Q1: {
          claims: {
            P355: [{ mainsnak: { datavalue: { value: { id: "Q2" } } } }],
            P749: [{ mainsnak: { datavalue: { value: { id: "Q3" } } } }],
            P127: [{ mainsnak: { datavalue: { value: { id: "Q3" } } } }],
          },
        },
      },
    }), [
      { id: "Q2", relation: "subsidiary" },
      { id: "Q3", relation: "parent" },
    ]);
    assert.deepEqual(businessTesting.normalizeWikidataLabels({
      entities: {
        Q2: { labels: { en: { value: "Example Subsidiary" } } },
      },
    }), [{ id: "Q2", label: "Example Subsidiary" }]);
    const wikidataEntity = {
      entities: {
        Q1: {
          sitelinks: {
            enwiki: { title: "Example Corp" },
          },
        },
      },
    };
    assert.equal(businessTesting.wikipediaTitleFromWikidataEntity(wikidataEntity), "Example Corp");
    assert.equal(
      businessTesting.wikipediaSummaryUrl("Example Corp"),
      "https://en.wikipedia.org/api/rest_v1/page/summary/Example%20Corp?redirect=true",
    );
    assert.deepEqual(businessTesting.normalizeWikipediaSummary({
      title: "Example Corp",
      description: "public company",
      extract: "This is a long article summary. ".repeat(80),
      content_urls: { desktop: { page: "https://en.wikipedia.org/wiki/Example_Corp" } },
    }, "https://en.wikipedia.org/api/rest_v1/page/summary/Example_Corp"), {
      title: "Example Corp",
      description: "public company",
      extract: `${"This is a long article summary. ".repeat(80).replace(/\s+/g, " ").trim().slice(0, 700)}`,
      url: "https://en.wikipedia.org/wiki/Example_Corp",
      caveat: "Wikipedia summary is context only; verify reputation, ownership, filings, and complaints with primary sources.",
    });
  });

  it("extracts bounded public-knowledge facts from Wikidata shapes", () => {
    assert.deepEqual(publicKnowledgeTesting.publicKnowledgeQueriesForBusiness("Yahoo Holdings Inc."), [
      "Yahoo Holdings Inc.",
      "Yahoo",
      "Yahoo Inc.",
    ]);
    assert.deepEqual(publicKnowledgeTesting.publicKnowledgeQueriesForDomain("service.example.co.uk"), ["example"]);
    const facts = publicKnowledgeTesting.wikidataFactsFromEntity({
      entities: {
        Q1: {
          aliases: { en: [{ value: "Example Brand" }] },
          sitelinks: { enwiki: { title: "Example Corp" } },
          claims: {
            P856: [{ mainsnak: { datavalue: { value: "https://example.com" } } }],
            P249: [{ mainsnak: { datavalue: { value: "EXM" } } }],
            P355: [{ mainsnak: { datavalue: { value: { id: "Q2" } } } }],
          },
        },
      },
    });
    assert.deepEqual(facts.aliases, ["Example Brand"]);
    assert.deepEqual(facts.officialWebsites, ["https://example.com"]);
    assert.deepEqual(facts.tickerSymbols, ["EXM"]);
    assert.deepEqual(facts.relatedOrganizations, [{ id: "Q2", relation: "subsidiary" }]);
    assert.equal(facts.wikipediaTitle, "Example Corp");
  });

  it("normalizes SEC company tickers and filing disclosure links", () => {
    const companies = businessTesting.normalizeSecCompanyTickerRows({
      0: { cik_str: 1234, ticker: "EXM", title: "EXAMPLE HOLDINGS INC" },
    });
    assert.deepEqual(companies, [{ cik: "0000001234", ticker: "EXM", title: "EXAMPLE HOLDINGS INC" }]);
    const submissions = businessTesting.normalizeSecSubmissions({
      filings: {
        recent: {
          form: ["10-K", "8-K"],
          filingDate: ["2026-02-03", "2026-01-04"],
          accessionNumber: ["0000001234-26-000001", "0000001234-26-000002"],
          primaryDocument: ["exm-20260203.htm", "exm-20260104.htm"],
        },
      },
    }, companies[0], 1, "https://data.sec.gov/submissions/CIK0000001234.json");

    assert.equal(submissions.recentFilings.length, 1);
    assert.equal(submissions.recentFilings[0].form, "10-K");
    assert.equal(
      submissions.recentFilings[0].url,
      "https://www.sec.gov/Archives/edgar/data/1234/000000123426000001/exm-20260203.htm",
    );
    assert.equal(
      submissions.companyFactsUrl,
      "https://data.sec.gov/api/xbrl/companyfacts/CIK0000001234.json",
    );
  });

  it("normalizes market snapshots and SEC facts for computed financial metrics", () => {
    const quote = businessTesting.normalizeYahooChartSnapshot({
      chart: {
        result: [{
          meta: {
            symbol: "EXM",
            longName: "Example Holdings Inc.",
            fullExchangeName: "NasdaqGS",
            currency: "USD",
            regularMarketPrice: 42,
            chartPreviousClose: 40,
            regularMarketTime: 1_700_000_000,
            regularMarketDayHigh: 43,
            regularMarketDayLow: 39,
            fiftyTwoWeekHigh: 55,
            fiftyTwoWeekLow: 25,
            regularMarketVolume: 123456,
          },
        }],
      },
    }, "https://query1.finance.yahoo.com/v8/finance/chart/EXM");
    assert.deepEqual(quote, {
      ok: true,
      source: "yahoo-finance-chart",
      url: "https://query1.finance.yahoo.com/v8/finance/chart/EXM",
      symbol: "EXM",
      name: "Example Holdings Inc.",
      exchange: "NasdaqGS",
      currency: "USD",
      regularMarketPrice: 42,
      previousClose: 40,
      regularMarketChange: 2,
      regularMarketChangePercent: 5,
      regularMarketTime: "2023-11-14T22:13:20.000Z",
      dayHigh: 43,
      dayLow: 39,
      fiftyTwoWeekHigh: 55,
      fiftyTwoWeekLow: 25,
      regularMarketVolume: 123456,
    });

    const facts = businessTesting.normalizeSecCompanyFacts({
      facts: {
        "us-gaap": {
          EarningsPerShareDiluted: {
            units: {
              "USD/shares": [
                { val: 2, end: "2025-12-31", filed: "2026-02-01", form: "10-K", fy: 2025, fp: "FY" },
              ],
            },
          },
          EntityCommonStockSharesOutstanding: {
            units: {
              shares: [
                { val: 1000, end: "2026-02-01", filed: "2026-02-02", form: "10-K", fy: 2025, fp: "FY" },
              ],
            },
          },
          Revenues: {
            units: {
              USD: [
                { val: 8000, end: "2024-12-31", filed: "2025-02-01", form: "10-K", fy: 2024, fp: "FY" },
              ],
            },
          },
          RevenueFromContractWithCustomerExcludingAssessedTax: {
            units: {
              USD: [
                { val: 9000, end: "2025-12-31", filed: "2026-02-01", form: "10-K", fy: 2025, fp: "FY" },
              ],
            },
          },
          NetIncomeLoss: {
            units: {
              USD: [
                { val: 1200, end: "2025-12-31", filed: "2026-02-01", form: "10-K", fy: 2025, fp: "FY" },
              ],
            },
          },
        },
      },
    }, { cik: "0000001234", ticker: "EXM", title: "EXAMPLE HOLDINGS INC" }, 4, "https://data.sec.gov/api/xbrl/companyfacts/CIK0000001234.json");

    assert.equal(facts.latestFacts.epsDiluted.value, 2);
    assert.equal(facts.latestFacts.revenue.value, 9000);
    assert.deepEqual(businessTesting.computeMarketMetrics(quote, facts), {
      peRatioApprox: 21,
      marketCapApprox: 42000,
      basis: "P/E uses Yahoo chart regularMarketPrice divided by latest SEC diluted EPS fact. Market cap uses Yahoo chart regularMarketPrice multiplied by latest SEC shares outstanding fact.",
    });
    assert.equal(
      businessTesting.yahooChartUrl("EXM"),
      "https://query1.finance.yahoo.com/v8/finance/chart/EXM?range=1d&interval=1d",
    );
  });

  it("normalizes regional business register leads", () => {
    const ukRows = businessTesting.normalizeCompaniesHouseSearchRows({
      items: [{
        title: "EXAMPLE LIMITED",
        company_number: "01234567",
        company_status: "active",
        company_type: "ltd",
        date_of_creation: "2020-01-02",
      }],
    }, 5);
    assert.deepEqual(ukRows, [{
      title: "EXAMPLE LIMITED",
      companyNumber: "01234567",
      companyStatus: "active",
      companyType: "ltd",
      dateOfCreation: "2020-01-02",
      url: "https://find-and-update.company-information.service.gov.uk/company/01234567",
    }]);

    const auRows = businessTesting.normalizeAbnLookupRows({
      Names: [{
        Abn: "53 004 085 616",
        Name: "BHP GROUP LIMITED",
        State: "VIC",
        Postcode: "3000",
      }],
    }, 5);
    assert.deepEqual(auRows, [{
      abn: "53 004 085 616",
      name: "BHP GROUP LIMITED",
      stateCode: "VIC",
      postcode: "3000",
      url: "https://abr.business.gov.au/ABN/View/53004085616",
    }]);

    assert.equal(
      businessTesting.parseJsonOrJsonp('callback({"Names":[{"Abn":"1","Name":"Example"}]});').Names[0].Name,
      "Example",
    );
    assert.equal(
      businessTesting.buildEuBusinessRegisterLeads("Example GmbH").source,
      "eu-bris-business-registers",
    );
    assert.equal(
      businessTesting.normalizeRegistryId(" 2082 8393 "),
      "20828393",
    );
    assert.equal(
      businessTesting.taiwanGcisApiUrl("20828393", 1).includes("Business_Accounting_NO+eq+20828393"),
      true,
    );
    const taiwanRows = businessTesting.normalizeTaiwanGcisRows([{
      Business_Accounting_NO: "20828393",
      Company_Status_Desc: "核准設立",
      Company_Name: "宏碁股份有限公司",
      Capital_Stock_Amount: 40000000000,
      Paid_In_Capital_Amount: 30478538280,
      Company_Location: "臺北市松山區民福里復興北路369號7樓之5",
      Register_Organization_Desc: "商業發展署",
      Company_Setup_Date: "0680718",
      Change_Of_Approval_Data: "1150622",
      Responsible_Name: "not emitted",
    }], 5);
    assert.deepEqual(taiwanRows, [{
      unifiedBusinessNumber: "20828393",
      companyName: "宏碁股份有限公司",
      status: "核准設立",
      capitalStockAmount: 40000000000,
      paidInCapitalAmount: 30478538280,
      location: "臺北市松山區民福里復興北路369號7樓之5",
      registerOrganization: "商業發展署",
      setupDate: "0680718",
      changedAt: "1150622",
      url: "https://findbiz.nat.gov.tw/fts/query/QueryBar/queryInit.do?fhl=en&request_locale=en&qryCond=20828393",
    }]);
    assert.equal("responsibleName" in taiwanRows[0], false);
    assert.equal(
      businessTesting.buildJapanBusinessRegisterLeads("Sony").source,
      "jp-gbizinfo",
    );
    assert.equal(
      businessTesting.buildChinaBusinessRegisterLeads("Tencent").source,
      "cn-gsxt",
    );
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

  it("detects CDN and DDoS protection providers from mixed evidence", () => {
    const matches = cdnTesting.detectProviders({
      headers: {
        server: "cloudflare",
        "cf-ray": "abc123-IAD",
      },
      bgpNames: ["Cloudflare, Inc."],
      tlsIssuers: [],
      tlsSubjects: [],
      tlsAltNames: [],
      hostnames: [],
    });

    assert.equal(cdnTesting.normalizeTarget("example.com")?.domain, "example.com");
    assert.equal(matches[0].provider, "Cloudflare");
    assert.equal(matches[0].category, "cdn_or_ddos_protection");
    assert.equal(matches[0].confidence >= 0.8, true);
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

  it("matches IPv4 and IPv6 addresses to RDAP bootstrap ranges", () => {
    assert.equal(
      ipAssignmentTesting.rangeContainsIp(
        "69.0.0.0/8",
        ipAssignmentTesting.ipv4ToBigInt("69.147.92.11"),
        4,
      ),
      true,
    );
    assert.equal(
      ipAssignmentTesting.rangeContainsIp(
        "2001:400::/23",
        ipAssignmentTesting.ipv6ToBigInt("2001:400::1"),
        6,
      ),
      true,
    );
    assert.equal(ipAssignmentTesting.registryHintFromRdapUrl("https://rdap.arin.net/registry/ip/1.1.1.1"), "ARIN");
    assert.equal(ipAssignmentTesting.registryHintFromRdapUrl("https://rdap.apnic.net/ip/1.1.1.1"), "APNIC");
    assert.equal(ipAssignmentTesting.registryHintFromRdapUrl("https://rdap.db.ripe.net/ip/1.1.1.1"), "RIPE NCC");
    assert.equal(ipAssignmentTesting.registryHintFromRdapUrl("https://rdap.registro.br/ip/200.160.2.3"), "LACNIC/NIC.br");
  });

  it("guards TLS certificate lookup hosts and parses SANs", () => {
    assert.equal(tlsCertificateTesting.normalizePublicHost("https://www.example.com/path"), "www.example.com");
    assert.equal(tlsCertificateTesting.normalizePublicHost("localhost"), undefined);
    assert.equal(tlsCertificateTesting.normalizePublicHost("127.0.0.1"), undefined);
    assert.equal(tlsCertificateTesting.isBlockedIpv4("10.0.0.1"), true);
    assert.equal(tlsCertificateTesting.isBlockedIpv4("8.8.8.8"), false);
    assert.equal(tlsCertificateTesting.isBlockedIpv6("fc00::1"), true);
    assert.deepEqual(tlsCertificateTesting.parseSubjectAltNames("DNS:example.com, DNS:www.example.com"), [
      "DNS:example.com",
      "DNS:www.example.com",
    ]);
    assert.deepEqual(tlsCertificateTesting.parseAltNames([
      "DNS:*.example.com",
      "DNS:api.example.com",
      "IP Address:8.8.8.8",
      "IP Address:10.0.0.1",
    ]), {
      dnsNames: ["example.com", "api.example.com"],
      ipAddresses: ["8.8.8.8"],
    });
  });

  it("normalizes Shodan InternetDB host summaries without requiring an API key", () => {
    const result = shodanTesting.formatInternetDbResponse("8.8.8.8", {
      ports: [443, 53, 443],
      hostnames: ["dns.google", "dns.google"],
      cpes: ["cpe:/a:example"],
      tags: ["cdn"],
      vulns: { "CVE-2024-0001": {}, "CVE-2024-0002": {} },
    });

    assert.equal(shodanTesting.normalizePublicIp("8.8.8.8"), "8.8.8.8");
    assert.equal(shodanTesting.normalizePublicIp("10.0.0.1"), undefined);
    assert.equal(shodanTesting.normalizePublicIp("2001:4860:4860::8888"), "2001:4860:4860::8888");
    assert.deepEqual(result.ports, [53, 443]);
    assert.deepEqual(result.vulnerabilities, ["CVE-2024-0001", "CVE-2024-0002"]);
    assert.equal(result.summary.openPortCount, 2);
  });

  it("normalizes keyed Shodan host summaries without raw banners", () => {
    const result = shodanTesting.formatShodanHostResponse("8.8.8.8", {
      ip_str: "8.8.8.8",
      ports: [443],
      hostnames: ["dns.google"],
      domains: ["google"],
      org: "Google LLC",
      asn: "AS15169",
      vulns: ["CVE-2024-0001"],
      data: [
        {
          port: 443,
          transport: "tcp",
          product: "Google Frontend",
          version: "1.0",
          data: "raw banner should not be copied",
          http: { title: "Google DNS", server: "gws" },
        },
      ],
    }, true);

    assert.equal(result.source, "shodan-host");
    assert.equal(result.provider, "shodan");
    assert.equal(result.mode, "keyed_full");
    assert.deepEqual(result.ports, [443]);
    assert.deepEqual(result.vulnerabilities, ["CVE-2024-0001"]);
    assert.equal(result.services[0].product, "Google Frontend");
    assert.equal("data" in result.services[0], false);
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

    const assignment = {
      ok: true,
      ip: "104.20.23.154",
      registryHint: "ARIN",
      summary: { handle: "NET-104-20-0-0-1" },
      derivedIndicators: { emails: ["abuse@example.net"], phones: [] },
    };
    assert.deepEqual(domainNetworkTesting.summarizeNetworkIntel(dns, bgp, true, [assignment]), {
      resolvedIpCount: 1,
      dnsFamilies: [4],
      bgpResolvedCount: 1,
      bgpErrorCount: 0,
      ipAssignmentResolvedCount: 1,
      ipAssignmentErrorCount: 0,
      asnCount: 1,
      primaryAsns: ["AS13335 Cloudflare, Inc."],
      registries: ["ARIN"],
      networkShape: "cdn_or_anycast_likely",
      tracerouteAvailable: "operator_plan_only",
    });
    assert.deepEqual(domainNetworkTesting.correlateNetworkPaths(dns, bgp, trace, [assignment]), [
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
        ipAssignment: {
          ok: true,
          registryHint: "ARIN",
          rdapUrl: undefined,
          summary: { handle: "NET-104-20-0-0-1" },
          derivedIndicators: { emails: ["abuse@example.net"], phones: [] },
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
      assert.deepEqual(result.numberingPlan.nanp, {
        npa: "202",
        nxx: "555",
        npaNxx: "202555",
        lineNumber: "0123",
      });
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
        result.sourceLeads.some(
          (lead) => lead.source === "didww-api-nanpa-prefix" && lead.category === "did_inventory",
        ),
        true,
      );
      assert.equal(
        result.sourceLeads.some(
          (lead) => lead.source === "ovh-telephony-api" && lead.automation === "authenticated_api",
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
    assert.equal(leads.some((lead) => lead.source === "countrycode.org"), true);
    assert.equal(leads.some((lead) => lead.source === "didww-area-prefix-directory"), true);
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

  it("scores VoIP path mismatch without identifying subscribers", () => {
    const risk = reputationTesting.scoreVoipPathRisk({
      assignmentCountry: "US",
      observedCountries: ["IN", "US"],
      stirShakenAttestation: "C",
      hasObservedPath: true,
    });

    assert.equal(risk.level, "high");
    assert.deepEqual(risk.observedForeignCountries, ["IN"]);
    assert.equal(risk.reasons.some((reason) => reason.includes("Weak")), true);
  });

  it("accepts missing VoIP path evidence as low confidence", async () => {
    const result = await reputationTesting.assessVoipPathForTool({
      phone: "+1 (202) 555-0123",
      stirShakenAttestation: "unknown",
    });

    assert.equal(result.ok, true);
    assert.equal(result.mismatchRisk.level, "low");
    assert.equal(result.assignment.numberingPlan.nanp.npaNxx, "202555");
    assert.equal(result.blockedClaims.includes("subscriber_identity"), true);
  });
});
