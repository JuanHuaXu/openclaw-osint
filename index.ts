import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";
import {
  CrtshDomainSchema,
  OsintCacheStatusSchema,
  osintCacheStatusForTool,
  queryCrtshDomainForTool,
} from "./src/crtsh.js";
import {
  DomainNetworkIntelSchema,
  queryDomainNetworkIntelForTool,
} from "./src/domain-network.js";
import {
  DomainAuthorityIntelSchema,
  queryDomainAuthorityIntelForTool,
} from "./src/domain-authority.js";
import {
  HibpEmailBreachSchema,
  HibpLatestBreachSchema,
  PwnedPasswordHashSchema,
  queryHibpEmailBreachForTool,
  queryHibpLatestBreachForTool,
  queryPwnedPasswordHashForTool,
} from "./src/hibp.js";
import {
  BotIdentityAssessSchema,
  InfraReputationSchema,
  PhoneReputationSchema,
  VoipPathAssessSchema,
  assessBotIdentityForTool,
  assessVoipPathForTool,
  queryInfraReputationForTool,
  queryPhoneReputationForTool,
} from "./src/reputation.js";
import {
  PipelineReconSchema,
  pipelineReconForTool,
} from "./src/pipeline.js";
import {
  ExtractIndicatorsSchema,
  UrlSnapshotSchema,
  extractIndicatorsForTool,
  snapshotUrlForTool,
} from "./src/tools.js";

export default defineToolPlugin({
  id: "osint",
  name: "OSINT",
  description: "Public-source OSINT helper tools with guarded fetching and indicator extraction.",
  tools: (tool) => [
    tool({
      name: "osint_extract_indicators",
      label: "OSINT Indicator Extractor",
      description:
        "Extract URLs, domains, IPs, emails, handles, and hashes from supplied text without network access.",
      parameters: ExtractIndicatorsSchema,
      execute: extractIndicatorsForTool,
    }),
    tool({
      name: "osint_url_snapshot",
      label: "OSINT URL Snapshot",
      description:
        "Fetch a public HTTP(S) URL through OpenClaw's SSRF guard and return bounded page metadata plus an untrusted excerpt.",
      parameters: UrlSnapshotSchema,
      execute: (params, _config, context) =>
        snapshotUrlForTool({ ...params, signal: context.signal }),
    }),
    tool({
      name: "osint_crtsh_domain",
      label: "OSINT crt.sh Domain Lookup",
      description:
        "Query cached crt.sh certificate transparency data for subdomains of a public domain.",
      parameters: CrtshDomainSchema,
      execute: (params, _config, context) =>
        queryCrtshDomainForTool({ ...params, signal: context.signal }),
    }),
    tool({
      name: "osint_domain_network_intel",
      label: "OSINT Domain Network Intel",
      description:
        "Resolve a domain and enrich its IPs with bgp.tools WHOIS BGP ownership data. Includes an operator-side traceroute plan when requested, but does not run traceroute.",
      parameters: DomainNetworkIntelSchema,
      execute: queryDomainNetworkIntelForTool,
    }),
    tool({
      name: "osint_domain_authority_intel",
      label: "OSINT Domain Authority Intel",
      description:
        "Inspect a domain's authority DNS records and RDAP registration summary, then return bounded RDAP-derived contact indicators for reputation correlation.",
      parameters: DomainAuthorityIntelSchema,
      execute: (params, _config, context) =>
        queryDomainAuthorityIntelForTool({ ...params, signal: context.signal }),
    }),
    tool({
      name: "osint_cache_status",
      label: "OSINT Cache Status",
      description:
        "Show bounded local OSINT cache counts and byte totals without exposing cached raw data.",
      parameters: OsintCacheStatusSchema,
      execute: osintCacheStatusForTool,
    }),
    tool({
      name: "osint_hibp_email_breach",
      label: "OSINT HIBP Email Breach",
      description:
        "Check an email address against Have I Been Pwned when HIBP_API_KEY is configured. Does not store raw email addresses in the local cache.",
      parameters: HibpEmailBreachSchema,
      execute: (params, _config, context) =>
        queryHibpEmailBreachForTool({ ...params, signal: context.signal }),
    }),
    tool({
      name: "osint_hibp_latest_breach",
      label: "OSINT HIBP Latest Breach",
      description:
        "Fetch the latest Have I Been Pwned breach metadata as a cheap preflight before account checks.",
      parameters: HibpLatestBreachSchema,
      execute: (params, _config, context) =>
        queryHibpLatestBreachForTool({ ...params, signal: context.signal }),
    }),
    tool({
      name: "osint_pwned_password_hash",
      label: "OSINT Pwned Password Hash",
      description:
        "Check a SHA-1 or NTLM password hash with the Have I Been Pwned k-anonymity range API. Never pass plaintext passwords.",
      parameters: PwnedPasswordHashSchema,
      execute: (params, _config, context) =>
        queryPwnedPasswordHashForTool({ ...params, signal: context.signal }),
    }),
    tool({
      name: "osint_phone_reputation",
      label: "OSINT Phone Reputation",
      description:
        "Normalize a US phone number and add bounded FTC unwanted-call complaint evidence when FTC_API_KEY is configured. Does not identify private owners.",
      parameters: PhoneReputationSchema,
      execute: (params, _config, context) =>
        queryPhoneReputationForTool({ ...params, signal: context.signal }),
    }),
    tool({
      name: "osint_infra_reputation",
      label: "OSINT Infrastructure Reputation",
      description:
        "Check an IPv4 address against cached Spamhaus DROP and optional AbuseIPDB reputation. Requires ABUSEIPDB_API_KEY for AbuseIPDB.",
      parameters: InfraReputationSchema,
      execute: (params, _config, context) =>
        queryInfraReputationForTool({ ...params, signal: context.signal }),
    }),
    tool({
      name: "osint_bot_identity_assess",
      label: "OSINT Bot Identity Assessment",
      description:
        "Classify bot/service likelihood from explicit evidence without resolving private human identity.",
      parameters: BotIdentityAssessSchema,
      execute: assessBotIdentityForTool,
    }),
    tool({
      name: "osint_voip_path_assess",
      label: "OSINT VoIP Path Assessment",
      description:
        "Assess mismatch risk between a US phone number assignment, observed SIP/RTP IP paths, DNS/BGP network ownership, and STIR/SHAKEN attestation. Does not identify private owners.",
      parameters: VoipPathAssessSchema,
      execute: assessVoipPathForTool,
    }),
    tool({
      name: "osint_pipeline_recon",
      label: "OSINT Pipeline Recon",
      description:
        "Run bounded OSINT recon by effort level: light extracts indicators, medium enriches URLs/domains, high runs the broader safe lookup suite.",
      parameters: PipelineReconSchema,
      execute: (params, _config, context) =>
        pipelineReconForTool({ ...params, signal: context.signal }),
    }),
  ],
});
