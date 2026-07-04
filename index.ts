import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";
import {
  CrtshDomainSchema,
  OsintCacheStatusSchema,
  osintCacheStatusForTool,
  queryCrtshDomainForTool,
} from "./src/crtsh.js";
import {
  HibpEmailBreachSchema,
  HibpLatestBreachSchema,
  PwnedPasswordHashSchema,
  queryHibpEmailBreachForTool,
  queryHibpLatestBreachForTool,
  queryPwnedPasswordHashForTool,
} from "./src/hibp.js";
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
  ],
});
