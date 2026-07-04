import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";
import {
  CrtshDomainSchema,
  OsintCacheStatusSchema,
  osintCacheStatusForTool,
  queryCrtshDomainForTool,
} from "./src/crtsh.js";
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
  ],
});
