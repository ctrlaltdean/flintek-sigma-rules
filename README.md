# FLINTEK Sigma Rules

Sigma detection rules for current threat intel and incidents, maintained alongside FLINTEK DFIR/CTI work.

Sigma is a vendor-agnostic rule format for log-based SIEM detections: write once in YAML, convert with [pySigma](https://github.com/SigmaHQ/pySigma) / `sigma-cli` to Splunk SPL, Elastic ES|QL, Microsoft Sentinel KQL, QRadar AQL, and others.

```bash
pip install sigma-cli
sigma convert -t splunk -p sentinel_asim rules/optimjack/dns.yml
```

Rules are organized one subfolder per incident: `rules/<campaign-name>/<surface>.yml`.

## About this repo

Rules here are mostly researched and drafted by AI (open-source threat reporting review + Sigma authoring), then published for the community. They are a starting point, not a finished detection.

**Audit before you deploy.** Validate logsource field names against your own schema, confirm IOCs are still live/relevant (domains and IPs in takedown-prone campaigns go stale fast), and test for false positives in your environment before enabling in production. Treat every rule as `status: experimental` until you've reviewed it yourself.

## Incidents covered

### OPTIMJACK — Optimizely Web Experimentation supply chain compromise (Nov 16-17, 2026)

Attacker gained write access to customer "Project JavaScript" fields on Optimizely Web Experimentation, serving a crypto clipper / card skimmer / cookie-screenshot stealer / iOS exploit loader to visitors of 178 organizations (BBC, CNN, Zoom, Salesforce, GitLab, HSBC, IKEA, etc.) via Optimizely's own trusted CDN.

- `rules/optimjack/dns.yml` - DNS queries to C2/exfil domains
- `rules/optimjack/proxy.yml` - HTTP(S) requests to malicious hosts/paths
- `rules/optimjack/network.yml` - Outbound connections to C2 IPs
- `rules/optimjack/filehash.yml` - Known payload file hashes

**Sources:** [Report URI](https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/), [StepSecurity](https://www.stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer), [Cynet](https://www.cynet.com/blog/optimjack-malicious-web-injection-across-cnn-zoom-salesforce-fox-and-more/)

**Caveat:** `cdn.optimizely.com` is the legitimate delivery path, not an IOC - do not blocklist it. `q1ls1ho9x7wsxlu.icu` and `ios-hack.icu` were registered minutes-to-hours after public IOC lists dropped and are Cloudflare-fronted; validate before hard-blocking.

### ConnectWise supply chain compromises (Oct 2026, two distinct incidents)

**A: SkyKick/Cloud Backup OAuth credential abuse** — a compromised M365 API secret belonging to ConnectWise Cloud Backup (SkyKick) was used to access customer M365 environments; Microsoft attributes it to Storm-0940 using the ARTEX AI agent framework. **B: ScreenConnect breach** — separate incident, ~50 orgs, ConnectWise's own Trust Center published reported C2 domains and operator names.

- `rules/connectwise-skykick-artex/network.yml` - confirmed + lower-confidence C2 IPs (split by confidence)
- `rules/connectwise-skykick-artex/application.yml` - scripted-tooling user agents + compromised app IDs
- `rules/connectwise-screenconnect-breach/dns_and_accounts.yml` - C2 domains + suspicious operator account names

**Sources:** [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise), [Huntress](https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access), [ConnectWise Trust Center](https://www.connectwise.com/company/trust/advisories)

**Caveat:** the unrelated "M365 Token-Replay, 97 accounts/79 orgs" story (Romanian AitM infra) is NOT part of this ConnectWise incident set — explicitly excluded after verification.

### LiteLLM / BerriAI supply chain compromise (two distinct incidents, Mar + Oct 2026)

March 2026: `litellm==1.82.7/1.82.8`, reportedly via a backdoored Trivy CI dependency (TeamPCP). October 2026: `litellm==1.107.0`, stolen GitHub CLI OAuth tokens via a leaked internal admin key, unattributed.

- `rules/litellm-teampcp-mar2026/{dns,network_connection,file_event}.yml`
- `rules/litellm-cookbackdoor-oct2026/{dns,proxy,file_event,process_creation}.yml`

**Sources:** LiteLLM/BerriAI advisory, Microsoft, Chainguard, OpenSourceMalware.

**Caveat:** March-incident file hashes are reported-but-unconfirmed (no primary source publishes them, secondary blogs conflict) — excluded from the rules rather than guessed at.

### Malicious "Claude Code" extension on Cursor / Fireworks AI breach (Oct-Nov 2026)

An access key Cursor issued to Fireworks AI was exposed in Fireworks' own breach; attackers pivoted into Cursor's internal systems and planted a trojanized "Claude Code" extension with a persistent SSH backdoor. Notion's exposure traces to the same Fireworks compromise via a separate path (Notion was a Fireworks customer).

- `rules/claude-code-cursor-ssh-backdoor/{network_connection,proxy,process_creation,file_event}.yml`

**Sources:** Cursor's own post-mortem, Microsoft, Expel, noma.security.

**Caveat:** claims the Fireworks breach also hit Uber appear only in aggregator pieces, not primary sources — marked unconfirmed.

### cPGuard / OpsShield autoupdate-channel hijack (Nov 1-2, 2026)

Attacker took over OpsShield's billing/licensing server via a fake trial account, stole the update-publishing key, pushed a malicious script in cPGuard 5.88.12-5.88.19 for ~70 minutes to ~2,950 customer servers as root.

- `rules/cpguard/{filehash,persistence,network,proxy}.yml`

**Sources:** OpsShield's own advisories, SecurityWeek, BleepingComputer, The Hacker News.

**Caveat:** exfil went to OpsShield's own hijacked licensing server, not attacker-registered C2 — the network.yml IP rule is heavily caveated (recon-only against OpsShield's portal, not confirmed customer-side C2).

### PHP2Shell — Check Point gateway + multi-vendor firewall campaigns (Nov 2026, two campaigns, one vuln class)

Campaign 1: Check Point gateways → TSGA/TSProxy backdoor → ESXi wiper (CVE-2026-109618/109619 + CVE-2026-123039 LPE). Campaign 2: Dream Security's "25 servers / US govt" report, same CVE pair chained with Fragnesia (CVE-2026-46300).

- `rules/php2shell/{network_connection,file_event,process_creation,webserver}.yml`

**Sources:** Check Point Research, The Hacker News, BleepingComputer, SecurityWeek.

**Caveat:** Campaign 1's IPs are single-source (Check Point only); Campaign 2 has no published IOCs at all (no rules written for it, documented in the vault note instead). Attribution to Armory Castle/UNC5221 is unconfirmed by the researchers themselves.

### DARKVIGIL / SlippyNunchucks — Sogou Input Method DNS hijack (Nov 2026)

China-aligned SlippyNunchucks hijacked DNS for Sogou Input Method's cleartext config-fetch to deliver the DarkVigil/FDMTP backdoor via a side-loaded DLL. CVE-2026-120422, patched in Sogou 16.10.

- `rules/darkvigil-sogou/{dns,network,filehash,proxy}.yml`

**Sources:** ESET Research/WeLiveSecurity (primary).

**Caveat:** `config.pinyin.sogou.com` is Sogou's own legitimate infrastructure, not an indicator.

### Qubole trusted-AWS-access supply chain attack (Oct-Nov 2026)

Attackers abused Qubole's trusted AWS access relationship to breach 12+ customer AWS environments via a compromised Qubole AWS account, malicious IAM principals, and TruffleHog-based credential validation.

- `rules/qubole-trusted-access/*.yml` (5 rules, AWS CloudTrail logsource)

**Sources:** Wiz CIRT (primary, with Sentra/Mandiant), CSO Online, The Register, SecurityWeek.

**Caveat:** a speculative `sso_agent.iso`/TCP 23458 indicator was explicitly NOT published — Wiz couldn't confirm it was ever deployed against a victim.

### AOMEI Backupper update-server compromise — UNC7017 (Apr-Jul 2026)

UNC7017 tampered with AOMEI Backupper's update server configs in three 5-10 min bursts to deliver CROSSROAD downloader → SHINYROAD backdoor, plus later ADAPTAGENT/Adaptix C2.

- `rules/aomei-backupper-unc7017/{network,dns,proxy,filehash,process_creation}.yml`

**Sources:** AOMEI's own statement, Google Cloud/GTIG (primary), ManageEngine METAL.

**Caveat:** network IOCs are confirmed (primary source + independent OTX cross-check); file hashes are reported-but-not-independently-verified except one cross-checked against Google's own YARA reference.

### GhostAction — GitHub Actions supply chain campaign (2025-2026)

Attackers planted malicious GitHub Actions workflows across compromised accounts/repos to exfiltrate secrets.

- `rules/ghostaction/{network,dns,proxy,process_creation,filehash,github_push_core,github_push_generic}.yml`

**Sources:** GitGuardian, StepSecurity, Socket, OpenSourceMalware, The Hacker News.

**Caveat:** the "Meta GitHub breach" story (SecurityWeek) is an unrelated, separate incident (stolen employee credential, no workflow-planting) — explicitly not conflated here. `github_push_generic.yml` is correlation-only (level: low) since its filenames are too common to alert on alone.

### npm supply chain, Oct 2026 — Shai-Hulud worm (SlugFest explicitly excluded)

Research disambiguated three storylines bucketed under one headline: a Ledger hardware implant (~$93M theft, no IOCs published, no rules written), "SlugFest" (an npm Trusted Publishing validation flaw, patched, never actively exploited, no rules written), and the real ongoing **Shai-Hulud npm worm** (3 waves: redhat-cloud-services, keyv/cacheable "ChainDrop," tensorlake) with genuine cross-corroborated IOCs.

- `rules/npm-shai-hulud-worm-2026/{dns,network,process_creation,filehash}.yml`

**Sources:** multiple independent sources per wave, see vault notes.

**Caveat:** Ledger implant and SlugFest intentionally have NO rules — nothing malicious/hunt-able exists for either; forcing rules would be fabrication.

### Rank Math PRO WordPress plugin supply chain compromise (Oct 2026)

Rank Math PRO v3.0.123 was compromised (CVE-2026-111862, CVSS 9.8), serving malicious packages via rankmath.com for ~11 hours, C2 to rank1cdn.com.

- `rules/rank-math-pro/{dns,file_event,wordpress_application}.yml`

**Sources:** Rank Math's own KB notice, Wordfence (both primary).

**Caveat:** no hashes/IPs were ever published for this campaign — network/file surfaces only. `wordpress_application.yml` uses non-standard field names that need mapping to your actual WP logging setup.

## License

Apache 2.0
