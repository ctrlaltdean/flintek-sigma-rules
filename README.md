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

### Cairn - MONAI Label university intrusions (Nov 20, 2026 disclosure)

- `rules/cairn-monai-label/network_connection.yml` - exact match on two historical IPs, either endpoint

**Sources:** [Amazon Threat Intelligence](https://aws.amazon.com/blogs/security/chinese-nexus-actors-cairn-ai-agents-found-a-zero-day-on-their-own/), [MONAI Label advisory](https://github.com/Project-MONAI/MONAILabel/security/advisories/GHSA-qc22-rmgc-vg94).

**Caveat:** IP associations are single-source AWS records dated September 8-10, 2026; individual roles and traffic direction are unspecified. The MONAI advisory corroborates the flaw, not the IPs. No current liveness or maliciousness verified. Historical hunting leads only, not automatic blocklist entries. Gambit's separate retail campaign is excluded.

### ARMORY CASTLE - vCenter CVE-2026-123890 campaign (Nov 2026)

- `rules/armory-castle-vcenter/network_connection.yml` - 11 suspected obfuscation-network IPs, either endpoint
- `rules/armory-castle-vcenter/file_event.yml` - LAZYBONES path and BONESAW signer-extraction artifacts
- `rules/armory-castle-vcenter/process_creation.yml` - observed BEARBONES temporary SSH listener execution

**Sources:** [GTIG/Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere), [Broadcom advisory](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/39495).

**Caveat:** all campaign IOCs are single-source GTIG observations. Broadcom confirms the vulnerability, not the indicators. IPs may be compromised third-party infrastructure, not attacker-owned C2. Historical, experimental hunting leads only; no liveness or local telemetry coverage verified. Sigma validation and independent Codex review passed after path-case and ATT&CK-tag corrections.

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

### Trigram — DPRK-linked infostealer/ClickFix campaign (Nov 2026)

Stormshield CTI uncovered an industrialized campaign impersonating ~50 blockchain/AI/logistics brands (Ritual, Mina, Metis, Mantle, Linea, Fuel, Webflow, DHL, DPD, Aramex) via fake recruitment, conference, and package-tracking sites. A ClickFix clipboard-hijack trick runs a dropper that deploys the OverLord infostealer. Correlated by Stormshield to Kimsuky/DPRK (UNK_DeadDrop cluster) via a shared admin email and a MongoDB username reused in the Oct 31 2026 `antd-img-crop` npm compromise.

- `rules/trigram/{dns,proxy,process_creation,process_creation_unix}.yml`

**Sources:** Stormshield CTI (primary), The Hacker News, securityonline.info, SafeDep.

**Caveat:** no file hashes published by any source reviewed — rules are domain/IP/process-based only. Stormshield's full IOC list runs to ~200 indicators; this note/ruleset captures the subset independently corroborated across 2+ sources, not the full list. Expect continued domain rotation.

### SCKit — ConnectWise ScreenConnect worm campaign (Nov 11-13, 2026)

Distinct from the Oct 2026 ConnectWise ScreenConnect breach above. A threat actor abused a blank-access-key flaw in the third-party RMM+ ScreenConnect extension to push rogue remote-access clients and a 16-file lateral-spread toolkit (SCKit, including a `RelayTrap` technician-session interceptor) across MSP-managed endpoints — 288 hosts/48 orgs in wave 1, 205 more hosts/41 orgs in wave 2 from new infrastructure.

- `rules/sckit-screenconnect-worm/{network_connection,dns,file_event,persistence,scheduled_task}.yml`

**Sources:** Microsoft Security Blog, Huntress (primary), The Hacker News, Beazley Security, ConnectWise Trust Center.

**Caveat:** no file hashes published in the sources reviewed — rules are IP/domain/artifact-name based. Initial access vector before the RMM+ abuse was still under investigation as of the last advisory reviewed.

### CVE-2026-90436 — Apache Axis RCE exploited against Confluence Data Center / N-able N-central (Nov 2026)

Critical unsafe-reflection RCE in end-of-life Apache Axis 1.x, bundled by both Confluence Data Center and N-able N-central. Rapid7 MDR confirmed exploitation against Confluence Data Center (Nov 13, 2026). A separate N-able N-central incident is correlated by Rapid7 to this CVE but NOT vendor-confirmed as the same flaw — kept in its own clearly-flagged ruleset.

- `rules/cve-2026-90436-axis-rce/network_connection_confluence.yml` - confirmed Confluence DC exploitation source IPs
- `rules/cve-2026-90436-axis-rce/network_connection_ncentral_legacy_api.yml` - N-central C2/miner IPs (correlated, unconfirmed)
- `rules/cve-2026-90436-axis-rce/webserver_ncentral_legacy_api.yml` - N-central SOAP fault request signature (correlated, unconfirmed)
- `rules/cve-2026-90436-axis-rce/file_event_ncentral_legacy_api.yml` - N-central host artifact hash (correlated, unconfirmed)

**Sources:** Rapid7 Emergent Threat Response (primary), Atlassian advisory, N-able's own Nov 13 update, rescana.com.

**Caveat:** the N-able N-central link to CVE-2026-90436 is Rapid7's inference, not confirmed by N-able itself — treat those four IOCs as correlated, not verified.

### BubbleLoader — trojanized software loader (WinRAR, x64dbg, Windows Media Player, Firefox Launcher, virtiofs) (Nov 2026)

A loader/packer that patches a legitimate signed binary's entry point and appends two PNGs (one a rolling XOR key, one hiding XOR-encrypted shellcode) to turn common tools into malware carriers. Uses runtime polymorphism (CPU-timestamp-seeded padding overwrites) so the unpacked payload's hash changes every execution — only the on-disk tampered-carrier hashes are stable IOCs.

- `rules/bubbleloader/file_event.yml` - hash match on 24 tampered carrier SHA-256s (primary, reliable)
- `rules/bubbleloader/process_creation.yml` - behavioral RWX-alloc/ntdll-hook rule (schema placeholder, needs EDR field mapping)

**Sources:** ReversingLabs (primary), kyberkit.com, Help Net Security.

**Caveat:** file-based IOCs only — no domains/IPs were published for this campaign.

### Microsoft agent-framework PyPI supply chain compromise (Nov 17, 2026)

Microsoft's official `agent-framework` PyPI package was compromised twice ~33 minutes apart (v1.26.1, v1.26.2), both stealing Azure/CI credentials via a `.pth`-triggered payload at Python startup. Suspected uploader is a same-day-created PyPI account (`vibiret`), not confirmed by PyPI or Microsoft.

- `rules/agent-framework-pypi-compromise/file_event.yml` - hash match on all 7 malicious wheel/.pth/.py artifacts

**Sources:** safedep.io, Aikido Security (primary, independently cross-checked), ox.security.

**Caveat:** the only network indicator is `webhook[.]site`, a legitimate shared service abused for exfil — documented as a hunting lead in the vault note, not forced into a Sigma rule.

### EggStreme v2 — Chinese APT malware rebuild targeting Philippine government (Nov 18, 2026)

Suspected Chinese APT group rebuilt its EggStreme fileless malware framework after Bitdefender's Sept 2025 exposure: new EggStremeFuel config encryption, a new loader cipher/payload format, an expanded EggStremeAgent command set, and a passive (non-beaconing) listening variant. Bitdefender assesses high confidence the operation continues targeting multiple Philippine government organizations, low-to-medium confidence on Taiwan.

- `rules/eggstreme-v2/dns.yml` - DNS queries to newer-protocol + original-infrastructure C2 domains
- `rules/eggstreme-v2/network_connection.yml` - outbound connections to C2/development IPs
- `rules/eggstreme-v2/file_event.yml` - known component/config file hashes (MD5)

**Sources:** Bitdefender (primary), The Hacker News, Infosecurity Magazine, alcybr — all derivative of the one Bitdefender IOC dataset, treat as single-source.

**Caveat:** indicators span Sept 2025-Nov 2026 compile times; older domains/IPs may be sinkholed or reassigned by now — re-verify liveness before blocking. No CVE/initial-access-vector confirmed for the 2026 wave.

### GL.iNet GoodCloud router/KVM backdoor campaign (Nov 20-23, 2026, updated)

Attackers exploited a vulnerability in GL.iNet's GoodCloud cloud remote-management platform to push custom malware to customer routers and KVM devices, including root-level reverse shells. GL.iNet patched the cloud flaw on Nov 20-21 but existing infections persist. A separately-reported, apparently older backdoor (first seen ~Sept 2025) on some GoodCloud-bound routers is not yet confirmed to be the same actor/campaign. **Nov 23 update:** added a look-alike dropper domain (`gl-inet.top`), two dropper-stage URLs, a wider C2 IP range, and KVM filesystem marker indicators, sourced from an independent forum IOC report and the RemoteToHome Consulting GitHub investigation.

- `rules/glinet-goodcloud-backdoor/network_connection.yml` - C2/reverse-shell IPs, including the `170.39.226.0/24` range
- `rules/glinet-goodcloud-backdoor/process_creation.yml` - masquerading process names (GL.iNet's own published IOC + older-backdoor process names)
- `rules/glinet-goodcloud-backdoor/file_event.yml` - dropped installer/payload filenames, modified startup script/netstat paths, KVM marker files, `/tmp/f` named pipe
- `rules/glinet-goodcloud-backdoor/dns.yml` - `gl-inet.top` look-alike domain
- `rules/glinet-goodcloud-backdoor/proxy.yml` - `ni.sh`/`n5` dropper-stage URLs over TCP 8000

**Sources:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-glinet-cloud-flaw-to-infect-routers-kvm-devices/), [GL.iNet official advisory](https://www.gl-inet.com/blogs/blog/glinet-security-notice-2026-11-20), [PrivacyAffairs](https://www.privacyaffairs.com/glinet-router-backdoor/), [CIO Monitor](https://ciomonitor.com/articles/hackers-breached-gl-inet-s-cloud-to-plant-router-and-kvm-malware), [The Hacker News](https://thehackernews.com/2026/11/hackers-exploited-glinet-cloud-flaw-to.html), [RemoteToHome Consulting investigation](https://github.com/RemoteToHome-io/gl-security-incident-2026).

**Caveat:** no SHA-256 hashes were published for the November malware; detection here is filename/process/network based. The older backdoor's binary hash varies per device (41 unique hashes on 41 routers checked), so hash-matching would not work for it regardless. DNS query-name fragments reported for the older backdoor (`adguardns`, `lede-openproject`, etc.) are not confirmed full domains and were excluded from the rules. The older-backdoor findings come from a single primary source cluster (GL.iNet forum + RemoteToHome Consulting); treat with more caution than the independently-verified `ni.sh`/C2-IP findings. `api.trongrid.io` is legitimate TRON blockchain API infrastructure abused by the implant, not an indicator — do not block it.

### CVE-2026-131914 — Idunno.AntiCsrf ASP.NET unauthenticated RCE (Nov 2026)

Critical (CVSS 9.3) insecure-deserialization RCE in the defunct, unmaintained third-party ASP.NET WebForms module Idunno.AntiCsrf (last released 2008, no official patch). The module deserializes the CSRF token before validating it, so a single unauthenticated POST to any anonymously-reachable `.aspx` endpoint can achieve RCE in the IIS worker process. Disclosed by Google Mandiant, which reports active exploitation in the wild but published no attacker C2 infrastructure.

- `rules/idunno-anticsrf-cve-2026-131914/webserver.yml` - anomalous POST to `.aspx` carrying `__CSRFCOOKIE`/`__CSRFTOKEN` with HTTP 302/500 response
- `rules/idunno-anticsrf-cve-2026-131914/file_event.yml` - vulnerable DLL inventory match via 3 verified SHA-256 hashes (exposure detection, not malware detection)
- `rules/idunno-anticsrf-cve-2026-131914/process_creation.yml` - `w3wp.exe` spawning a shell/script child (generic post-exploitation signal, low/medium confidence)

**Sources:** [Mandiant advisory MNDT-2026-0048](https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2026/MNDT-2026-0048.md) (primary), [The Hacker News](https://thehackernews.com/2026/11/hackers-exploit-critical-aspnet-anti.html), [zerohunt.ai technical writeup](https://zerohunt.ai/blog/cve-2026-131914-idunno-anticsrf-aspnet-rce/).

**Caveat:** Mandiant published no attacker domains/IPs — these rules detect the exploitation technique and the vulnerable artifact itself, not attacker network infrastructure. No vendor patch exists; remediation is to remove the module entirely.

### Webworm / NtMonitor VPN — modified SoftEther VPN Bridge campaign (Nov 2026)

Rapid7 (moderate confidence) attributes a stealth-rebuilt SoftEther VPN Bridge binary, rebranded "NtMonitor VPN," to the China-aligned espionage group Webworm. No new malicious functionality was added — the rebuild exists purely to strip SoftEther's detection fingerprint (renamed endpoints, swapped watermark format, encrypted config, embedded resource archive) while posing as legitimate network-monitoring software. Only one public sample is known.

- `rules/webworm-ntmonitor-softether-2026/process_creation.yml` - PE metadata match (`netcapa.exe` original filename, "Network Systems Solutions Inc." product/company strings)
- `rules/webworm-ntmonitor-softether-2026/service_creation.yml` - `SEVPNBRIDGE` service install (correlation-only, low confidence)
- `rules/webworm-ntmonitor-softether-2026/file_hash_and_config.yml` - known sample SHA-256 hashes + `setting.conf` encrypted-config filename
- `rules/webworm-ntmonitor-softether-2026/proxy_http_paths.yml` - renamed tunnel endpoints `/update/alive.cgi`, `/update/picture.cgi`
- `rules/webworm-ntmonitor-softether-2026/network_connection_c2.yml` - reported C2 IP (secondary-sourced)

**Sources:** [Rapid7](https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge) (primary), [The Hacker News](https://thehackernews.com/2026/11/webworm-suspected-of-modifying.html).

**Caveat:** single known sample, moderate-confidence attribution. The C2 IP and two config-file hashes came from secondary outlets quoting Rapid7's IOC list (direct extraction from Rapid7's own blog was not possible this run) — treat those specific values with more caution than the directly-sourced sample hash and filename/metadata indicators. No attacker-registered domain was published.

### Cisco Expressway CVE-2026-76466 exploitation (Nov 2026)

Unauthenticated root RCE in the clustered database service of Cisco Expressway-C/E (hard-coded Erlang distribution cookie, no client-cert validation). Cisco fixed it Oct 21, 2026; a public PoC landed on GitHub, and F6 (published Nov 19) reported the first observed in-the-wild exploitation, against a Russian organization — 2 internet-facing devices breached, pivoted to 2 more internal cluster nodes, then staged Python recon/credential-theft tooling (SMB/SQL Server/WinRM/GitLab).

- `rules/cisco-expressway-cve-2026-76466/network_connection.yml` - F6's two attacker source IPs
- `rules/cisco-expressway-cve-2026-76466/file_event.yml` - staged Python script path pattern under `/mnt/harddisk/`
- `rules/cisco-expressway-cve-2026-76466/application.yml` - Erlang `nodeup 'wombat@127.0.0.1'` exploitation log signature

**Sources:** [F6](https://f6.security/media-center/press-releases/cisco-vulnerability-exploitation/) (primary), [TheHackerNews](https://thehackernews.com/2026/11/hackers-exploit-critical-cisco.html), [SecurityWeek](https://www.securityweek.com/hackers-exploit-cisco-expressway-vulnerability-soon-after-poc-release/), [SecurityAffairs](https://securityaffairs.com/203598/hacking/hackers-exploit-cisco-expressway-flaw-cve-2026-76466-to-breach-russian-organization.html).

**Caveat:** all technical IOCs trace to F6's single report (widely syndicated, not independently corroborated). Only one confirmed victim; treat the two IPs as tied to this specific incident, not a comprehensive list for the whole exploitation wave. No file hashes published for the staged scripts.

### Volant Manticore — Iran-aligned KuboShell IPFS backdoor espionage campaign (Nov 2026)

Check Point Research disclosed a previously undocumented MOIS-linked group targeting Cyprus (telecom, airlines, critical infrastructure) and, from Sept 2026, Saudi Arabia (healthcare), via phishing lures delivering an IPFS-based backdoor (KuboShell) and a MuddyC2Go-derived post-compromise framework (Homa).

- `rules/volant-manticore/network_connection.yml` - hardcoded Homa stager C2 IP:port
- `rules/volant-manticore/proxy.yml` - medochomie domain + N-able RMM installer path
- `rules/volant-manticore/file_event.yml` - lure filenames and KuboShell artifact paths

**Sources:** [Check Point Research](https://research.checkpoint.com/2026/volant-manticore-flying-under-the-radar/) (primary), [The Hacker News](https://thehackernews.com/2026/11/iran-aligned-volant-manticore-uses-ipfs.html), [Brandefense](https://brandefense.io/security-news/volant-manticore-campaign-cyprus-saudi).

**Caveat:** single primary source for all technical IOCs; narrative corroboration only from secondary outlets. Attribution to MOIS/Iran is Check Point's own assessment. IPFS/Pinata are abused legitimate services, not attacker infrastructure — do not blocklist them.

### GT13 — Check Point Security Management Server intrusion campaign (Oct-Nov 2026)

GreyNoise (sensor-based, AI-assisted-campaign assessment) tracked an unattributed actor exploiting Rejetto HFS (CVE-2026-61500) and Check Point SmartConsole (CVE-2026-16232) to compromise 24 Check Point Security Management Servers across 22 organizations in 17 countries, using one victim as an operational relay.

- `rules/gt13-checkpoint-smcompromise/dns.yml` - newpayapp.com and known subdomains
- `rules/gt13-checkpoint-smcompromise/file_event.yml` - ld.so.preload persistence + implant .so path

**Sources:** [GreyNoise](https://www.greynoise.io/blog/check-point-security-management-servers-intrusion-campaign) (primary), [SecurityWeek](https://www.securityweek.com/check-point-security-management-servers-hacked-in-ai-assisted-campaign/).

**Caveat:** single primary source. ~70 IPs observed in the campaign are ExpressVPN egress nodes (shared VPN infrastructure, not attacker-owned) and were deliberately excluded as indicators. No file hashes were published for the "ZULT" implant (download failed in GreyNoise's observation window).

## License

Apache 2.0
