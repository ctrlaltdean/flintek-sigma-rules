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

## License

Apache 2.0
