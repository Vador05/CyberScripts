# CyberScripts — Tool Index

*Last updated: 2026-06-18 — 61 tools*

## BlueTeam

### Deception
- **Create a Deceptive User in AD** (PowerShell) — Creates a honeypot user account in Active Directory to detect lateral movement and credential attacks.

### Detection
- **AI Recon Pattern Detector** (Python) *(draft)* — Analyzes plain text auth/syslog entries to identify behavioral signatures of LLM-driven lateral movement, such as systematic sequential probing and structured host enumeration chains. Outputs scored alert lines to stdout for use in developing detection rules against autonomous AI-reasoned reconnaissance.
- **CDN Hash Sentinel** (Python) *(draft)* — Simulates a CDN-level supply chain attack by generating a fake plugin update log with an injected hash mismatch, then scans the log to detect unexpected asset hash changes that indicate possible JavaScript tampering. Demonstrates how blue teams can monitor CDN asset integrity to catch compromised plugin update channels.
- **Check Point VPN Qilin Sigma Rule Generator** (Python) *(draft)* — Generates Sigma detection rules for the Check Point VPN auth-bypass exploitation chain (CVE-2024-24919) used by Qilin ransomware affiliates, mapping each attack stage to MITRE ATT&CK. Accepts plain-text VPN/auth logs and outputs ready-to-use Sigma YAML rules to stdout.
- **ClickFix Loader Detector** (Python) *(draft)* — Scans plain text logs for behavioral indicators matching BabaDeda, Lorem Ipsum, and Potemkin loader patterns surfaced in ClickFix campaigns. Outputs YARA-style and Sigma-compatible rule matches to stdout with timestamps and severity ratings.
- **Commvault Ransomware Pre-Staging Detector** (Python) *(draft)* — Analyzes plain-text Commvault log exports for ransomware pre-staging indicators including anomalous API calls, credential enumeration patterns, and job-schedule tampering. Helps blue team analysts triage potential ransomware intrusions targeting backup infrastructure before encryption begins.
- **Container Escape & Privesc Detector** (Python) *(draft)* — Parses Linux audit and syslog plaintext output to detect exploitation signatures associated with kernel privilege-escalation and container breakout techniques (e.g., nf_tables UAF, runc/OverlayFS escapes, capability abuse). Includes a lab mode that emits synthetic exploit event sequences to validate detection coverage without a live environment.
- **DetectIncommingConnection** (Python) — Monitors and alerts on new incoming network connections in real time.
- **EDR Probe Detector** (Python) *(draft)* — Analyzes plain text security logs to identify automated AI-assisted EDR evasion probing patterns such as rapid enumeration, timing anomalies, and systematic API call sequences. Generates actionable Sigma and YARA rules to detect these reconnaissance behaviors before any payload is deployed.
- **Langflow CVE-2026-5027 Triage Scanner** (Python) *(draft)* — Detects exploitation attempts and post-exploitation artifacts of the Langflow unauthenticated file-write RCE vulnerability (CVE-2026-5027). Scans plain-text log files for suspicious endpoint hits, file-write payloads, and known post-exploitation indicators on AI development hosts.
- **LiteLLM SSRF-to-RCE Detector** (Python) *(draft)* — Scans LiteLLM and AI gateway plain-text logs for SSRF-to-RCE exploit chain indicators using regex-based IOC matching against known attack patterns targeting the /config/update endpoint, internal callback URIs, and metadata service probes. Outputs timestamped flagged lines with severity tags and a prioritized hardening checklist for LiteLLM deployments.
- **Miasma Rule Generator** (Python) *(draft)* — Scans plain-text logs for Miasma malware IOCs and behavioral signatures tied to its credential-harvesting and supply-chain delivery mechanics. Emits ready-to-deploy YARA or Sigma rules to stdout based on matched evidence.
- **Netlogon RCE Detector** (Python) *(draft)* — Detects CVE-2026-41089 exploitation attempts by scanning plain-text Windows Security event logs for suspicious Event ID 4742/5805 patterns and anomalous Netlogon RPC signatures. Alerts on credential resets, unauthorized secure channel establishment, and RPC anomalies indicative of privilege escalation via Netlogon.
- **SEO Poison DNS Detector** (Python) *(draft)* — Parses plain-text DNS or proxy logs to flag domains matching indicators associated with SEO-poisoned fake open-source package sites delivering Remus Stealer and SessionGate via traffic distribution systems. Outputs timestamped alerts to stdout and optionally appends flagged IPs to a blocklist file compatible with DetectIncomingConnectionandBlockIP.
- **Splunk Unauth File-Op Triage** (Python) *(draft)* — Scans plain-text Splunk Enterprise access logs for unauthenticated file-operation attempts matching CVE-2026-20253 exploit patterns, then cross-checks a supplied version string to confirm whether the targeted instance carries the patch. Produces a timestamped stdout report suitable for SOC triage or portfolio evidence.
- **Voice Assistant Injection Detector** (Python) *(draft)* — Simulates notification-borne prompt injection payloads to model how malicious content in alerts or messages can hijack AI voice assistant behavior. Analyzes plain-text assistant action logs for heuristic anomalies indicating the assistant may have acted on injected instructions rather than legitimate user commands.
- **WinRE XML BitLocker Bypass Detector** (Python) *(draft)* — Simulates the GreatXML BitLocker bypass technique by generating synthetic WinRE recovery XML access event sequences, then scans plain-text Windows logs for the same anomalous ReAgent.xml and BCD file access signatures. Outputs flagged log lines and a ready-to-import Sigma or Elastic EQL detection rule to stdout.

### Forensics
- **C/C++ Taint Flow Scanner** (Python) *(draft)* — Performs pattern-based taint analysis on C/C++ source files by tracing untrusted input from sources (stdin, argv, fgets) to dangerous sinks (strcpy, system, sprintf). Outputs structured bug reports with file location, taint path, and a reproduction stub to stdout, suitable for embedding in CI pipelines.
- **HARanalyzer** (Python) — Parses and analyzes HTTP Archive (HAR) files to surface security-relevant requests, headers, and responses.
- **list IPs in a pcap** (Python) — Extracts and lists all unique IP addresses observed in a PCAP capture file.
- **list IPs in a pcap with HTTP code NOT 200** (Python) — Extracts IPs from a PCAP that generated non-200 HTTP responses — useful for spotting errors, probes, and attacks.

### IncidentResponse
- **DetectIncommingConnectionandBlockIP** (Python) — Detects suspicious incoming connections and automatically blocks the source IP via firewall rules.

### Labs
- **AI Agent Human-in-the-Loop Checkpoint Lab** (Python) *(draft)* — Interactive CLI lab that simulates an AI security agent executing tasks with explicit human approval gates at privilege escalation and data access decision points. Demonstrates how mandatory checkpoints prevent automated exploitation by requiring operator sign-off before sensitive operations proceed.
- **LLM Security Benchmark** (Python) *(draft)* — Scores LLM-generated responses against a fixed rubric of security research tasks including CVE triage, exploit summarization, and malware prompt analysis. Outputs a ranked scorecard to stdout so practitioners can compare models on domain-specific accuracy.
- **npm Supply Chain Attack Lab** (Python) *(draft)* — Parses a plain-text npm verbose install log to replay a classic postinstall-script supply chain attack, then re-evaluates each detected script under npm 12's opt-in execution model to show exactly what gets blocked. Outputs a side-by-side comparison table and a ready-to-paste allowlist for packages whose postinstall scripts are legitimate.

### Posture
- **DownloadDNSRecordsInCSVforADomain** (Python) — Exports all DNS records for a given domain to a CSV file for inventory and monitoring.
- **EDR Telemetry Gap Detector** (Python) *(draft)* — Parses plain-text EDR/syslog output to identify coverage gaps exploitable by AI-assisted evasion techniques and lateral movement via AD discovery. Flags missing telemetry signals that would leave container escapes and privilege escalation undetected.
- **Healthcheck** (PowerShell) — System health check script covering key security-relevant services and configurations.
- **Healthcheck (Python)** (Python) — Python version of the system health check for Linux/cross-platform environments.
- **MCP Config Scanner** (Python) *(draft)* — Scans MCP server configuration files for known misconfigurations and supply-chain risks using customizable detection rules. Outputs structured findings to stdout with severity ratings and remediation hints.
- **findIdP** (Python) — Identifies the Identity Provider (IdP) for a given domain or email address.

### SupplyChain
- **Contagious Interview NPM Payload Scanner** (Python) *(draft)* — Detects behavioral signatures of Contagious Interview threat actor TTPs in npm package audit logs and repository metadata, including malicious install hooks, staged payload delivery patterns, and trojanized developer-tool indicators. Outputs prioritized alerts to stdout for integration into CI/CD pipeline log monitoring workflows.
- **Marketplace Plugin Risk Scanner** (Python) *(draft)* — Scans a plain-text log of IDE plugin metadata (publisher age, download counts, timestamps) to flag suspicious packages using velocity anomalies and publisher freshness heuristics. Outputs risk-scored findings to stdout for use in CI/CD pre-install gates.
- **NPM IOC Log Scanner** (Python) *(draft)* — Scans plain-text CI/CD and npm audit logs for TeamPCP supply chain campaign indicators using embedded YARA-style pattern rules. Detects malicious package names, suspicious install hooks, and known IOC strings associated with npm-based supply chain attacks.
- **NPM Malicious Pattern Scanner** (Python) *(draft)* — Scans npm install or audit log output for behavioral patterns associated with worm-style credential stealers, as documented in the Red Hat supply-chain campaign. Flags suspect package events to stdout so CI/CD pipelines can gate on exit code.
- **PyPI Trojan Scanner** (Python) *(draft)* — Downloads a PyPI package wheel and scans its extracted Python source files for credential-harvesting stub patterns characteristic of supply-chain trojanization attacks. Reports suspicious code fragments, matched pattern names, and line numbers to stdout without executing any package code.

### ThreatHunting
- **CVE Triage Scanner** (Python) *(draft)* — Parses plain-text CVE feed logs to score exploitability based on keyword heuristics and CVSS indicators, then drafts Sigma detection rules for high-severity findings. Outputs triage results and detection rules to stdout without requiring external dependencies or human prompting.
- **FortiSandbox Post-Exploitation Scanner** (Python) *(draft)* — Applies embedded Sigma-style detection rules to plain text FortiSandbox/FortiGate logs to surface post-exploitation indicators consistent with the 30,000-credential compromise baseline. Outputs severity-ranked matches to stdout for triage without requiring external tooling or SIEM integration.
- **Ivanti Sentry Sigma Rule Matcher** (Python) *(draft)* — Scans plain-text log files for attacker pre-positioning patterns associated with post-disclosure exploitation of Ivanti Sentry edge appliances. Matches log lines against a built-in Sigma-style rule set covering CVE-2023-38035 and related recon/exploitation indicators, printing structured runbook alerts to stdout.
- **PeopleSoft CVE-2026-35273 Hunt Rule Generator** (Python) *(draft)* — Scans plain-text PeopleSoft application logs for CVE-2026-35273 exploitation indicators attributed to ShinyHunters TTPs and emits Sigma-compatible detection rules to stdout. Extends the WebLogic CVE-2024-21182 hunt rule pattern with PeopleSoft-specific URI traversal, credential-stuffing, and bulk-export signatures.
- **RedCAP Long-Dwell Credential Theft Detector** (Python) *(draft)* — Analyzes plain-text authentication logs for behavioral patterns consistent with UNC6508-style credential theft campaigns targeting research institutions, including low-and-slow login enumeration, off-hours access spikes, and credential reuse across research portals. Outputs a prioritized alert report to stdout with dwell-time estimates and MITRE ATT&CK mappings.
- **Tailscale+SSH Persistence Detector** (Python) *(draft)* — Parses plain-text system logs to detect co-installation of Tailscale and OpenSSH on endpoints, flagging the combination as a potential covert persistence indicator. Outputs structured Sigma-style alert findings to stdout for triage or pipeline ingestion.
- **VS Code URI Token Hunter** (Python) *(draft)* — Scans plain-text CI/CD pipeline logs for indicators of GitHub token exfiltration via VS Code workspace trust abuse, flagging suspicious URI handler invocations, malicious .vscode/settings.json patterns, and credential exposure sequences. Outputs timestamped findings with severity and matched rule to stdout for rapid triage by pipeline defenders.
- **WebLogic CVE-2024-21182 Hunt Rule Generator** (Python) *(draft)* — Parses plain-text HTTP/WebLogic access and server logs to detect exploitation patterns matching CVE-2024-21182 (JNDI/T3 deserialization abuse) as tracked in active KEV campaigns. Outputs structured Sigma-style detection hits with timestamp, source IP, and matched pattern to stdout.
- **Xeno RAT Log Hunter** (Python) *(draft)* — Scans plain-text log files for Xeno RAT indicators including C2 registration patterns, persistence registry keys, and network beaconing signatures. Outputs timestamped SIGMA-aligned findings to stdout, tuned for government finance sector environments.

## RedTeam

### Labs
- **AWS Privilege Escalation Probe** (Python) *(draft)* — Simulates IAM privilege-escalation and S3 misconfiguration scenarios against a LocalStack endpoint so practitioners can learn and test detection logic offline. Outputs a structured audit trail to stdout showing each attack path attempted and whether it succeeded.
- **Agentjacking Prompt Injection Lab** (Python) *(draft)* — Simulates the agentjacking attack technique by injecting adversarial prompts into a sandboxed AI agent session log and evaluating whether guardrail patterns detect the injection attempt. Produces a plain-text report showing which injections succeeded, which were caught, and confidence scores for each detection rule.
- **PhishBench** (Python) *(draft)* — Fires configurable prompt-injection phishing payloads at AI email agent endpoints and measures resilience by parsing stdout responses for compliance or refusal signals. Benchmarks multiple model/config profiles in a single run and reports a scored summary to stdout.
- **Prompt Injection Lab** (Python) *(draft)* — Demonstrates prompt injection and data exfiltration attacks against a simulated RAG pipeline, then shows how zero-trust input/output validation mitigations block each attack vector. Runs attack scenarios end-to-end in a single script with annotated stdout output for hands-on learning.
- **Vulnerability Triage Lab** (Python) *(draft)* — Scans a deliberately vulnerable Python codebase for common vulnerability patterns (SQLi, command injection, hardcoded secrets, path traversal) and produces a prioritized triage report. Guides practitioners through reading findings and understanding why each pattern is dangerous.

- **PingScan** (Shell) — ICMP ping sweep to discover live hosts on a network range.
- **SearchKeyWordsInAWebsite** (Python) — Crawls a website and searches all pages for specified keywords — useful for recon and content discovery.
- **SearchKeyWordsInAWebsiteThroughTor** (Python) — Same as SearchKeyWordsInAWebsite but routes traffic through the Tor network for anonymity.
- **TelnetPortScanner** (Shell) — Port scanner using telnet to test connectivity to common service ports.
- **TestFiletypeuploads** (Python) — Tests file upload endpoints for weak extension/MIME type restrictions that could allow malicious uploads.

## GRC

- **Agent Policy Auditor** (Python) *(draft)* — Parses plain-text agent audit logs to detect over-privileged access patterns when autonomous agents interact with Postgres and Kubernetes. Flags violations of least-privilege policy rules and reports findings to stdout.
- **CVE Asset Correlator** (Python) *(draft)* — Ingests a CVE list and a plain-text SBOM/CMDB asset inventory, correlates vulnerabilities against affected assets, and outputs prioritized remediation tickets to stdout. Ranks findings by CVSS severity and asset criticality to surface the highest-risk exposures first.
- **UploadExceltoSharepointList** (PowerShell) — Uploads data from an Excel file into a SharePoint list for compliance tracking and reporting.
- **UploadExceltoSharepointListUsingPrimaryKey** (PowerShell) — Uploads Excel data to SharePoint using a primary key to prevent duplicate entries.
- **checkHostingPlatform** (Python) — Identifies the hosting platform (AWS, Azure, GCP, etc.) for a given domain or IP.
- **dnsinventory** (Python) — Enumerates and inventories DNS records across multiple domains for asset management and compliance.
