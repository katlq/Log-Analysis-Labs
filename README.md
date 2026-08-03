# 🔍 SOC Log Analysis Labs

This repo hosts two separate SOC log-analysis labs — one on Linux, one on Windows — both focused on the same core skill: parsing raw logs with native tooling to detect and document security incidents, without relying on a SIEM.

```
.
├── README.md                      → you are here (repo overview, no findings)
├── 01-cli-log-analysis/           → Project 1: Log Analysis with CLI Tools
│   ├── apache_access.log          →   raw Apache access log used for the analysis
│   ├── Log-Analysis-Report.md     →   full write-up: methodology, commands, findings
│   ├── unique_ips.txt             →   every unique IP extracted from the log
│   ├── suspicious_ips.txt         →   IPs flagged as genuine follow-up/blocking candidates
│   └── urls.txt                   →   URLs identified during the analysis
└── 02-powershell-log-analysis/    → Project 2: Windows Log Analysis with PowerShell
    └── ...                        →   scripts + report (in progress)
```

---

## 📁 Project 1 — Log Analysis with CLI Tools

**Tools:** `grep` · `awk` · `sed` · `cut` · `sort` · `uniq` · `wc`

**Scenario:** Acting as a SOC analyst at **SecureCorp**, investigating a potential web application attack. The security team flagged unusual traffic patterns hitting the company's web server, and the task was to parse the raw Apache access logs and determine what was actually going on — attack vectors, likely-compromised or malicious sources, and overall traffic health.

**What it practices:**
- Using `grep` to search for attack signatures and patterns in log files
- Using `awk` to extract and manipulate specific fields from log entries
- Using `sed` for basic text transformations
- Chaining CLI tools together for multi-step log analysis
- Spotting suspicious activity in web server logs
- Writing up findings as a clear, professional security report

Full results live in [`01-cli-log-analysis/Log-Analysis-Report.md`](./01-cli-log-analysis/Log-Analysis-Report.md).

---

## 📁 Project 2 — Windows Log Analysis with PowerShell

**Tools:** PowerShell, `Get-WinEvent`, Windows Security Event Log

**Scenario:** Acting as a SOC analyst at **FinanceCorp**, investigating suspicious activity on critical Windows servers. The security team detected multiple failed login attempts and unusual account behavior, and the task was to use PowerShell to analyze Windows Security Event Logs, identify attack patterns, and determine the scope of the compromise.

**What it practices:**
- Using `Get-WinEvent` to query and filter Windows Security Event Logs
- Extracting specific properties from event log entries via XML parsing
- Using PowerShell pipelining to group, sort, and count event data
- Analyzing logon events to identify potential brute-force attacks
- Detecting lateral movement and privilege escalation attempts
- Writing automated PowerShell scripts for log analysis
- Generating professional security reports from Windows Event Logs

Full results will live in [`02-powershell-log-analysis/`](./02-powershell-log-analysis/) once complete.

---

*Both labs: Beginner → Intermediate. This README is a project index only — detailed methodology, commands, and findings are in each project's own report.*
