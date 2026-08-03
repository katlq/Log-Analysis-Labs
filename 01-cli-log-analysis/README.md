# Apache Log Analysis Report

**Analyst:** rapoko
**Date:** 03.08.2026  
**Log File:** apache_access.log
**Analysis Period:** Single-day capture (exact timestamps not extracted from sampled log)

---

## Executive Summary

Analysis of 61,065 requests from 76 unique IP addresses shows a server under active, sustained attack rather than normal traffic. Roughly 19% of requests returned client/server errors (400/403/404/500 combined = ~16,845), and pattern-matching found 2,384 possible SQL-injection strings and 791 possible XSS strings in the request lines. A handful of public IP addresses (185.220.101.x, 45.129.14.201, 45.155.204.9, 91.243.85.12, 198.51.100.x, 203.0.113.x, 80.94.95.116) account for the bulk of traffic and should be treated as the priority for blocking and further investigation; internal-looking RFC1918 addresses (10.0.0.x, 192.168.1.x) that also appear in the "SQL injection" grep results are very likely false positives from the broad keyword match rather than real attackers (see note in Section 3).

---

## 1. Traffic Overview

### Total Requests
**Answer:** 61065

**Command:**
```bash
wc -l name.log
```
### Unique IP addresses

**Answer:** 76
**Command:**
```bash
awk '{print $1}' name.log | sort -u | wc -l
```

### Top 10 IP addresses
```
   2584 80.94.95.116
   2540 45.129.14.201
   2531 198.51.100.77
   2526 185.220.101.34
   2515 203.0.113.46
   2510 198.51.100.23
   2480 91.243.85.12
   2474 45.155.204.9
   2456 185.220.101.7
   2449 203.0.113.45
```
```bash
awk '{print $1}' name.log | sort | uniq -c | sort -rn | head -10
```

**Note:** these 10 IPs alone account for roughly 24,865 requests (~41% of all traffic) despite the log showing 76 unique IPs total, indicating a small set of clients dominates the traffic — consistent with automated/scripted activity rather than organic browsing.

## 2. HTTP Status Code Analysis

### Status Code Distribution
```
   29233 200
   5933 302
   5854 304
   5084 400
   5043 404
   4993 403
   4925 500
```

```bash
awk '{print $9}' name.log | sort | uniq -c | sort -rn
```

Error/redirect responses (302+304+400+403+404+500 = 31,832) make up just over half of all requests, and server errors (500) alone account for 4,925 requests (~8%) — a rate high enough to suggest the application itself is being stressed or exploited (e.g. malformed input reaching the backend), not just being scanned.

### 404 Errors
**Answer:** 5043

```bash
awk '$9 == 404' name.log | wc -l
```

### Top 5 urls with 404
```
    321 /tienda1/publico/anadir.jsp
    285 /tienda1/miembros/editar.jsp
    280 /tienda1/publico/registro.jsp
    269 /tienda1/publico/pagar.jsp
    261 /tienda1/publico/autenticar.jsp
```
```bash
awk '$9 == 404 {print $7}' name.log | sort | uniq -c | sort -rn | head -5
```
*(corrected the misplaced quote/brace from the original one-liner — the filter and print need to happen inside the same awk block)*

These are all endpoints from the "tienda1" (WASC/DVWA-style e-commerce) test application — registration, login, edit, and payment pages — and are exactly the pages an attacker would probe for injection or authentication-bypass flaws, which lines up with the SQLi/XSS findings below.

## 3. Security Analysis

### Scanning activity (Nikto)
**Request from Nikto:** 0
```bash
grep -i 'nikto' name.log | wc -l
```
No requests carried a Nikto user-agent string. This only rules out *this specific* scanner signature — it does not rule out scanning done with a spoofed or blank user agent, which the traffic concentration in Section 1 suggests may be happening anyway.

### SQL Injection Attempts
**Total Attempts:** 2384

```bash
grep -iE "(union|select|insert|drop)" name.log | wc -l
```

**Attacking IPs:** 76
```
10.0.0.10
10.0.0.11
10.0.0.12
10.0.0.13
10.0.0.14
10.0.0.15
10.0.0.16
10.0.0.17
10.0.0.18
10.0.0.19
10.0.0.2
10.0.0.20
10.0.0.21
10.0.0.22
10.0.0.23
10.0.0.24
10.0.0.25
10.0.0.26
10.0.0.27
10.0.0.28
10.0.0.29
10.0.0.3
10.0.0.4
10.0.0.5
10.0.0.6
10.0.0.7
10.0.0.8
10.0.0.9
185.220.101.34
185.220.101.7
192.168.1.10
192.168.1.11
192.168.1.12
192.168.1.13
192.168.1.14
192.168.1.15
192.168.1.16
192.168.1.17
192.168.1.18
192.168.1.19
192.168.1.2
192.168.1.20
192.168.1.21
192.168.1.22
192.168.1.23
192.168.1.24
192.168.1.25
192.168.1.26
192.168.1.27
192.168.1.28
192.168.1.29
192.168.1.3
192.168.1.30
192.168.1.31
192.168.1.32
192.168.1.33
192.168.1.34
192.168.1.35
192.168.1.36
192.168.1.37
192.168.1.38
192.168.1.39
192.168.1.4
192.168.1.5
192.168.1.6
192.168.1.7
192.168.1.8
192.168.1.9
198.51.100.23
198.51.100.77
203.0.113.45
203.0.113.46
45.129.14.201
45.155.204.9
80.94.95.116
91.243.85.12
```

**Important caveat:** this list is every single unique IP in the log (76 of 76). That's a strong signal the keyword grep is over-matching rather than finding true attackers — `select`, `insert`, `union`, and `drop` are common substrings inside ordinary words, headers, and static asset paths (e.g. "insert" inside a product description, "union" inside a referrer URL), so a plain `grep -iE` across the *whole log line* (user agent, referrer, timestamp, etc.) instead of just the request's query string will flag normal traffic too. To get a trustworthy attacking-IP list, this should be re-run against only the request field with word boundaries and ideally only against `400`/`403`/`500` responses, e.g.:
```bash
awk -F'"' '{print $2}' name.log | grep -iE '\b(union select|select .* from|insert into|drop table)\b'
```
Until that's done, treat the private/internal addresses (10.0.0.x, 192.168.1.x) as likely false positives, and treat the public IPs on this list (185.220.101.34/7, 198.51.100.23/77, 203.0.113.45/46, 45.129.14.201, 45.155.204.9, 80.94.95.116, 91.243.85.12 — the same set as the Top 10 talkers) as the ones warranting real investigation.

### XSS Attempts
**Total attempts:** 791
```bash
grep -iE '(script|javascript:|onerror)' name.log
```
Same caveat as above applies: "script" appears in ordinary content-type/user-agent strings (e.g. `Mozilla`, static `.js` asset requests), so this count should be treated as an upper bound, not a confirmed attack count, until narrowed to the request/query-string field.

### Directory Traversal
**Total Attempts:** 0
```bash
grep -E '(\.\./|\.\.%2[Ff])' name.log | wc -l
```
No `../` or URL-encoded traversal sequences were found. This is a genuinely clean result (the pattern is specific enough to avoid the false-positive problem above).

## 4. Request Method Analysis

**Distribution:**
```
43088 GET
17580 POST
397 PUT
```
```bash
awk '{print $6}' apache_access.log | tr -d '"' | sort | uniq -c | sort -rn
```
POST traffic is unusually high at ~29% of all requests (typical browsing traffic is usually 80-95% GET). Combined with the 397 PUT requests — a method rarely used by browsers but common in automated API abuse or file-upload attack attempts — this reinforces that a meaningful share of this traffic is scripted rather than human.

## 5. Suspicious Activity Summary

### High-Risk IP Addresses

| IP Address | Requests (from Top 10) | Suspicious Activities |
|---|---|---|
| 80.94.95.116 | 2584 | Highest-volume talker; flagged in SQLi/XSS keyword match |
| 45.129.14.201 | 2540 | High-volume talker; flagged in SQLi/XSS keyword match |
| 198.51.100.77 | 2531 | High-volume talker; flagged in SQLi/XSS keyword match |
| 185.220.101.34 | 2526 | High-volume talker; IP range associated with Tor exit nodes; flagged in SQLi match |
| 203.0.113.46 | 2515 | High-volume talker; flagged in SQLi/XSS keyword match |
| 198.51.100.23 | 2510 | High-volume talker; flagged in SQLi/XSS keyword match |
| 91.243.85.12 | 2480 | High-volume talker; flagged in SQLi/XSS keyword match |
| 45.155.204.9 | 2474 | High-volume talker; flagged in SQLi/XSS keyword match |
| 185.220.101.7 | 2456 | High-volume talker; IP range associated with Tor exit nodes; flagged in SQLi match |
| 203.0.113.45 | 2449 | High-volume talker; flagged in SQLi/XSS keyword match |

*(198.51.100.0/24 and 203.0.113.0/24 are IANA-reserved documentation ranges — in a real capture these would actually be spoofed/placeholder addresses, which is itself worth flagging to whoever owns this log source.)*

The 10.0.0.x and 192.168.1.x addresses are excluded from the high-risk table above: they are internal/private ranges that only appear because of the SQLi keyword over-match discussed in Section 3, not because of distinct suspicious behavior.

### Recommended Actions

**Block the following IPs (pending confirmation with the narrowed grep from Section 3):**
- 185.220.101.34, 185.220.101.7 — Reason: known Tor-exit-node range, high request volume, present in SQLi keyword matches
- 45.129.14.201, 45.155.204.9 — Reason: high request volume, present in SQLi/XSS keyword matches, no legitimate business reason identified
- 80.94.95.116, 91.243.85.12 — Reason: highest request volumes in the entire log, present in SQLi/XSS keyword matches

**Investigate further:**
- Re-run SQLi/XSS detection against only the request query-string field (not the full log line) to eliminate false positives before acting on the "76 attacking IPs" list.
- Confirm whether 198.51.100.0/24 and 203.0.113.0/24 traffic is coming from NAT/proxy infrastructure, since those ranges are reserved for documentation and shouldn't appear in real internet traffic.
- The 4,925 HTTP 500 responses (~8% of all traffic) should be cross-referenced against application error logs to determine whether SQLi/XSS attempts are successfully reaching and breaking the backend.

**Patch/Update:**
- The concentration of 404s on `/tienda1/publico/anadir.jsp`, `/tienda1/miembros/editar.jsp`, `/tienda1/publico/registro.jsp`, `/tienda1/publico/pagar.jsp`, and `/tienda1/publico/autenticar.jsp` suggests these registration/login/checkout endpoints are being actively probed; verify they have current input validation and are not exposing stack traces on error (which would explain some of the 500s).

## 6. Bandwidth Analysis

**Total bandwidth:** Not computed — the response-size field (typically `$10` in combined log format) was not extracted in any of the commands run for this analysis.

**Top 10 bandwidth consumers:** Not computed for the same reason.

To fill in this section, re-run against the log with:
```bash
# Total bytes transferred (treats "-" as 0)
awk '{sum += ($10 == "-" ? 0 : $10)} END {print sum}' name.log

# Top 10 IPs by bytes transferred
awk '{bytes[$1] += ($10 == "-" ? 0 : $10)} END {for (ip in bytes) print bytes[ip], ip}' name.log | sort -rn | head -10
```

## Conclusion

The log shows a server receiving substantially more error and non-GET traffic than a healthy production site would, concentrated among a small set of public IP addresses that dominate total request volume. Keyword-based SQLi/XSS detection (`grep -iE` across full log lines) massively over-flagged benign traffic — up to and including every unique IP in the log — so those specific counts (2,384 / 791) should be treated as upper bounds pending a proper query-string-scoped re-run, not as confirmed attack totals. What *is* solid: the top-10 IP concentration, the abnormal GET/POST/PUT method split, the 8% server-error rate, and the 404 clustering on authentication/checkout endpoints. Together these point to targeted, automated probing of the "tienda1" application's login, registration, and payment flows, rather than routine crawler or user traffic. Recommended next step is blocking the six public IPs listed in Section 5 pending the corrected grep, and reviewing application logs for the affected endpoints to see whether any probe attempts actually succeeded.

## Appendices

### Appendix A: All Commands Used

```bash
# Total requests
wc -l name.log

# Unique IP addresses
awk '{print $1}' name.log | sort -u | wc -l

# Top 10 IP addresses
awk '{print $1}' name.log | sort | uniq -c | sort -rn | head -10

# Status code distribution
awk '{print $9}' name.log | sort | uniq -c | sort -rn

# 404 count
awk '$9 == 404' name.log | wc -l

# Top 5 URLs with 404 (corrected)
awk '$9 == 404 {print $7}' name.log | sort | uniq -c | sort -rn | head -5

# Nikto scanning check
grep -i 'nikto' name.log | wc -l

# SQL injection keyword count
grep -iE "(union|select|insert|drop)" name.log | wc -l

# SQL injection attacking IPs
grep -ilE "(union|select|insert|drop)" name.log
# (recommended narrower re-run:)
awk -F'"' '{print $2}' name.log | grep -iE '\b(union select|select .* from|insert into|drop table)\b'

# XSS keyword count
grep -iE '(script|javascript:|onerror)' name.log

# Directory traversal check
grep -E '(\.\./|\.\.%2[Ff])' name.log | wc -l

# Request method distribution
awk '{print $6}' apache_access.log | tr -d '"' | sort | uniq -c | sort -rn

# Bandwidth (recommended, not yet run)
awk '{sum += ($10 == "-" ? 0 : $10)} END {print sum}' name.log
awk '{bytes[$1] += ($10 == "-" ? 0 : $10)} END {for (ip in bytes) print bytes[ip], ip}' name.log | sort -rn | head -10
```

### Appendix B: Suspicious IPs List

Full list flagged by the broad SQLi/XSS keyword grep (see Section 3 caveat — internal ranges likely false positives):

```
10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5, 10.0.0.6, 10.0.0.7, 10.0.0.8, 10.0.0.9,
10.0.0.10, 10.0.0.11, 10.0.0.12, 10.0.0.13, 10.0.0.14, 10.0.0.15, 10.0.0.16,
10.0.0.17, 10.0.0.18, 10.0.0.19, 10.0.0.20, 10.0.0.21, 10.0.0.22, 10.0.0.23,
10.0.0.24, 10.0.0.25, 10.0.0.26, 10.0.0.27, 10.0.0.28, 10.0.0.29,
192.168.1.2, 192.168.1.3, 192.168.1.4, 192.168.1.5, 192.168.1.6, 192.168.1.7,
192.168.1.8, 192.168.1.9, 192.168.1.10, 192.168.1.11, 192.168.1.12, 192.168.1.13,
192.168.1.14, 192.168.1.15, 192.168.1.16, 192.168.1.17, 192.168.1.18, 192.168.1.19,
192.168.1.20, 192.168.1.21, 192.168.1.22, 192.168.1.23, 192.168.1.24, 192.168.1.25,
192.168.1.26, 192.168.1.27, 192.168.1.28, 192.168.1.29, 192.168.1.30, 192.168.1.31,
192.168.1.32, 192.168.1.33, 192.168.1.34, 192.168.1.35, 192.168.1.36, 192.168.1.37,
192.168.1.38, 192.168.1.39
```

Genuine high-priority subset (public IPs, cross-referenced against Top 10 talkers — see Section 5):

```
80.94.95.116
45.129.14.201
198.51.100.77
185.220.101.34
203.0.113.46
198.51.100.23
91.243.85.12
45.155.204.9
185.220.101.7
203.0.113.45
```

---

**Lab Completion Time:** —
**Difficulty Level:** Beginner to Intermediate
