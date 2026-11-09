# INCIDENT INVESTIGATION REPORT: JWT ALGORITHM NONE & OWASP SQLI TRIAGE (T1550.001, T1190)

## 1. Ticket Information
- Incident ID: INC-202611-004
- Priority: P1 - Critical (SQLi Exploit) / P2 - High (JWT None Attack)
- Classification: True Positive
- Status: Closed / Remediated
- Assignee: SOC Tier 1 Analyst
- Target Host: Production Web API Gateway (Nginx Reverse Proxy)
- Detector: Wazuh Manager (Rule 100401, Rule 100402, Rule 100403)

## 2. Executive Summary (SBAR Framework)
- Situation: Web access logs recorded consecutive attacks targeting API authentication using unsigned JWT tokens, followed by automated SQL Injection probes and a successful injection returning HTTP 200 OK.
- Background: Insecure JWT implementations may accept tokens with `alg: "none"`, bypassing signature verification. Web applications vulnerable to SQLi allow direct database query manipulation.
- Assessment: Attacker attempted privilege escalation via unsigned JWT `alg:none`. When probed with SQLi, endpoint `/api/v1/blocked/search` returned HTTP 403 (blocked), whereas `/api/v1/products` returned HTTP 200 with 8,450 bytes of data (successful exfiltration).
- Recommendation: Enforce mandatory cryptographic signature verification for all JWTs, patch API SQL parameterization, and block offending IP address at the firewall/WAF.

## 3. Log Evidence & Analysis

Event 1 - JWT Algorithm None Attack:
```text
185.220.101.5 - - [09/Nov/2026:09:25:15 +0700] "GET /api/v1/user/profile?access_token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ. HTTP/1.1" 200 418 "-" "python-requests/2.31.0"
```
Base64 Decoded Header: `{"alg":"none","typ":"JWT"}`
Base64 Decoded Payload: `{"user":"admin","role":"admin"}`
Analysis: The attacker stripped the third segment (signature) and asserted administrative privileges without providing a cryptographic secret.

Event 2 - SQL Injection Probe Blocked (HTTP 403):
```text
185.220.101.5 - - [09/Nov/2026:09:25:19 +0700] "GET /api/v1/products?cat=books%27%20OR%201=1-- HTTP/1.1" 403 162 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
```
Analysis: WAF or application validation rule intercepted the payload `books' OR 1=1--` and returned HTTP 403 Forbidden. Minimal risk.

Event 3 - SQL Injection Exploited (HTTP 200):
```text
185.220.101.5 - - [09/Nov/2026:09:25:24 +0700] "GET /api/v1/products?cat=books%27%20UNION%20SELECT%20username,password_hash%20FROM%20users-- HTTP/1.1" 200 8450 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"
```
Analysis: The application processed the payload `' UNION SELECT username,password_hash FROM users--`, returning HTTP 200 OK and 8,450 bytes. Indicates successful data dump of user credential records.

## 4. Threat Intelligence & Artifact Triage
- Source IP: 185.220.101.5 (External Tor Exit Node / Public Scanning IP)
- User-Agent: `sqlmap/1.8.4` (Automated exploitation tool)
- Signature: Unsigned JWT and UNION-based SQLi

## 5. MITRE ATT&CK Mapping
- Tactic: Defense Evasion / Initial Access
- Technique IDs:
  - T1550.001 (Use Alternate Authentication Material: Application Access Token)
  - T1190 (Exploit Public-Facing Application)

## 6. Remediation & Containment Actions
- WAF: Updated ModSecurity ruleset to strictly reject all JWT headers containing `"alg":"none"`.
- Backend: Rewrote database queries on `/api/v1/products` using parameterized prepared statements (Pydantic / ORM).
- Invalidated all active sessions and forced credential reset for database user accounts.

## 7. Lessons Learned & Rule Tuning
- Distinct rule levels for HTTP 403 (Level 6) versus HTTP 200 (Level 12) enable SOC analysts to triage high-risk breaches instantly without wasting time on blocked reconnaissance traffic.

