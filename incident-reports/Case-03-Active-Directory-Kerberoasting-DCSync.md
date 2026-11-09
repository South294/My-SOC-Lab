# INCIDENT INVESTIGATION REPORT: ACTIVE DIRECTORY KERBEROASTING & DCSYNC (T1558.003, T1003.006)

## 1. Ticket Information
- Incident ID: INC-202611-003
- Priority: P1 - Critical
- Classification: True Positive
- Status: Closed / Remediated
- Assignee: SOC Tier 1 Analyst
- Target Host: Active Directory Domain Controller (CORP.LOCAL)
- Detector: Wazuh Manager (Rule 100301 & Rule 100302)

## 2. Executive Summary (SBAR Framework)
- Situation: Sequential detections indicating Kerberos TGS ticket request with deprecated RC4 encryption followed by directory replication synchronization from a non-DC account.
- Background: Kerberoasting allows offline cracking of service account passwords when weak encryption (RC4 0x17) is requested. DCSync leverages directory replication rights to harvest domain credential hashes.
- Assessment: Attacker compromised domain account `t.nguyen` and initiated Kerberoasting against service `svc_sqlengine`, subsequently executing a DCSync attack to replicate domain secrets.
- Recommendation: Reset service account passwords, disable RC4 encryption across Kerberos policies, and audit Extended Rights for Replicating Directory Changes.

## 3. Log Evidence & Analysis

Phase 1 - Kerberoasting (Event ID 4769):
```json
{"UtcTime":"2026-11-09 09:22:04.519","EventID":4769,"Computer":"DC01.corp.local","TargetUserName":"t.nguyen@CORP.LOCAL","TargetDomainName":"CORP.LOCAL","ServiceName":"svc_sqlengine","ServiceSid":"S-1-5-21-3457937927-2839227994-823803824-2104","TicketOptions":"0x40810000","TicketEncryptionType":"0x17","IpAddress":"::ffff:192.168.10.45","IpPort":"54122","Status":"0x0"}
```
Analysis:
- `ServiceName` identifies a specific user-configured SPN (`svc_sqlengine`), not the `krbtgt` account.
- `TicketEncryptionType == 0x17` indicates the client explicitly requested RC4-HMAC instead of AES-256 (0x12). RC4 hashes are susceptible to fast offline dictionary attacks.
- Note: Legitimate TGS requests for `krbtgt` with `TicketEncryptionType: 0x12` in the dataset were properly evaluated and ignored by Rule 100301.

Phase 2 - DCSync Replication (Event ID 4662):
```json
{"UtcTime":"2026-11-09 09:22:18.742","EventID":4662,"Computer":"DC01.corp.local","SubjectUserSid":"S-1-5-21-3457937927-2839227994-823803824-1145","SubjectUserName":"t.nguyen","SubjectDomainName":"CORP","SubjectLogonId":"0x29f41b","ObjectServer":"DS","ObjectType":"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}","ObjectName":"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}","HandleId":"0x0","AccessList":"%%7688","AccessMask":"0x100","Properties":"%%7688\t{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}\t{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}\t{19195a5b-6da0-11d0-afd3-00c04fd930c9}"}
```
Analysis:
- `ObjectName` corresponds to domainDNS (`%{19195a5b-6da0-11d0-afd3-00c04fd930c9}`).
- GUID `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` in `Properties` corresponds to `DS-Replication-Get-Changes-All`.
- `SubjectUserName` is `t.nguyen` (does not end with `$`), proving the request originated from a standard user account rather than a legitimate replication partner Domain Controller (`DC02$`).

## 4. Threat Intelligence & Artifact Triage
- Source IP: 192.168.10.45 (Internal workstation in subnet VLAN 10)
- Account Identified: `t.nguyen` (Compromised domain credentials)
- Targeted Account: `svc_sqlengine` (MSSQL Service Principal Name)

## 5. MITRE ATT&CK Mapping
- Tactic: Credential Access
- Technique IDs:
  - T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)
  - T1003.006 (OS Credential Dumping: DCSync)

## 6. Remediation & Containment Actions
- Disabled the compromised user account `t.nguyen`.
- Forced immediate password change for service account `svc_sqlengine` with 30+ character complex passphrase.
- Revoked all unauthorized `DS-Replication` extended permissions granted to standard users.
- Enforced Group Policy requiring AES-128 and AES-256 encryption types for Kerberos tickets.

## 7. Lessons Learned & Rule Tuning
- Rule 100301 and 100302 properly filtered machine accounts with trailing `$` to eliminate false positives from legitimate inter-DC replication.

