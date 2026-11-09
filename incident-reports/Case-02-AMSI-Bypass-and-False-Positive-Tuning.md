# INCIDENT INVESTIGATION REPORT: AMSI BYPASS & FALSE POSITIVE TUNING (T1562.001)

## 1. Ticket Information
- Incident ID: INC-202611-002
- Priority: P2 - High (True Positive) / P4 - Low (False Positive Tuning)
- Classification: True Positive (Attack) vs. False Positive (Maintenance Whitelist)
- Status: Closed / Tuned
- Assignee: SOC Tier 1 Analyst
- Target Host: Windows 11 Enterprise (DESKTOP-O7NQ6VH)
- Detector: Wazuh Manager (Rule 100201 & Rule 100202)

## 2. Executive Summary (SBAR Framework)
- Situation: Detection alert triggered on PowerShell execution utilizing evasion flags and in-memory AMSI tampering strings. Followed by analysis of repetitive alert triggers from scheduled maintenance tasks.
- Background: Antimalware Scan Interface (AMSI) is an interface standard allowing applications to integrate with antivirus engines. Attackers routinely patch AmsiUtils in memory to evade detection.
- Assessment: Event 1 (attacker) represents a True Positive malicious script altering amsiInitFailed. Event 2 (Task Scheduler) represents a False Positive caused by legitimate system scripts using hidden window styles.
- Recommendation: Maintain high-severity detection for unauthorized PowerShell evasion while implementing precise parent-process whitelisting for authorized administrative scripts.

## 3. Log Evidence & Analysis

True Positive Malicious Event:
```json
{"UtcTime":"2026-11-09 09:18:45.891","EventID":1,"Computer":"DESKTOP-O7NQ6VH","ProcessGuid":"{3a7f82b1-6c6d-672e-8507-000000001a00}","ProcessId":9340,"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","FileVersion":"10.0.22621.3085","CommandLine":"powershell.exe -NoP -NonI -w hidden -ep bypass -enc W1JlZl0uQXNzZW1ibHkuR2V0VHlwZSgnU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHMnKS5HZXRGaWVsZChgJ2Ftc2lJbml0RmFpbGVkYCcsJ05vblB1YmxpYyxTdGF0aWMnKS5TZXRWYWx1ZSgkbHVsbCwkdHJ1ZSk=","User":"DESKTOP-O7NQ6VH\\nam2945","ParentImage":"C:\\Windows\\System32\\cmd.exe"}
```
Decoded Base64 Payload:
`[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`
Analysis: In-memory reflection patching of `amsiInitFailed` forces the AMSI initialization check to return true, effectively bypassing real-time scanning for all subsequent commands executed in this session.

False Positive Benign Maintenance Event:
```json
{"UtcTime":"2026-11-09 09:20:00.015","EventID":1,"Computer":"DESKTOP-O7NQ6VH","ProcessGuid":"{3a7f82b1-6cb8-672e-a208-000000001a00}","ProcessId":6504,"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","FileVersion":"10.0.22621.3085","CommandLine":"powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File \"C:\\Windows\\System32\\HealthCheck_Maintenance.ps1\"","ParentImage":"C:\\Windows\\System32\\svchost.exe","User":"NT AUTHORITY\\SYSTEM"}
```
Analysis: The Task Scheduler service (svchost.exe Schedule) executes health checks under NT AUTHORITY\SYSTEM. Because it uses `-WindowStyle Hidden` and `-ExecutionPolicy Bypass`, it matches Rule 100201.

## 4. Threat Intelligence & Artifact Triage
- SHA256: D83372C2B40F3C5E2326B722894E4F8145F8902E97A8F21D98A2E57A0C8C3A12 (Legitimate Microsoft powershell.exe binary misused as LOLBIN).
- Technique Signature: Memory manipulation of `AmsiUtils`.

## 5. MITRE ATT&CK Mapping
- Tactic: Defense Evasion / Execution
- Technique ID: T1562.001 (Impair Defenses: Disable or Modify Tools), T1059.001 (PowerShell)

## 6. Remediation & Containment Actions
- Terminated the interactive command prompt and suspicious PowerShell process tree.
- Isolated workstation to prevent staged payload download.
- Cleared temporary files and analyzed scheduled task triggers.

## 7. Tuning & Alert Fatigue Mitigation
Implemented Rule 100202 with level="0":
- Condition 1: ParentImage is `\\svchost.exe`
- Condition 2: User is `NT AUTHORITY\SYSTEM`
- Condition 3: CommandLine ends with `HealthCheck_Maintenance.ps1`
Result: Legitimate maintenance executions are suppressed, eliminating false alarms without reducing sensitivity to malicious evasion scripts.

Verification Evidence via `wazuh-logtest`:
```plaintext
$ docker exec -i my-soc-lab-main-wazuh.manager-1 /var/ossec/bin/wazuh-logtest < datasets/windows_amsi_benign.json

**Phase 1: Completed pre-decoding.
**Phase 2: Completed decoding.
	decoder: 'json'
	EventID: '1'
	Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
	CommandLine: 'powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\Windows\System32\HealthCheck_Maintenance.ps1"'
	ParentImage: 'C:\Windows\System32\svchost.exe'
	User: 'NT AUTHORITY\SYSTEM'

**Phase 3: Completed filtering (rules).
	id: '100202'
	level: '0'
	description: 'Tuning: Whitelist scheduled Windows maintenance script'
	groups: '['local', 'custom_soc_lab']'
```

