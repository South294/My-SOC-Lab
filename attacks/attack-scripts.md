# ⚔️ Attack Simulation Scenarios

## Scenario 1: Brute Force Attack (SMB)
**Objective:** Trigger Active Response (Firewall Block).
**Tool:** Hydra (Kali Linux)
**Command:**
```bash
hydra -l Administrator -p wrongpass123 smb://<VICTIM_IP> -t 4
```

## Scenario 2: Malware Download
**Objective:** Trigger VirusTotal Integration (Level 12+ Alert).
**Tool:** PowerShell (Windows)
**Command:**
```powershell
Invoke-WebRequest -Uri "https://secure.eicar.org/eicar.com" -OutFile "C:\Users\Public\eicar_test.com"
```
