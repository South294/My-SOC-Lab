import os
import re
import sys
import argparse
import urllib.request
import urllib.error
import json

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

def is_ip(val):
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(pattern, val.strip()))

def is_hash(val):
    val = val.strip()
    return len(val) in (32, 40, 64) and bool(re.match(r"^[a-fA-F0-9]+$", val))

def check_abuseipdb(ip):
    print(f"\n[+] Tra cuu IP tren AbuseIPDB: {ip}")
    if not ABUSEIPDB_API_KEY:
        print("  [!] Khong co ABUSEIPDB_API_KEY. Che do Lab Simulation:")
        if ip in ("203.0.113.45", "198.51.100.23"):
            print("  - Abuse Confidence Score : 100% [MALICIOUS / HIGH RISK]")
            print("  - ISP / Country          : Suspicious Host / CN")
            print("  - Total Reports          : 1,420 reports (SSH Brute Force, Scanning)")
        else:
            print("  - Abuse Confidence Score : 0% [CLEAN / BENIGN]")
        return

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode()).get("data", {})
            print(f"  - Abuse Confidence Score : {data.get('abuseConfidenceScore', 0)}%")
            print(f"  - ISP / Country          : {data.get('isp')} / {data.get('countryCode')}")
            print(f"  - Total Reports          : {data.get('totalReports', 0)} reports")
    except Exception as e:
        print(f"  [-] Loi ket noi AbuseIPDB: {e}")

def check_virustotal(ioc, ioc_type):
    print(f"\n[+] Tra cuu {ioc_type.upper()} tren VirusTotal: {ioc}")
    if not VT_API_KEY:
        print("  [!] Khong co VT_API_KEY. Che do Lab Simulation:")
        if ioc_type == "hash" or ioc in ("198.51.100.23", "44d88612fea8a8f36de82e1278abb02f"):
            print("  - Detection Rate         : 58/72 security vendors flagged as MALICIOUS")
            print("  - Threat Classification  : Trojan:PowerShell/RevShell.A, CobaltStrike")
        else:
            print("  - Detection Rate         : 0/72 [Clean / Undetected]")
        return

    endpoint = "ip_addresses" if ioc_type == "ip" else "files"
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}"
    headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode()).get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            print(f"  - Detection Rate         : {malicious}/{total} security vendors flagged as malicious")
    except Exception as e:
        print(f"  [-] Loi ket noi VirusTotal: {e}")

def main():
    parser = argparse.ArgumentParser(description="SOC Triage IOC Reputation Checker")
    parser.add_argument("-i", "--ip", help="Dia chi IPv4")
    parser.add_argument("-f", "--hash", help="Ma Hash MD5 hoac SHA256")
    args = parser.parse_args()

    target = args.ip or args.hash
    if not target:
        print("=" * 60)
        print("       SOC ANALYST - QUICK IOC TRIAGE CHECKER")
        print("=" * 60)
        target = input("Nhap dia chi IP hoac File Hash can tra cuu: ").strip()

    if is_ip(target):
        check_abuseipdb(target)
        check_virustotal(target, "ip")
    elif is_hash(target):
        check_virustotal(target, "hash")
    else:
        print(f"[-] Gia tri nhap khong hop le: '{target}'. Hay nhap IP hoac Hash hop le.")

if __name__ == "__main__":
    main()
