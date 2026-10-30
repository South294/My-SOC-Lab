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
    print(f"\n[+] Checking IP reputation on AbuseIPDB: {ip}")
    if not ABUSEIPDB_API_KEY:
        print("[-] Error: ABUSEIPDB_API_KEY environment variable not set")
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
        print(f"[-] AbuseIPDB request failed: {e}")

def check_virustotal(ioc, ioc_type):
    print(f"\n[+] Checking {ioc_type.upper()} on VirusTotal: {ioc}")
    if not VT_API_KEY:
        print("[-] Error: VT_API_KEY environment variable not set")
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
        print(f"[-] VirusTotal request failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="SOC Triage IOC Reputation Checker")
    parser.add_argument("-i", "--ip", help="IPv4 address to query")
    parser.add_argument("-f", "--hash", help="MD5/SHA1/SHA256 hash to query")
    args = parser.parse_args()

    target = args.ip or args.hash
    if not target:
        target = input("Enter IP address or File Hash: ").strip()

    if is_ip(target):
        check_abuseipdb(target)
        check_virustotal(target, "ip")
    elif is_hash(target):
        check_virustotal(target, "hash")
    else:
        print(f"[-] Invalid input: '{target}'")

if __name__ == "__main__":
    main()
