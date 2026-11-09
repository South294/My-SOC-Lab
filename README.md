# 🛡️ My-SOC-Lab: Multi-Layer Detection Engineering & SOC Triage Lab

Hệ thống SIEM giám sát an ninh mạng, phát hiện tấn công đa tầng và điều tra sự cố vận hành độc lập trên nền tảng Wazuh SIEM, Docker Desktop và Ubuntu WSL2. Lab cung cấp năng lực giám sát tập trung từ tầng container, hệ điều hành (Linux/Windows), dịch vụ xác thực Active Directory đến ứng dụng Web API.

---

## 📌 1. Cách Hoạt Động (How It Works)

### Luồng Dữ Liệu (Data Pipeline)
1. **Sinh / Bơm dữ liệu (Log Generation):** Các kịch bản tấn công thực tế và dữ liệu mẫu được bơm vào thư mục chia sẻ `shared-logs/` thông qua script `scripts/feed_logs.sh`.
2. **Thu thập & Giải mã (Log Ingestion & Decoding):** Wazuh Manager gắn kết thư mục `shared-logs/` (mount đọc chỉ đọc `:ro` vào `/var/log/datasets/`), tự động giải mã các định dạng Syslog, Nginx access log và Sysmon JSON.
3. **Phân tích & Cảnh báo (Detection Engine):** Wazuh Analysis Engine đối soát dữ liệu với bộ quy tắc tùy chỉnh `rules/local_rules.xml` để kích hoạt cảnh báo theo mức độ nghiêm trọng (Level 0 - 13) và ánh xạ kỹ thuật MITRE ATT&CK.
4. **Lưu trữ & Trực quan hóa (Indexing & Dashboard):** Cảnh báo được gửi qua Filebeat bảo mật TLS tới Wazuh Indexer (OpenSearch) và hiển thị trực quan trên Wazuh Dashboard tại `https://localhost`.
5. **Điều tra Sự Cố (Triage & Threat Intel):** Nhà phân tích SOC sử dụng script `scripts/triage_ioc_checker.py` để tự động tra cứu danh tiếng IP/Hash qua AbuseIPDB và VirusTotal (tích hợp cơ chế bỏ qua dải IP riêng tư RFC 1918).

```plaintext
[ Ubuntu WSL2 / Test Environment ]
       │
       ▼ (Bơm log thời gian thực)
[ shared-logs/ ]
 ├── linux_auth.log       ──► Sudo / Linux Syslog
 ├── windows_sysmon.json  ──► Sysmon & Active Directory Security Events
 └── web_access.log       ──► Nginx Combined Web Access Log
       │
       ▼ (Docker Volume Mount :ro)
[ Wazuh Manager Container ] ──► Đối soát rules/local_rules.xml
       │
       ▼ (Filebeat TLS)
[ Wazuh Indexer (OpenSearch) ]
       │
       ▼
[ Wazuh Dashboard (Port 443) ]
```

---

## 🎯 2. Các Kịch Bản Phát Hiện (Detection Scenarios)

| Kịch bản | Kỹ thuật phát hiện | Mức cảnh báo | MITRE ATT&CK |
| :--- | :--- | :--- | :--- |
| **1. Docker Container Escape** | Nhận diện lệnh `nsenter --target 1` can thiệp namespace máy chủ vật lý từ container đặc quyền | Level 13 (Critical) | **T1611** |
| **2. APT AMSI In-Memory Bypass** | Phát hiện tiến trình PowerShell chạy cờ ẩn (`-w hidden`, `-ep bypass`, `-enc`) can thiệp `AmsiUtils.amsiInitFailed` | Level 12 (High) | **T1562.001**, **T1059.001** |
| **2b. Rule Tuning Whitelist** | Triệt tiêu cảnh báo giả từ tác vụ Task Scheduler (`svchost.exe` + `SYSTEM` + `HealthCheck_Maintenance.ps1`) | Level 0 (Tuned) | **FP Mitigation** |
| **3a. AD Kerberoasting** | Phát hiện yêu cầu cấp vé Kerberos TGS (Event 4769) hạ cấp mã hóa về RC4 `0x17` | Level 10 (Warning) | **T1558.003** |
| **3b. AD DCSync Attack** | Phát hiện Event 4662 chứa quyền nhân bản miền `DS-Replication-Get-Changes-All` từ tài khoản người dùng thường | Level 13 (Critical) | **T1003.006** |
| **4a. JWT Algorithm None** | Nhận diện chuỗi token JWT không chữ ký `{"alg":"none"}` (`eyJhbGciOiJub25l...`) trên query string URI | Level 11 (High) | **T1550.001** |
| **4b. OWASP SQLi Triage** | Phân loại giữa thăm dò bị chặn (HTTP 403 - Level 6) và khai thác thành công trích xuất dữ liệu (HTTP 200 - Level 12) | Level 6 vs. Level 12 | **T1190** |

---

## 📂 3. Cấu Trúc Dự Án

```plaintext
My-SOC-Lab/
├── docker-compose.yml              # Khởi chạy cụm Wazuh Single-Node (Manager, Indexer, Dashboard)
├── config/                         # Cấu hình chứng chỉ SSL nội bộ, ossec.conf và indexer
├── rules/
│   └── local_rules.xml             # 9 rule phát hiện chuyên sâu và tinh chỉnh giảm nhiễu
├── datasets/                       # 5 bộ dữ liệu log tấn công thực tế
├── shared-logs/                    # Thư mục đệm chuyển tiếp log giữa WSL2 và Wazuh Manager
├── scripts/
│   ├── feed_logs.sh                # Script bơm dữ liệu vào shared-logs/ theo từng kịch bản
│   └── triage_ioc_checker.py       # Công cụ tra cứu Threat Intelligence (AbuseIPDB, VirusTotal)
└── incident-reports/               # 4 biên bản điều tra sự cố chi tiết theo chuẩn SBAR
```

---

## 🚀 4. Hướng Dẫn Vận Hành

### Bước 1: Khởi động cụm SIEM
```powershell
docker compose up -d
docker compose restart wazuh.manager
docker exec my-soc-lab-main-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t
```
Truy cập giao diện Web Dashboard tại `https://localhost` (Tài khoản: `admin` / Mật khẩu: `SecretPassword`).

### Bước 2: Bơm dữ liệu kiểm thử (Trên Ubuntu WSL2)
```bash
cd /mnt/c/Users/Admin/Downloads/My-SOC-Lab-main
sed -i 's/\r$//' scripts/*.sh datasets/* rules/local_rules.xml

# Bơm log theo từng kịch bản:
bash scripts/feed_logs.sh docker       # Kịch bản 1: Docker Container Escape (Replay log)
bash scripts/feed_logs.sh docker_live  # Kịch bản 1: Sinh tấn công trực tiếp qua Docker runtime trên WSL2
bash scripts/feed_logs.sh amsi         # Kịch bản 2: AMSI Bypass
bash scripts/feed_logs.sh amsi_benign  # Kịch bản 2b: Kiểm tra Rule Tuning Whitelist (Level 0)
bash scripts/feed_logs.sh ad           # Kịch bản 3: AD Kerberoasting & DCSync
bash scripts/feed_logs.sh jwt          # Kịch bản 4: JWT alg:none & SQL Injection Triage

# Hoặc bơm toàn bộ kịch bản cùng lúc:
bash scripts/feed_logs.sh all
```

Kiểm tra bằng chứng Rule Tuning triệt tiêu cảnh báo giả qua `wazuh-logtest`:
```bash
docker exec -i my-soc-lab-main-wazuh.manager-1 /var/ossec/bin/wazuh-logtest < datasets/windows_amsi_benign.json
```

### Bước 3: Tra cứu Threat Intelligence
```bash
export VT_API_KEY="your_virustotal_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"

python3 scripts/triage_ioc_checker.py -i 192.168.1.100  # IP nội bộ -> Tự động bỏ qua theo RFC 1918
python3 scripts/triage_ioc_checker.py -i 185.220.101.5   # IP độc hại C2 / Tor Exit Node
python3 scripts/triage_ioc_checker.py -f 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f # Hash mẫu EICAR
```
