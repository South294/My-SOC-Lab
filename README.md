# 🛡️ Security Operations Center (SOC Tier 1) Detection & Triage Lab

> Hệ thống lab giám sát an ninh mạng và phản ứng sự cố vận hành trên nền tảng **Docker Desktop (WSL2 Backend)** kết hợp **Wazuh Single-Node SIEM**. Hệ thống tối ưu hóa tài nguyên (tiêu thụ ~2GB - 2.5GB RAM), nạp trực tiếp dataset tấn công thực tế từ môi trường WSL2 qua thư mục mount `shared-logs/`, kiểm thử luật phát hiện theo thời gian thực và xử lý cảnh báo chuẩn SOC Tier 1.

---

## 📌 1. Kiến trúc Lab Tối ưu (WSL2 & Docker SIEM)

```
[ Windows 10/11 Host ]
 ├── Trình duyệt Web (https://localhost) ◄── Xem Alert, Lọc KQL & Điều tra
 └── Môi trường Ubuntu WSL2 (~/My-SOC-Lab)
      ├── Giới hạn RAM (.wslconfig)      ──► Khống chế trần 4GB RAM cho toàn bộ WSL2
      ├── Datasets Tấn công Thật         ──► datasets/ (OpenSSH, OWASP, Sysmon)
      ├── Script Bơm Log (feed_logs.sh)  ──► shared-logs/ ──(Mount)──► Container: wazuh.manager (/var/log/datasets/)
      └── Tập Luật Phát hiện & Tuning    ──► rules/local_rules.xml ──► (/var/ossec/etc/rules/)
```

---

## 📂 2. Cấu trúc Thư mục Dự án

```plaintext
My-SOC-Lab/
├── .wslconfig                             # Tệp cấu hình giới hạn RAM/CPU cho WSL2
├── README.md                              # Tài liệu kiến trúc & hướng dẫn vận hành
├── PROJECT_PLAN.md                        # Kế hoạch chi tiết và tiến trình xây dựng hệ thống
├── docker-compose.yml                     # Cụm Wazuh Single-Node (Indexer RAM 512m, mount logs & rules)
├── config/
│   └── wazuh_manager.conf                 # Cấu hình <localfile> đọc log từ /var/log/datasets/
├── rules/
│   └── local_rules.xml                    # Bộ luật phát hiện (Web SQLi, SSH Brute Force, Sysmon) & Tuning
├── shared-logs/                           # Điểm mount trực tiếp giữa WSL2 và Wazuh Manager
│   ├── web_access.log
│   ├── linux_auth.log
│   └── windows_sysmon.json
├── datasets/                              # Dữ liệu tấn công thô chuẩn quốc tế
│   ├── owasp_sqli.log                     # coreruleset & splunk/attack_data (T1190)
│   ├── openssh_bruteforce.log             # logpai/loghub & splunk/attack_data (T1110.001)
│   ├── windows_sysmon_execution.json      # OTRF/Security-Datasets (T1059.001)
│   └── windows_sysmon_benign.json         # Log quản trị hợp lệ dùng kiểm thử False Positive
├── scripts/
│   ├── feed_logs.sh                       # Script bash bơm log từ datasets vào shared-logs
│   └── triage_ioc_checker.py              # Script tra cứu IP/Hash qua AbuseIPDB và VirusTotal
└── incident-reports/                      # 4 hồ sơ điều tra sự cố chuẩn SOC ITSM
    ├── Case-01-OWASP-SQLi-and-WAF-Triage.md
    ├── Case-02-SSH-BruteForce-ActiveResponse.md
    ├── Case-03-Windows-Encoded-PowerShell-Persistence.md
    └── Case-04-False-Positive-Alert-Tuning.md
```

---

## ⚙️ 3. Thiết lập Hạ tầng & Tối ưu Tài nguyên

### Bước 1: Khống chế RAM trên Windows
Sao chép tệp `.wslconfig` vào thư mục người dùng Windows (`%UserProfile%\.wslconfig`):
```ini
[wsl2]
memory=4GB
processors=2
swap=2GB
```
Khởi động lại WSL trong PowerShell:
```cmd
wsl --shutdown
```

### Bước 2: Khởi động Wazuh SIEM
Tại thư mục dự án trên WSL hoặc terminal Windows:
```bash
docker compose up -d
```
Mở trình duyệt truy cập: `https://localhost` (Tài khoản mặc định: `admin` / Mật khẩu: `SecretPassword123!`).

---

## 🎯 4. Bơm Dữ liệu Tấn công & Bắt Cảnh báo (Live Testing)

Dùng script `scripts/feed_logs.sh` để đẩy log từ `datasets/` vào `shared-logs/` với độ trễ (delay) thực tế:

```bash
# 1. Bơm tấn công Web SQL Injection (ModSecurity WAF & Nginx)
bash scripts/feed_logs.sh web

# 2. Bơm tấn công SSH Brute Force (kích hoạt rule frequency 5 lần / 60 giây)
bash scripts/feed_logs.sh ssh

# 3. Bơm lệnh PowerShell mã hóa Base64 & Sysmon Event ID 1
bash scripts/feed_logs.sh sysmon

# 4. Bơm tác vụ quản trị hợp lệ để kiểm thử bộ lọc False Positive
bash scripts/feed_logs.sh benign
```

---

## 🔍 5. Lọc Cảnh báo trên Wazuh Dashboard & Tinh chỉnh Luật

### Lọc sự kiện trên giao diện (KQL Filters):
- Lọc theo nhóm luật custom: `rule.groups: "custom_soc_lab"`
- Lọc mức cảnh báo cao: `rule.level >= 10`
- Lọc theo kỹ thuật MITRE: `rule.mitre.id: "T1190"` hoặc `rule.mitre.id: "T1110.001"`

### Kiểm tra nhanh cấu trúc log bằng `wazuh-logtest`:
```bash
head -n 1 datasets/openssh_bruteforce.log | docker exec -i my-soc-lab-main-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

### Áp dụng luật mới sau khi sửa `rules/local_rules.xml`:
```bash
docker exec my-soc-lab-main-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

---

## 📊 6. Danh mục Kịch bản Điều tra (Use Cases)

| Kịch bản | Bề mặt giám sát | Nguồn Dataset | Phân loại | Báo cáo chi tiết |
| :--- | :--- | :--- | :---: | :--- |
| **Case 01** | Web SQLi & WAF Action | `coreruleset` & `splunk/attack_data` | True Positive | [Case-01-Report](incident-reports/Case-01-OWASP-SQLi-and-WAF-Triage.md) |
| **Case 02** | SSH Brute Force & Compromise | `logpai/loghub` & `splunk/attack_data` | True Positive | [Case-02-Report](incident-reports/Case-02-SSH-BruteForce-ActiveResponse.md) |
| **Case 03** | Encoded PowerShell & Persistence | `OTRF/Security-Datasets` & Sysmon | True Positive | [Case-03-Report](incident-reports/Case-03-Windows-Encoded-PowerShell-Persistence.md) |
| **Case 04** | False Positive & Rule Tuning | Windows 10 Task Scheduler Sysmon | False Positive | [Case-04-Report](incident-reports/Case-04-False-Positive-Alert-Tuning.md) |
