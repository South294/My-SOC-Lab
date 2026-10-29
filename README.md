# 🛡️ Security Operations Center (SOC Tier 1) Detection & Triage Lab

> Hệ thống lab giám sát an ninh mạng và phản ứng sự cố tập trung vào các năng lực vận hành thực tế của SOC Tier 1: **Giám sát cảnh báo (Alert Monitoring & Triage)**, **Phân tích log tấn công (Detection Engineering)**, **Điều tra sự cố & Lập biên bản (Incident Investigation & Reporting)**, **Tự động hóa tra cứu chỉ số nguy hại (Threat Intelligence Scripting)** và **Tối ưu hóa luật phát hiện (SIEM Rule Tuning)**.

---

## 📌 1. Kiến trúc Hệ thống Giám sát (Lab Architecture)

Mô hình luồng dữ liệu giám sát an ninh mạng đa nền tảng kết nối về SIEM trung tâm:

```
                  ┌────────────────────────────────────────────────────────┐
                  │                 HỆ THỐNG GIÁM SÁT TRUNG TÂM             │
                  │              Wazuh SIEM (Manager + Dashboard)          │
                  │   - Correlate Alerts       - Custom Detection Rules    │
                  │   - Active Response        - Rule Tuning Engine        │
                  └───────────────────────────▲────────────────────────────┘
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      │ Log Streams (TCP/1514)                        │ Log Streams (TCP/1514)
                      │                                               │
    ┌─────────────────┴───────────────────┐       ┌───────────────────┴─────────────────┐
    │     MỤC TIÊU WEB & BIÊN (LINUX)     │       │     MÁY TRẠM ĐÍCH (WINDOWS 10)      │
    │  Ubuntu Server + Nginx Reverse Proxy│       │  Windows Workstation (Sysmon)       │
    │  ─────────────────────────────────  │       │  ─────────────────────────────────  │
    │  - Nginx Access/Error Logs          │       │  - Windows Security Logs (4624/4625)│
    │  - ModSecurity WAF (OWASP CRS)      │       │  - Sysmon Event ID 1 (Process)      │
    │  - Suricata NIDS (eve.json)         │       │  - Sysmon Event ID 13 (Registry)    │
    │  - OS Auth Log (SSH Failed/Success) │       │  - Sysmon Event ID 11 (File Create) │
    └─────────────────────────────────────┘       └─────────────────────────────────────┘
```

---

## 📂 2. Cấu trúc Dự án (Repository Structure)

```plaintext
My-SOC-Lab/
├── README.md                              # Tài liệu kiến trúc & hướng dẫn vận hành
├── PROJECT_PLAN.md                        # Nhật ký triển khai kỹ thuật toàn diện từ con số 0
├── deployment/
│   └── docker-compose.yml                 # Triển khai cụm Wazuh SIEM Single-Node
├── configurations/
│   ├── windows-agent/
│   │   ├── ossec.conf                     # Cấu hình Wazuh Agent thu thập Sysmon & Windows Events
│   │   └── sysmonconfig.xml               # Bộ lọc Sysmon giám sát Process, Network, Registry
│   ├── linux-web-agent/
│   │   └── ossec.conf                     # Cấu hình Agent đọc auth.log, nginx, ModSecurity & Suricata
│   └── siem-rules/
│       └── local_rules.xml                # Tập luật phát hiện tùy chỉnh & luật loại trừ (Tuning)
├── scripts/
│   └── triage_ioc_checker.py              # Công cụ dòng lệnh làm giàu dữ liệu qua AbuseIPDB & VirusTotal
├── sample-logs/                           # Dữ liệu log thô từ 4 kho dataset chuẩn quốc tế
│   ├── case1_modsec_sqli.log              # Nguồn: coreruleset/coreruleset & splunk/attack_data (T1190)
│   ├── case2_ssh_bruteforce.log           # Nguồn: logpai/loghub (OpenSSH) & splunk/attack_data (T1110.001)
│   ├── case3_sysmon_encoded_powershell.json # Nguồn: OTRF/Security-Datasets & sbousseaden/EVTX-ATTACK-SAMPLES
│   └── case4_sysmon_admin_false_positive.json # Nguồn: Windows 10 Task Scheduler Sysmon EventChannel
└── incident-reports/                      # Hồ sơ điều tra sự cố chuẩn SOC ITSM
    ├── Case-01-OWASP-SQLi-and-WAF-Triage.md
    ├── Case-02-SSH-BruteForce-ActiveResponse.md
    ├── Case-03-Windows-Encoded-PowerShell-Persistence.md
    └── Case-04-False-Positive-Alert-Tuning.md
```

---

## 🎯 3. Các Kịch bản Giám sát & Nguồn Dữ liệu Chuẩn (Use Cases & Datasets)

Dự án thiết lập 4 kịch bản giám sát trọng tâm với nguồn dữ liệu đối chiếu chuẩn ngành:

| Kịch bản | Bề mặt giám sát | Nguồn Dataset Chuẩn Quốc tế | Kết luận Triage | Hồ sơ sự cố |
| :--- | :--- | :--- | :---: | :--- |
| **Case 01** | **OWASP Top 10 SQLi & WAF**<br>Đối chiếu request bị chặn (403) và request thành công (200). | `coreruleset/coreruleset`<br>`splunk/attack_data` (T1190) | **True Positive (TP)** | [Case-01-Report](incident-reports/Case-01-OWASP-SQLi-and-WAF-Triage.md) |
| **Case 02** | **SSH Brute Force & Compromise**<br>Bắt chuỗi brute force tài khoản hợp lệ/không hợp lệ; kiểm tra Active Response. | `logpai/loghub` (OpenSSH_2k)<br>`splunk/attack_data` (T1110.001) | **True Positive (TP)** | [Case-02-Report](incident-reports/Case-02-SSH-BruteForce-ActiveResponse.md) |
| **Case 03** | **Windows Encoded PowerShell & Persistence**<br>Giải mã Base64 sang UTF-16LE, truy vết khóa Run Key Registry. | `OTRF/Security-Datasets` (Mordor)<br>`sbousseaden/EVTX-ATTACK-SAMPLES` | **True Positive (TP)** | [Case-03-Report](incident-reports/Case-03-Windows-Encoded-PowerShell-Persistence.md) |
| **Case 04** | **Điều tra Cảnh báo Giả & Tinh chỉnh Luật (Tuning)**<br>Xác minh tác vụ quản trị hệ thống hợp lệ, thiết lập luật `level="0"` triệt tiêu Alert Fatigue. | Windows 10 Task Scheduler Sysmon EventChannel (svchost.exe) | **False Positive (FP)** | [Case-04-Report](incident-reports/Case-04-False-Positive-Alert-Tuning.md) |

---

## 🛠️ 4. Công cụ Hỗ trợ Điều tra (Threat Intelligence Scripting)

Tệp [`scripts/triage_ioc_checker.py`](scripts/triage_ioc_checker.py) là công cụ dòng lệnh độc lập hỗ trợ quá trình làm giàu dữ liệu cảnh báo (Enrichment):
- Tự động nhận diện định dạng **IPv4** hoặc **File Hash (MD5/SHA256)**.
- Kết nối API v2 của **AbuseIPDB** để trích xuất điểm uy tín (Abuse Confidence Score), ISP và quốc gia.
- Kết nối API v3 của **VirusTotal** để kiểm tra tỷ lệ nhận diện độc hại từ các engine an ninh mạng.
- Tự động fallback về chế độ kiểm thử nội bộ khi hệ thống hoạt động trong mạng cô lập (Air-gapped) hoặc chưa nạp API key.

**Cú pháp thực thi:**
```bash
python scripts/triage_ioc_checker.py -i 203.0.113.45
python scripts/triage_ioc_checker.py -f 44d88612fea8a8f36de82e1278abb02f
```

---

## 🚀 5. Hướng dẫn Vận hành & Phương pháp Kiểm thử

### Bước 1: Khởi động Wazuh SIEM
Yêu cầu hệ thống cài đặt Docker và Docker Compose:
```bash
cd deployment/
docker compose up -d
```
Truy cập giao diện quản trị Wazuh Dashboard: `https://localhost:443` (Tài khoản mặc định: `admin` / Mật khẩu: `SecretPassword123!`).

### Bước 2: Kiểm thử luật phát hiện
- **Đối với log văn bản Linux/Web (Case 1 & Case 2):** Sử dụng tiện ích dòng lệnh `wazuh-logtest` có sẵn trong container:
  ```bash
  docker exec -it deployment-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
  ```
  Dán các dòng log từ `sample-logs/case1_modsec_sqli.log` hoặc `sample-logs/case2_ssh_bruteforce.log` để kiểm tra các giai đoạn Pre-decoding, Decoding và Rule Matching.
- **Đối với log Windows Sysmon (Case 3 & Case 4):** Do log Sysmon sử dụng cấu trúc `windows_eventchannel` nội bộ của Wazuh Agent với các trường phân nhánh `win.system.eventID` và `win.eventdata.*`, việc kiểm thử được thực hiện qua luồng thu thập EventChannel hoặc kiểm tra qua tệp nhật ký `archives.json` trong container thay vì dán chuỗi JSON phẳng vào `wazuh-logtest`.

---

## 💡 6. Chu trình Vận hành Chuẩn của SOC Tier 1 (SOC Operations Standard)

1. **Quy trình Initial Triage 5 bước:**
   - **Bước 1 (Ingestion & Verification):** Tiếp nhận cảnh báo, phân tích log JSON thô, trích xuất Rule ID và mức độ nghiêm trọng.
   - **Bước 2 (Field Extraction):** Bóc tách các trường dữ liệu quan trọng (`srcip`, `user`, `CommandLine`, `ParentImage`, `targetObject`).
   - **Bước 3 (Threat Enrichment):** Kiểm tra danh tiếng IOC trên AbuseIPDB / VirusTotal; giải mã các dòng lệnh obfuscated (Base64 UTF-16LE).
   - **Bước 4 (Classification):** Đối chiếu với quy trình vận hành tiêu chuẩn (SOP) và lịch sử phê duyệt thay đổi (Change Tickets) để đưa ra kết luận True Positive (TP) hoặc False Positive (FP).
   - **Bước 5 (Escalation & Tuning):** Khởi tạo ticket bàn giao kèm phương án xử lý ngắn hạn (Containment) lên Tier 2 nếu là TP; thiết lập luật loại trừ nếu là FP.

2. **Nguyên lý Tinh chỉnh Giảm nhiễu (Rule Tuning Strategy):**
   - Sử dụng thẻ `<if_sid>` kế thừa logic phát hiện từ luật cha.
   - Định nghĩa điều kiện thu hẹp bằng biểu thức chính quy PCRE2 trên các trường định danh an toàn (`win.eventdata.user`, `win.eventdata.parentImage`, `win.eventdata.commandLine`).
   - Gán `level="0"` để vô hiệu hóa việc tạo cảnh báo cho hành vi đã được kiểm chứng an toàn mà không làm ảnh hưởng đến khả năng phát hiện tấn công thật.
