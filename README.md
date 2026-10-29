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
├── sample-logs/                           # Dữ liệu log mẫu chuẩn ngành để kiểm thử SIEM
│   ├── case1_modsec_sqli.log              # Log Nginx HTTP 403 vs 200 & ModSecurity WAF audit log
│   ├── case2_ssh_bruteforce.log           # Log Linux auth.log chuỗi SSH Brute Force & chiếm quyền
│   ├── case3_sysmon_encoded_powershell.json # Log Sysmon Event 1 & 13 lệnh PowerShell mã hóa Base64
│   └── case4_sysmon_admin_false_positive.json # Log tác vụ sao lưu hợp lệ kiểm tra bộ lọc
└── incident-reports/                      # Hồ sơ điều tra sự cố chuẩn SOC ITSM
    ├── Case-01-OWASP-SQLi-and-WAF-Triage.md
    ├── Case-02-SSH-BruteForce-ActiveResponse.md
    ├── Case-03-Windows-Encoded-PowerShell-Persistence.md
    └── Case-04-False-Positive-Alert-Tuning.md
```

---

## 🎯 3. Các Kịch bản Giám sát & Điều tra (Use Cases)

Dự án thiết lập 4 kịch bản giám sát trọng tâm với đầy đủ hồ sơ kỹ thuật:

| Kịch bản | Phạm vi điều tra | Nguồn Log & Công nghệ | Kết luận Triage | Hồ sơ sự cố |
| :--- | :--- | :--- | :---: | :--- |
| **Case 01** | **OWASP Top 10 SQLi & WAF**<br>Đối chiếu request bị chặn (403) và request khai thác thành công (200). | Nginx Access Log, ModSecurity CRS | **True Positive (TP)** | [Case-01-Report](incident-reports/Case-01-OWASP-SQLi-and-WAF-Triage.md) |
| **Case 02** | **SSH Brute Force & Compromise**<br>Nhận diện chuỗi dò mật khẩu kèm đăng nhập thành công; xác thực cơ chế chặn tự động Active Response. | Linux `/var/log/auth.log`, Wazuh Active Response | **True Positive (TP)** | [Case-02-Report](incident-reports/Case-02-SSH-BruteForce-ActiveResponse.md) |
| **Case 03** | **Windows Encoded PowerShell & Persistence**<br>Giải mã Base64 sang UTF-16LE, truy vết hành vi cắm chốt khởi động tại Run Key Registry. | Sysmon Event ID 1 & 13, VirusTotal | **True Positive (TP)** | [Case-03-Report](incident-reports/Case-03-Windows-Encoded-PowerShell-Persistence.md) |
| **Case 04** | **Điều tra Cảnh báo Giả & Tinh chỉnh Luật (Tuning)**<br>Xác minh tác vụ quản trị hệ thống hợp lệ, thiết lập luật `level="0"` triệt tiêu Alert Fatigue. | Sysmon Event ID 1, IT Change Ticket #CHG-8921 | **False Positive (FP)** | [Case-04-Report](incident-reports/Case-04-False-Positive-Alert-Tuning.md) |

---

## 🛠️ 4. Công cụ Hỗ trợ Điều tra (Threat Intelligence Scripting)

Tệp [`scripts/triage_ioc_checker.py`](scripts/triage_ioc_checker.py) là công cụ dòng lệnh độc lập hỗ trợ quá trình làm giàu dữ liệu cảnh báo (Enrichment):
- Tự động nhận diện định dạng **IPv4** hoặc **File Hash (MD5/SHA256)**.
- Kết nối API v2 của **AbuseIPDB** để trích xuất điểm uy tín (Abuse Confidence Score), ISP và quốc gia.
- Kết nối API v3 của **VirusTotal** để kiểm tra tỷ lệ nhận diện độc hại từ các engine an ninh mạng.
- Tự động fallback về chế độ kiểm thử nội bộ khi hệ thống hoạt động trong mạng cô lập (Air-gapped) hoặc chưa nạp API key.

**Cú pháp thực thi:**
```bash
# Tra cứu danh tiếng địa chỉ IP
python scripts/triage_ioc_checker.py -i 203.0.113.45

# Tra cứu mã Hash tệp thực thi
python scripts/triage_ioc_checker.py -f 44d88612fea8a8f36de82e1278abb02f
```

---

## 🚀 5. Hướng dẫn Vận hành & Kiểm thử (Quickstart)

### Bước 1: Khởi động Wazuh SIEM
Yêu cầu hệ thống cài đặt Docker và Docker Compose:
```bash
cd deployment/
docker compose up -d
```
Truy cập giao diện quản trị Wazuh Dashboard: `https://localhost:443` (Tài khoản mặc định: `admin` / Mật khẩu: `SecretPassword123!`).

### Bước 2: Kiểm thử luật phát hiện bằng `wazuh-logtest`
Wazuh cung cấp tiện ích `wazuh-logtest` cho phép kiểm tra trực tiếp khả năng nhận diện của luật đối với các sự kiện log thô:
```bash
# Truy cập vào container Wazuh Manager
docker exec -it deployment-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```
Sau đó dán nội dung log từ thư mục [`sample-logs/`](sample-logs/) để kiểm tra chuỗi giải mã (Decoder) và mã luật (Rule ID) được kích hoạt.

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
   - Định nghĩa điều kiện thu hẹp bằng biểu thức chính quy PCRE2 trên các trường định danh an toàn (`win.eventdata.user`, `win.eventdata.commandLine`).
   - Gán `level="0"` để vô hiệu hóa việc tạo cảnh báo cho hành vi đã được kiểm chứng an toàn mà không làm ảnh hưởng đến khả năng phát hiện tấn công thật.
