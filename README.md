# SOC Triage Toolkit (SIEM Lab & Triage Dashboard)

SOC Triage Toolkit là lab mô phỏng quy trình xử lý cảnh báo cho SOC Analyst Tier 1, tập trung vào phân tích log, triage alert, decoding, rule tuning và tạo report.

Dự án giúp trả lời nhanh 4 câu hỏi cốt lõi của một SOC Analyst L1 khi tiếp nhận cảnh báo:
1. Cảnh báo này là gì?
2. Có thật hay giả (True/False Positive)?
3. Nên xử lý thế nào?
4. Ghi lại thành ticket/report ra sao?

---

## Khối A — Overview

- **Mục tiêu:** Mô phỏng quy trình vận hành thực tế của một trung tâm giám sát an ninh mạng (SOC) ở mức độ L1, giảm thiểu tình trạng mệt mỏi vì cảnh báo giả (Alert Fatigue) thông qua kỹ thuật tinh chỉnh luật (Rule Tuning).
- **Giải quyết vấn đề:** Giúp Analyst L1 thực hành phân loại cảnh báo, trích xuất chỉ số độc hại (IOC), giải mã lệnh che giấu và viết báo cáo sự cố chuẩn hóa Markdown.
- **Tech Stack:**
  - SIEM: Wazuh Manager 4.7.2 (Docker)
  - Endpoint Agent: Wazuh Agent + Windows Sysmon
  - Web UI: HTML, CSS, JavaScript (Bảng Triage & Phân tích độc lập)
  - Detection Framework: MITRE ATT&CK

---

## Khối B — Data Pipeline

Luồng xử lý dữ liệu từ endpoint đến báo cáo cuối cùng:
```
[Log Source] (Windows Event / Sysmon)
     │
     ▼
[Parse & Detect] (Wazuh Rules Matching & MITRE Mapping)
     │
     ▼
[Enrichment] (IP Reputation Lookup / PowerShell UTF-16LE Decode)
     │
     ▼
[Classification] (SOP Reference -> True Positive / False Positive Decision)
     │
     ▼
[Response Action] ───► [TP] Containment & Escalation
     │                └──► [FP] SIEM Rule Tuning (Exclude Safe Regex)
     ▼
[Incident Report] (Export Markdown Report & Close Ticket)
```

---

## Khối C — Detection Use Cases

Hệ thống triển khai 5 use case phát hiện trọng tâm:

### 1. SMB Brute Force
- **Phát hiện:** Nhiều lần đăng nhập thất bại liên tiếp qua dịch vụ chia sẻ file SMB.
- **Log Source:** Windows Security Event ID 4625.
- **Rule Phát hiện:** Wazuh Rule ID `100001` (Level 10).
- **IOC cần nhìn:** Địa chỉ IP nguồn (`ipAddress`), tài khoản đích (`targetUserName`), tần suất đăng nhập lỗi.
- **Triage:** Xác minh IP nguồn có thuộc dải IP quản trị hoặc máy của người dùng hợp lệ bị gõ sai mật khẩu (FP) hay không.
- **Hành động:** Nếu là TP, block IP nguồn trên Firewall, kiểm tra Event 4624 (đăng nhập thành công) của tài khoản đó.

### 2. PowerShell Encoded Command
- **Phát hiện:** Tiến trình PowerShell chạy với tham số che giấu command line bằng mã hóa Base64.
- **Log Source:** Sysmon Event ID 1 (Process Creation).
- **Rule Phát hiện:** Wazuh Rule ID `100004` (Level 10).
- **IOC cần nhìn:** Chuỗi `-EncodedCommand` hoặc `-enc` trong CommandLine.
- **Triage:** Giải mã chuỗi Base64 sang văn bản rõ UTF-16LE, quét tìm từ khóa độc hại (IEX, DownloadString, URLs lạ).
- **Hành động:** Nếu chứa payload độc hại (TP), cô lập máy (Isolate Host) và kết thúc tiến trình PowerShell.

### 3. Registry Run Key Persistence
- **Phát hiện:** Ghi nhận hành vi tạo hoặc sửa đổi Registry Run Key để duy trì quyền truy cập khi máy khởi động lại.
- **Log Source:** Sysmon Event ID 12/13 (Registry Event).
- **Rule Phát hiện:** Wazuh Rule ID `100003` (Level 10).
- **IOC cần nhìn:** Đường dẫn khóa (`targetObject`), tệp thực thi đích (`details`).
- **Triage:** Kiểm tra tệp thực thi đích có nằm trong thư mục tạm (`Temp`, `Public`, `Downloads`) hay không.
- **Hành động:** Nếu là TP, xóa khóa Registry và tệp thực thi tương ứng, kích hoạt Full Scan Antivirus.

### 4. Suspicious File Download
- **Phát hiện:** Tệp thực thi (.exe, .dll, .ps1) được tạo ra trong các thư mục tạm.
- **Log Source:** Sysmon Event ID 11 (File Create).
- **Rule Phát hiện:** Wazuh Rule ID `100005` (Level 11).
- **IOC cần nhìn:** Tên tệp (`targetFilename`), tiến trình tải (`image` như curl.exe, powershell.exe).
- **Triage:** Tính toán Hash SHA256 của tệp và tra cứu danh tiếng trên VirusTotal.
- **Hành động:** Xóa tệp độc hại ngay lập tức; kiểm tra xem tệp đã từng được thực thi (Sysmon ID 1) chưa.

### 5. Shadow Copy Deletion
- **Phát hiện:** Lệnh xóa bản sao lưu hệ thống (Shadow Copies), hành vi đặc trưng của Ransomware nhằm ngăn cản phục hồi dữ liệu.
- **Log Source:** Sysmon Event ID 1 (Process Creation).
- **Rule Phát hiện:** Wazuh Rule ID `100002` (Level 12).
- **IOC cần nhìn:** CommandLine chứa `vssadmin.exe delete shadows` hoặc `wmic shadowcopy delete`.
- **Triage:** Xác định tiến trình cha và tài khoản thực thi. Đây luôn là cảnh báo mức độ Critical cần xử lý khẩn cấp.
- **Hành động:** Cô lập mạng thiết bị ngay lập tức, kết thúc tiến trình cha đáng ngờ.

---

## Khối D — Response Playbooks

Quy trình phản ứng sự cố chuẩn hóa (SOP):

1. **Verify:** Phân tích log thô JSON, xác định Event ID và các trường chính.
2. **Scope:** Trích xuất IOCs (IP, Tiến trình, Tài khoản), tra cứu danh tiếng hoặc giải mã payload.
3. **Contain:** Cô lập thiết bị, ngắt tiến trình hoặc vô hiệu hóa tài khoản.
4. **Eradicate:** Loại bỏ tệp độc hại, khôi phục Registry bị thay đổi.
5. **Report:** Ghi nhận xử lý và xuất báo cáo sự cố (Markdown).

---

## Khối E — Tuning & Report

### 1. Giảm False Positive (Rule Tuning)
Khi phát hiện cảnh báo giả, Analyst viết luật ngoại trừ trên Wazuh Manager:
- Dùng `<if_sid>` kế thừa rule gốc.
- Dùng `<field>` kết hợp biểu thức chính quy (Regex) để loại bỏ đối tượng an toàn.
- **Hiệu quả:** Giảm nhiễu hiệu quả, chỉ tập trung vào cảnh báo thực sự quan trọng.

### 2. Gắn MITRE ATT&CK & Incident Report
Báo cáo sự cố xuất ra chứa:
- Phân loại sự cố (TP / FP).
- Liên kết kỹ thuật MITRE ATT&CK (T1110, T1027, v.v.).
- Kế hoạch phản ứng chi tiết.

---

## Khối F — Lab Deployment

### 1. Triển khai Wazuh Manager
```bash
cd deployment/
cp .env.example .env
docker-compose up -d
```

### 2. Cấu hình Windows Agent & Sysmon
- Cài đặt Wazuh Agent trên máy Windows đích, kết nối về Wazuh Manager IP. Áp dụng cấu hình đẩy log tại [ossec.conf](configurations/agent/ossec.conf).
- Cài đặt Sysmon trên máy Windows:
  ```cmd
  sysmon.exe -i configurations/agent/sysmonconfig.xml
  ```

### 3. Cập nhật Rules & Kiểm thử
- Copy nội dung luật custom tại [local_rules.xml](configurations/manager/local_rules.xml) vào thư mục cấu hình Wazuh Manager, restart dịch vụ Wazuh Manager.
- Sử dụng **Synthetic Event Generator** trên ứng dụng Web để tạo dữ liệu log mẫu nhằm kiểm tra và xác minh tính hoạt động của các luật phát hiện.
