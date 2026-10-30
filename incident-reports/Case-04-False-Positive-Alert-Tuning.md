# INCIDENT INVESTIGATION REPORT: INC-2026-004
## False Positive Investigation & SIEM Detection Rule Tuning

---

### 1. THÔNG TIN CHUNG (INCIDENT METADATA)
| Thông tin | Chi tiết |
| :--- | :--- |
| **Ticket ID** | INC-2026-004 |
| **Mức độ ban đầu (Initial Severity)** | Medium (P3) / Rule Level 10 |
| **Trạng thái (Status)** | Closed as False Positive (FP) / Tuned |
| **Phân loại (Classification)** | **False Positive (FP - Authorized IT Task)** |
| **Người trực / Phân tích (Analyst)** | SOC Analyst Tier 1 |
| **Thời gian phát hiện** | 2026-10-30 14:40:00 (UTC+7) |
| **Nguồn log (Log Source)** | `shared-logs/windows_sysmon.json` (JSON Replay) |
| **Luật SIEM bị kích hoạt** | Rule ID `100301` (Suspicious PowerShell execution detected) |

---

### 2. TÓM TẮT SỰ CỐ (EXECUTIVE SUMMARY)
Cảnh báo mức độ 10 trên Wazuh SIEM được kích hoạt khi phát hiện tiến trình `powershell.exe` chạy với tham số `-ExecutionPolicy Bypass` và `-WindowStyle Hidden`.

Sau khi tiếp nhận cảnh báo, Analyst tiến hành điều tra:
1. Tài khoản thực thi: `DOMAIN\svc_backup` (Service Account dùng riêng cho sao lưu dữ liệu).
2. Tiến trình cha: `C:\Windows\System32\svchost.exe` (`svchost.exe -k netsvcs -p -s Schedule` - Windows Task Scheduler).
3. Tệp thực thi: `C:\Program Files\IT-Management\Backup_Routine.ps1` có chữ ký số nội bộ và trùng khớp mã hash trong kho IT.
4. Đối chiếu lịch trình IT: Khớp với Ticket bảo trì định kỳ `#CHG-8921`.

**Kết luận:** Cảnh báo được xác định là **False Positive (FP)**. Analyst đã viết luật loại trừ Rule `100401` với `level="0"` tại `rules/local_rules.xml` để triệt tiêu cảnh báo giả này.

---

### 3. BẰNG CHỨNG LOG CHI TIẾT
```json
{"EventID": "1", "UtcTime": "2026-10-30 07:40:00.005", "ProcessGuid": "{7c4a5a21-4321-8765-dcba-fe0987654321}", "ProcessId": "5120", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -WindowStyle Hidden -File \"C:\\Program Files\\IT-Management\\Backup_Routine.ps1\"", "CurrentDirectory": "C:\\Windows\\System32\\", "User": "DOMAIN\\svc_backup", "ParentProcessId": "1044", "ParentImage": "C:\\Windows\\System32\\svchost.exe", "ParentCommandLine": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule", "Hashes": "SHA256=3B5F6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B"}
```

---

### 4. LUẬT TINH CHỈNH ĐÃ ÁP DỤNG (RULE TUNING)
Thêm vào `rules/local_rules.xml`:
```xml
<rule id="100401" level="0">
  <if_sid>100301</if_sid>
  <field name="User" type="pcre2">(?i)^DOMAIN\\svc_backup$</field>
  <field name="ParentImage" type="pcre2">(?i)\\svchost\.exe$</field>
  <field name="CommandLine" type="pcre2">(?i)-File\s+\\?"C:\\Program Files\\IT-Management\\Backup_Routine\.ps1\\?"$</field>
  <description>Tuning: Whitelist authorized IT Backup Service account</description>
</rule>
```

#### Hiệu quả tinh chỉnh:
- Triệt tiêu 100% cảnh báo giả cho tác vụ sao lưu định kỳ của `DOMAIN\svc_backup`.
- Giữ nguyên khả năng kích hoạt của Rule `100301` khi kẻ tấn công thực thi PowerShell dưới quyền các tài khoản khác.

