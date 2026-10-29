# INCIDENT INVESTIGATION REPORT: INC-2026-004
## False Positive Investigation & SIEM Detection Rule Tuning

---

### 1. THÔNG TIN CHUNG (INCIDENT METADATA)
| Thông tin | Chi tiết |
| :--- | :--- |
| **Ticket ID** | INC-2026-004 |
| **Mức độ ban đầu (Initial Severity)** | Medium (P3) / Rule Level 10 |
| **Trạng thái (Status)** | Closed as False Positive (FP) / Tuned |
| **Phân loại (Classification)** | False Positive (FP - Authorized IT Activity) |
| **Người trực / Phân tích (Analyst)** | SOC Analyst Tier 1 |
| **Thời gian phát hiện** | 2026-10-29 14:40:00 (UTC+7) |
| **Hệ thống cảnh báo (Target)** | `WIN10-WORKSTATION` (IP `192.168.1.150`) |
| **Luật SIEM bị kích hoạt** | Rule ID `100301` (Defense Evasion: Suspicious PowerShell execution detected) |

---

### 2. TÓM TẮT SỰ CỐ (EXECUTIVE SUMMARY)
Cảnh báo mức độ 10 trên Wazuh SIEM được kích hoạt khi phát hiện tiến trình `powershell.exe` chạy với tham số `-ExecutionPolicy Bypass` và `-WindowStyle Hidden` trên trạm làm việc `WIN10-WORKSTATION`.

Sau khi tiếp nhận cảnh báo, Analyst L1 tiến hành điều tra:
1. Kiểm tra tài khoản thực thi: Tài khoản hệ thống là `DOMAIN\svc_backup` (Service Account dùng riêng cho sao lưu dữ liệu).
2. Kiểm tra tiến trình cha: Được gọi bởi `C:\Windows\System32\svchost.exe` với dòng lệnh `svchost.exe -k netsvcs -p -s Schedule` (dịch vụ Windows Task Scheduler trên Windows 10).
3. Kiểm tra tệp thực thi: Script được gọi là `"C:\Program Files\IT-Management\Backup_Routine.ps1"`. Tệp có chữ ký số nội bộ và hàm băm trùng khớp với bản phát hành trên kho quản trị IT.
4. Đối chiếu lịch trình vận hành: Hoạt động khớp với yêu cầu thay đổi định kỳ `#CHG-8921` do bộ phận IT System Admin phê duyệt.

**Kết luận:** Cảnh báo được xác định là **False Positive (FP)**. Việc tác vụ định kỳ kích hoạt cảnh báo này mỗi ngày gây ra tình trạng Alert Fatigue cho ca trực. Analyst L1 đã thiết lập luật loại trừ (Rule Tuning) tại `local_rules.xml` để vô hiệu hóa cảnh báo cho tác vụ này.

---

### 3. BẰNG CHỨNG LOG & BƯỚC ĐIỀU TRA (INVESTIGATION STEPS)

#### A. Log ghi nhận qua luồng EventChannel từ Sysmon Event ID 1:
```json
{
  "EventID": 1,
  "Computer": "WIN10-WORKSTATION.corp.local",
  "User": "DOMAIN\\svc_backup",
  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "CommandLine": "powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -WindowStyle Hidden -File \"C:\\Program Files\\IT-Management\\Backup_Routine.ps1\"",
  "ParentImage": "C:\\Windows\\System32\\svchost.exe",
  "ParentCommandLine": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule"
}
```

#### B. Phân tích Chi tiết:
- Dòng lệnh thực thi: `powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -WindowStyle Hidden -File "C:\Program Files\IT-Management\Backup_Routine.ps1"`.
- Tiến trình cha `svchost.exe` chạy dịch vụ Task Scheduler (`Schedule`), xác nhận script được kích hoạt tự động theo lịch đã định sẵn của hệ thống chứ không phải do người dùng thao tác trực tiếp hay mã độc kích hoạt từ `cmd.exe` hoặc ứng dụng Office.

---

### 4. GIẢI PHÁP TINH CHỈNH LUẬT (RULE TUNING IMPLEMENTATION)

Bổ sung luật loại trừ (Suppression Rule) vào tệp `configurations/siem-rules/local_rules.xml`:

```xml
<rule id="100401" level="0">
  <if_sid>100301</if_sid>
  <field name="win.eventdata.user" type="pcre2">(?i)^DOMAIN\\svc_backup$</field>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)\\svchost\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)Backup_Routine\.ps1</field>
  <description>Tuning: Whitelist authorized IT Backup Service account</description>
</rule>
```

#### Cơ chế hoạt động của luật Tuning:
- `<if_sid>100301</if_sid>`: Kế thừa điều kiện bắt PowerShell khả nghi từ luật mẹ.
- `<field name="win.eventdata.user">`: Giới hạn áp dụng cho tài khoản `DOMAIN\svc_backup`.
- `<field name="win.eventdata.parentImage">`: Đảm bảo tiến trình cha phải là `svchost.exe` (Task Scheduler).
- `<field name="win.eventdata.commandLine">`: Kiểm tra đối số chứa tên tệp `Backup_Routine.ps1`.
- `level="0"`: Triệt tiêu cảnh báo trên SIEM cho hành vi khớp toàn bộ 3 điều kiện trên.

---

### 5. KIỂM THỬ XÁC MINH VÀ ĐO LƯỜNG HIỆU QUẢ (VERIFICATION & METRICS)

1. **Phương pháp kiểm thử thực tế:**
   - Đối với các log dạng văn bản Linux/Web (`auth.log`, `access.log`), hệ thống kiểm thử qua công cụ `/var/ossec/bin/wazuh-logtest`.
   - Đối với log Windows Sysmon dạng EventChannel, việc kiểm thử được thực hiện bằng cách đẩy dữ liệu qua kênh thu thập `windows_eventchannel` của Wazuh Agent hoặc nạp trực tiếp vào luồng xử lý `analysisd` qua tệp `archives.json`. Kết quả ghi nhận luật `100401` được kích hoạt thay vì `100301`, mức độ cảnh báo là 0.
   - Khi kiểm tra với kịch bản mã độc thực tế (Case 03: chạy từ `cmd.exe` dưới quyền user thông thường), Rule `100301` vẫn kích hoạt ở mức Level 10, chứng minh việc whitelist không tạo lỗ hổng bỏ lọt tấn công.

2. **Đo lường tác động vận hành:**
   - Số lượng cảnh báo trước tuning: ~48 cảnh báo/ngày.
   - Số lượng cảnh báo sau tuning: 0 cảnh báo/ngày đối với tác vụ sao lưu.
   - Giảm thiểu triệt để Alert Fatigue cho ca trực.
