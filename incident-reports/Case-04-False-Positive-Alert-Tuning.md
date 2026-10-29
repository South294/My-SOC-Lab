# INCIDENT INVESTIGATION REPORT: INC-2026-004
## False Positive Investigation & SIEM Detection Rule Tuning

---

### 1. THÔNG TIN CHUNG (INCIDENT METADATA)
| Thông tin | Chi tiết |
| :--- | :--- |
| **Ticket ID** | INC-2026-004 |
| **Mức độ ban đầu (Initial Severity)** | Medium (P3) / Rule Level 10 |
| **Trạng thái (Status)** | **Closed as False Positive (FP) / Tuned** |
| **Phân loại (Classification)** | **False Positive (FP - Authorized IT Activity)** |
| **Người trực / Phân tích (Analyst)** | SOC Analyst Tier 1 |
| **Thời gian phát hiện** | 2026-10-29 14:40:00 (UTC+7) |
| **Hệ thống cảnh báo (Target)** | `WIN10-WORKSTATION` (IP `192.168.1.150`) |
| **Luật SIEM bị kích hoạt** | Rule ID `100301` (PowerShell execution with Encoded Command) |

---

### 2. TÓM TẮT SỰ CỐ (EXECUTIVE SUMMARY)
Cảnh báo mức độ 10 trên Wazuh SIEM được kích hoạt khi phát hiện một tiến trình `powershell.exe` chạy với tham số `-enc` trên máy tính `WIN10-WORKSTATION`.

Sau khi tiếp nhận cảnh báo, Analyst L1 tiến hành điều tra:
1. Giải mã chuỗi Base64: Chuỗi lệnh chỉ đơn giản là in ra thông báo trạng thái `Write-Host "Backup in progress"`.
2. Kiểm tra tài khoản thực thi: Tài khoản hệ thống là `DOMAIN\svc_backup` (Service Account dùng riêng cho sao lưu dữ liệu).
3. Kiểm tra tiến trình cha: Được gọi bởi `C:\Windows\System32\taskeng.exe` (Windows Task Scheduler).
4. Đối chiếu lịch trình IT nội bộ: Khớp với Ticket bảo trì định kỳ `#CHG-8921` do đội IT System Admin phê duyệt.

**Kết luận:** Đây là cảnh báo giả (**False Positive**). Việc cảnh báo này lặp lại hàng ngày vào cùng khung giờ gây ra tình trạng quá tải cảnh báo (Alert Fatigue). Analyst L1 đã tiến hành viết luật tinh chỉnh (Rule Tuning) loại trừ tài khoản và script sao lưu trên Wazuh Manager, đưa số lượng cảnh báo nhiễu về 0.

---

### 3. BẰNG CHỨNG LOG & BƯỚC ĐIỀU TRA (INVESTIGATION STEPS)

#### A. Log thô ghi nhận từ Sysmon Event ID 1:
```json
{
  "EventID": 1,
  "Computer": "WIN10-WORKSTATION.corp.local",
  "User": "DOMAIN\\svc_backup",
  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "CommandLine": "powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAQgBhAGMAawB1AHAAIABpAG4AIABwAHIAbwBnAHIAZQBzAHMAIgA= -File C:\\Program Files\\IT-Management\\Backup_Routine.ps1",
  "ParentImage": "C:\\Windows\\System32\\taskeng.exe"
}
```

#### B. Phân tích & Giải mã:
- Chuỗi Base64: `VwByAGkAdABlAC0ASABvAHMAdAAgACIAQgBhAGMAawB1AHAAIABpAG4AIABwAHIAbwBnAHIAZQBzAHMAIgA=`
- Giải mã UTF-16LE: `Write-Host "Backup in progress"`
- Tệp thực thi đi kèm: `C:\Program Files\IT-Management\Backup_Routine.ps1`
- Kiểm tra tính toàn vẹn: Tệp có chữ ký số nội bộ hợp lệ của Domain CA và mã Hash SHA256 khớp với bản lưu trữ tại kho IT Operations.

---

### 4. GIẢI PHÁP TINH CHỈNH LUẬT (RULE TUNING IMPLEMENTATION)

Để hệ thống SIEM không tiếp tục bắn cảnh báo cho hành vi hợp lệ này mà vẫn giữ nguyên khả năng phát hiện khi hacker tấn công thật, Analyst bổ sung luật loại trừ (Suppression Rule) vào tệp `configurations/siem-rules/local_rules.xml`:

```xml
<!-- Tinh chỉnh luật: Đặt level="0" để bỏ qua cảnh báo giả khi script quản trị Backup nội bộ chạy -->
<rule id="100401" level="0">
  <if_sid>100301</if_sid>
  <field name="win.eventdata.user" type="pcre2">(?i)^DOMAIN\\svc_backup$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)Backup_Routine\.ps1</field>
  <description>Tuning/Whitelist: Suppress alert for authorized IT Backup Service account</description>
</rule>
```

#### Cơ chế hoạt động của luật Tuning:
- `<if_sid>100301</if_sid>`: Kế thừa điều kiện bắt Encoded PowerShell từ luật mẹ.
- `<field name="win.eventdata.user">`: Giới hạn chỉ áp dụng khi người chạy đúng là tài khoản dịch vụ `DOMAIN\svc_backup`.
- `<field name="win.eventdata.commandLine">`: Kiểm tra lệnh có chứa tên script sao lưu đã thẩm định.
- `level="0"`: Hạ mức cảnh báo về 0 (Wazuh sẽ bỏ qua, không ghi nhận thành alert và không làm phiền ca trực SOC).

---

### 5. KIỂM THỬ XÁC MINH VÀ ĐO LƯỜNG HIỆU QUẢ (VERIFICATION & METRICS)

1. **Xác minh qua công cụ `wazuh-logtest`:**
   - Đưa dữ liệu mẫu của sự cố INC-2026-004 vào kiểm tra.
   - Kết quả: Luật `100401` được kích hoạt thay vì `100301`, mức độ cảnh báo là 0 (Passed / Suppressed).
   - Đưa dòng lệnh của hacker (từ sự cố INC-2026-003) vào kiểm tra: Luật `100301` vẫn kích hoạt ở mức độ 10 bình thường (Không bị lọt lưới).

2. **Đo lường tác động vận hành (Operational Metrics):**
   - **Tần suất kích hoạt trước tuning:** ~48 alerts/ngày (kịch bản backup chạy 30 phút một lần trên toàn bộ cụm máy tính).
   - **Tần suất kích hoạt sau tuning:** **0 alert/ngày**.
   - **Tỷ lệ giảm nhiễu:** **100%** đối với luồng tác vụ sao lưu, giúp kỹ sư SOC tập trung tối đa vào các mối đe dọa thực tế.

