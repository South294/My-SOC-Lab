# 🧠 Phân Tích Logic Phát Hiện (Detection Logic)

Tài liệu này giải thích **tại sao** hệ thống SOC (Wazuh + Sysmon) có thể phát hiện được các cuộc tấn công mình đã giả lập.

---

## 1. Brute Force Attack (SMB)
*   **Hành vi:** Kẻ tấn công thử đăng nhập nhiều lần thất bại trong thời gian ngắn.
*   **Dấu hiệu (Logs):**
    *   **Windows Event ID 4625:** An account failed to log on.
*   **Wazuh Rule:**
    *   Wazuh có rule mặc định (ID `60122` hoặc tương tự) để đếm số lần Event 4625 xuất hiện.
    *   Nếu > 5 lần trong 60s -> Trigger Alert Level 10.
*   **MITRE ATT&CK:** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)

## 2. Malware Download (EICAR)
*   **Hành vi:** Tải xuống một file có mã hash trùng với danh sách đen (Blacklist).
*   **Dấu hiệu:**
    *   Wazuh File Integrity Monitoring (FIM) sẽ quét hash của file mới tạo.
    *   Module VirusTotal Integration gửi hash lên cloud để kiểm tra.
*   **Logic:**
    *   `New File` -> `Calculate Hash` -> `Query VirusTotal API` -> `Result: Positive` -> `Alert`.
*   **MITRE ATT&CK:** [T1204 - User Execution](https://attack.mitre.org/techniques/T1204/)

## 3. Ransomware Simulation (Shadow Copy Deletion)
*   **Hành vi:** Xóa các bản sao lưu Shadow Copy để ngăn khôi phục dữ liệu.
*   **Dấu hiệu (Sysmon):**
    *   **Event ID 1 (Process Create):** Có chứa dòng lệnh `vssadmin delete shadows`.
*   **Wazuh Rule:**
    *   Cần viết rule custom hoặc dùng rule có sẵn của Sysmon integration.
    *   Keyword match: `vssadmin` VÀ `delete` VÀ `shadows`.
*   **MITRE ATT&CK:** [T1490 - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)

## 4. Persistence (Registry Run Key)
*   **Hành vi:** Thêm value vào key `Run` hoặc `RunOnce` trong Registry để tự khởi động cùng Windows.
*   **Dấu hiệu (Sysmon):**
    *   **Event ID 12 or 13 (Registry Event):** TargetObject chứa `...CurrentVersion\Run...`.
*   **Logic:**
    *   Bất kỳ thay đổi ghi (Write) nào vào key này đều đáng ngờ nếu không phải do Trusted Installer thực hiện.
*   **MITRE ATT&CK:** [T1547.001 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/001/)

## 5. Obfuscated PowerShell
*   **Hành vi:** Sử dụng tham số `-EncodedCommand` để giấu nội dung lệnh thật.
*   **Dấu hiệu:**
    *   **Process Create (Sysmon ID 1):** CommandLine chứa `-EncodedCommand` hoặc `-enc`.
*   **Logic:**
    *   PowerShell chạy với tham số mã hóa thường là dấu hiệu của malware hoặc hacker đang cố gắng lẩn trốn.
*   **MITRE ATT&CK:** [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
