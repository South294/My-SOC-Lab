# ⚡ Các Kịch Bản Tấn Công Giả Lập (Attack Scenarios)

File này mình dùng để lưu lại các lệnh test hệ thống SOC. Mục đích là giả lập hành vi của hacker để xem Wazuh và Sysmon có bắt được log và cảnh báo đúng như mong đợi không.

---

## 1. Tấn công dò mật khẩu (Brute Force SMB)
**Mục đích:** Test tính năng "Active Response". Mình sẽ cố tình đăng nhập sai nhiều lần để xem Firewall có tự động chặn IP của máy tấn công không.

* **Công cụ:** Hydra (trên Kali Linux).
* **Lệnh thực hiện:** (Thay `<IP_MAY_WIN>` bằng IP máy Windows của bạn)

```bash
hydra -l Administrator -p matkhausai123 smb://<IP_MAY_WIN> -t 4
```

---

## 2. Tải mã độc giả (Malware Download)
**Mục đích:** Test tính năng VirusTotal. Khi tải file EICAR (đây là file test an toàn, không phải virus thật), hệ thống phải quét Hash và báo động đỏ (Level 12).

* **Công cụ:** PowerShell (trên Windows).
* **Lệnh thực hiện:**

```powershell
Invoke-WebRequest -Uri "https://secure.eicar.org/eicar.com" -OutFile "C:\Users\Public\eicar_test.com"
```

---

## 3. Giả lập hành vi Ransomware (Xóa Shadow Copy)
**Mục đích:** Hầu hết Ransomware khi vào máy sẽ xóa các bản backup (Shadow Copies) để nạn nhân không khôi phục được dữ liệu. Kịch bản này test xem hệ thống có phát hiện hành vi nguy hiểm này không (MITRE T1490).

* **Lưu ý:** Cần chạy CMD/PowerShell quyền Administrator.
* **Lệnh thực hiện:**

```powershell
vssadmin delete shadows /all
```
(Lệnh này an toàn, chỉ báo lỗi nếu máy không có bản backup nào).

---

## 4. Kỹ thuật "Nằm vùng" (Persistence via Registry)
**Mục đích:** Hacker thường cài virus vào Registry để mỗi khi bật máy là virus tự chạy lại. Bài test này sẽ thử thêm chương trình máy tính (Calculator) vào danh sách khởi động cùng Windows (MITRE T1547).

* **Lệnh thực hiện (CMD):**

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Backdoor" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
```
* **Lệnh dọn dẹp (Cleanup):** (Chạy lệnh này sau khi test để xóa key đã tạo, trả lại trạng thái sạch cho máy)

```cmd
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Backdoor" /f
```

---

## 5. Né tránh giám sát (Obfuscated PowerShell)
**Mục đích:** Hacker hay mã hóa lệnh (dạng Base64) để né các từ khóa nhạy cảm. Bài này chạy một lệnh vô hại nhưng được mã hóa loằng ngoằng để xem SOC có phát hiện và giải mã được không (MITRE T1027).

* **Lệnh thực hiện:**

```powershell
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABhAGkAIABsAGEAIABIAGEAYwBrAGUAcgAiAA==
```
*(Giải mã: Đoạn mã trên khi decode ra chính là lệnh: `Write-Host "Tai la Hacker"`)*