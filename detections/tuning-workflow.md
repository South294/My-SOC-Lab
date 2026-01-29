# 🛠️ Quy Trình Tinh Chỉnh & Xử Lý Báo Động Giả (Tuning Workflow)

## 1. Vấn đề thực tế (The Problem)
Trong quá trình vận hành SOC Lab, hệ thống thường xuyên phát sinh cảnh báo **Level 12 (Critical)** khi Administrator thực hiện bảo trì định kỳ. Điều này gây ra "Alert Fatigue" (Quá tải cảnh báo ảo).

## 2. Case Study: Administrator dùng PsExec

### 🚨 Sự Cố (The Incident)
* **Cảnh báo:** `Suspicious lateral movement - PsExec execution detected`
* **Mức độ:** Level 12
* **Thiết bị:** `My-PC-Lab` (IP: 192.168.208.1)
* **User:** `Administrator`

### 🕵️ Phân Tích (Investigation)
1.  **Context:** Lệnh `PsExec.exe -i cmd.exe` được chạy vào thời điểm tôi đang debug kết nối Agent.
2.  **Verification:** User thực thi là Administrator (chính chủ), IP nguồn là nội bộ (Localhost).
3.  **Conclusion:** Đây là **False Positive** (Hành vi hợp lệ bị nhận diện nhầm là tấn công).

### ⚙️ Giải Pháp Tuning (Solution)
Tôi đã viết một **Custom Rule** (trong `local_rules.xml`) để Whitelist hành vi này.

**Logic:**
* **NẾU** phát hiện PsExec
* **VÀ** User là "Administrator"
* **THÌ** hạ mức cảnh báo xuống Level 0 (Ignored).

```xml
<rule id="100501" level="0">
  <if_sid>100500</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)psexec\.exe</field>
  <field name="win.eventdata.user" type="pcre2">(?i)Administrator</field>
  <description>False Positive: Admin maintenance via PsExec</description>
</rule>
```
