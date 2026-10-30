# INCIDENT INVESTIGATION REPORT: INC-2026-001
## Web Application SQL Injection & WAF Action Triage

---

### 1. THÔNG TIN CHUNG (INCIDENT METADATA)
| Thông tin | Chi tiết |
| :--- | :--- |
| **Ticket ID** | INC-2026-001 |
| **Mức độ nghiêm trọng (Severity)** | **High (P2)** |
| **Trạng thái (Status)** | Contained / Closed (Bàn giao AppSec) |
| **Phân loại (Classification)** | **True Positive (TP)** |
| **Người trực / Phân tích (Analyst)** | SOC Analyst Tier 1 |
| **Thời gian phát hiện** | 2026-10-30 14:15:20 (UTC+7) |
| **Nguồn log (Log Source)** | `shared-logs/web_access.log` (Nginx combined format) |
| **Luật SIEM kích hoạt (Alert)** | Rule ID `100100` (Level 10) & Rule ID `100101` (Level 6) |

---

### 2. TÓM TẮT SỰ CỐ (EXECUTIVE SUMMARY)
Hệ thống SIEM ghi nhận nhiều cảnh báo tấn công SQL Injection nhắm vào dịch vụ Web từ địa chỉ IP nguồn `185.220.101.5`. Qua đối chiếu nhật ký truy cập web, phát hiện công cụ quét lỗ hổng tự động (`sqlmap/1.7#stable`) liên tục gửi các payload `UNION SELECT` và logic injection vào tham số truy vấn `id`.

Phần lớn các request khai thác chuyên sâu đã bị WAF chặn lại với mã trạng thái HTTP `403 Forbidden` (kích hoạt Rule `100101`). Tuy nhiên, bản ghi lúc 14:10:02 trả về mã HTTP `200 OK` (kích hoạt Rule `100102`) cho thấy kẻ tấn công đã từng thăm dò thành công khi chưa bật luật WAF. Sự cố được kết luận là **True Positive**.

---

### 3. BẰNG CHỨNG LOG CHI TIẾT
```log
185.220.101.5 - - [30/Oct/2026:14:10:02 +0700] "GET /vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit HTTP/1.1" 200 4821 "http://192.168.1.100/vulnerabilities/sqli/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
185.220.101.5 - - [30/Oct/2026:14:15:20 +0700] "GET /vulnerabilities/sqli/?id=1%27+UNION+SELECT+null%2Cuser%2Cpassword+FROM+users--+-&Submit=Submit HTTP/1.1" 403 548 "http://192.168.1.100/vulnerabilities/sqli/" "sqlmap/1.7#stable"
185.220.101.5 - - [30/Oct/2026:14:15:22 +0700] "GET /vulnerabilities/sqli/?id=1%27+AND+1%3D1--+-&Submit=Submit HTTP/1.1" 403 548 "http://192.168.1.100/vulnerabilities/sqli/" "sqlmap/1.7#stable"
```

---

### 4. BÓC TÁCH CHỈ SỐ NGUY HẠI (IOCs)
| Loại IOC | Giá trị | Nhận định |
| :--- | :--- | :--- |
| **Attacker IP** | `185.220.101.5` | IP ngoại vi, phát sinh lưu lượng quét bất thường |
| **Target URL** | `/vulnerabilities/sqli/?id=...` | Đường dẫn chức năng tìm kiếm người dùng |
| **User-Agent** | `sqlmap/1.7#stable` | Dấu hiệu nhận diện công cụ khai thác SQLi tự động |
| **MITRE ATT&CK** | `T1190` | Exploit Public-Facing Application |

---

### 5. HÀNH ĐỘNG XỬ LÝ (CONTAINMENT & REMEDIATION)
1. **Ngăn chặn tức thời:** Bổ sung IP `185.220.101.5` vào danh sách cấm tại tường lửa biên.
2. **Khắc phục dài hạn:** Chuyển ticket sang bộ phận AppSec yêu cầu chuẩn hóa tham số hóa truy vấn (Parameterized Queries / Prepared Statements) thay vì nối chuỗi SQL.
