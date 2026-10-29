# INCIDENT INVESTIGATION REPORT: INC-2026-001
## Web Application SQL Injection & WAF Triage Analysis

---

### 1. THÔNG TIN CHUNG (INCIDENT METADATA)
| Thông tin | Chi tiết |
| :--- | :--- |
| **Ticket ID** | INC-2026-001 |
| **Mức độ nghiêm trọng (Severity)** | **High (P2)** |
| **Trạng thái (Status)** | Contained / Closed (Bàn giao AppSec) |
| **Phân loại (Classification)** | **True Positive (TP)** |
| **Người trực / Phân tích (Analyst)** | SOC Analyst Tier 1 |
| **Thời gian tiếp nhận** | 2026-10-29 14:15:20 (UTC+7) |
| **Hệ thống bị nhắm tới (Target)** | Web Server Ubuntu (`192.168.1.100`), dịch vụ DVWA |
| **Luật SIEM kích hoạt (Alert)** | Rule ID `100100` / `100101` (SQL Injection Detected / Blocked by WAF) |

---

### 2. TÓM TẮT SỰ CỐ (EXECUTIVE SUMMARY)
Hệ thống SIEM Wazuh ghi nhận nhiều cảnh báo liên quan đến hành vi tấn công web dạng SQL Injection hướng tới máy chủ Web `192.168.1.100` từ IP ngoại vi `198.51.100.50`. Qua đối chiếu log truy cập máy chủ (Nginx Access Log) và log phòng vệ của tường lửa ứng dụng web ModSecurity (WAF), Analyst xác định đây là một cuộc quét lỗ hổng và khai thác tự động (dùng công cụ `sqlmap`). 

Tường lửa ModSecurity đã phát hiện và chặn thành công (HTTP 403 Forbidden) đối với payload khai thác `UNION SELECT`. Tuy nhiên, kiểm tra lược sử log trước đó cho thấy kẻ tấn công đã từng thăm dò thành công (HTTP 200 OK) với payload kiểm tra logic cơ bản `1' OR '1'='1`. Cảnh báo được kết luận là **True Positive**, IP nguồn đã được chặn tại Gateway và chuyển thông tin cho đội AppSec khắc phục triệt để lỗ hổng trong mã nguồn ứng dụng.

---

### 3. QUÁ TRÌNH PHÂN TÍCH KỸ THUẬT & BẰNG CHỨNG LOG (EVIDENCE & TRIAGE)

#### A. So sánh 2 dòng Log trên Nginx:
```log
# Dòng 1: Request bị ModSecurity chặn (HTTP 403 Forbidden)
198.51.100.50 - - [29/Oct/2026:14:15:20 +0700] "GET /vulnerabilities/sqli/?id=1%27+UNION+SELECT+null%2Cuser%2Cpassword+FROM+users--+-&Submit=Submit HTTP/1.1" 403 548 "http://192.168.1.100/vulnerabilities/sqli/" "sqlmap/1.7#stable"

# Dòng 2: Request trước đó chưa bật luật WAF / đã lọt qua (HTTP 200 OK)
198.51.100.50 - - [29/Oct/2026:14:10:02 +0700] "GET /vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit HTTP/1.1" 200 4821 "http://192.168.1.100/vulnerabilities/sqli/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

#### B. Phân tích ModSecurity Audit Log:
- **Mã luật WAF kích hoạt:** OWASP ModSecurity Core Rule Set (CRS) `Rule 942100` (SQL Injection Attack Detected via libinjection).
- **Tham số tấn công:** `ARGS:id` chứa payload `1' UNION SELECT null,user,password FROM users-- -`.
- **Hành động của WAF:** HTTP Status `403 Forbidden`, Anomaly Score vượt ngưỡng cho phép (Score >= 5).

#### C. Bóc tách Chỉ số Nguy hại (IOCs Extraction):
| Loại IOC | Giá trị | Nhận định |
| :--- | :--- | :--- |
| **Attacker IP** | `198.51.100.50` | IP lạ từ ngoài Internet, tra cứu AbuseIPDB có điểm uy tín xấu |
| **Target URL** | `http://192.168.1.100/vulnerabilities/sqli/` | Đường dẫn chứa chức năng tìm kiếm người dùng |
| **User-Agent** | `sqlmap/1.7#stable` | Chữ ký đặc trưng của công cụ khai thác SQLi tự động |
| **Attack Vector** | `UNION-based SQL Injection` | Kỹ thuật trích xuất dữ liệu bảng `users` |

---

### 4. ĐÁNH GIÁ TÁC ĐỘNG & MITRE ATT&CK MAPPING
- **MITRE ATT&CK:**
  - **Tactic:** Initial Access / Execution
  - **Technique:** `T1190` - Exploit Public-Facing Application
- **Tác động:** Kẻ tấn công có mục tiêu lấy cắp dữ liệu tài khoản (`user`, `password`) từ cơ sở dữ liệu. Nhờ có WAF chặn ở pha 2 nên cuộc tấn công diện rộng bị bẻ gãy, nhưng cần vá code để không bị phụ thuộc hoàn toàn vào WAF.

---

### 5. HÀNH ĐỘNG XỬ LÝ (CONTAINMENT & REMEDIATION)
1. **Cô lập tức thời (Perimeter Block):** Đưa IP `198.51.100.50` vào danh sách đen (Blacklist) trên Firewall biên để chặn toàn bộ kết nối đến mạng DMZ.
2. **Kiểm tra rò rỉ dữ liệu:** Truy vấn nhật ký cơ sở dữ liệu (MySQL/Postgres) trong khoảng thời gian từ `14:10:00` đến `14:15:00` xem có truy vấn nhạy cảm nào được thực thi hoàn tất hay không.
3. **Chuyển tuyến (Escalation):** Tạo ticket bàn giao đội Lập trình viên / AppSec yêu cầu:
   - Sử dụng **Prepared Statements / Parameterized Queries** thay vì nối chuỗi SQL trực tiếp.
   - Giữ nguyên chế độ `SecRuleEngine On` của ModSecurity trên toàn bộ vhost Nginx.

