# INCIDENT INVESTIGATION REPORT: INC-2026-002
## Linux SSH Brute Force with Successful Compromise & Active Response

---

### 1. THÔNG TIN CHUNG (INCIDENT METADATA)
| Thông tin | Chi tiết |
| :--- | :--- |
| **Ticket ID** | INC-2026-002 |
| **Mức độ nghiêm trọng (Severity)** | **Critical (P1)** |
| **Trạng thái (Status)** | Under Remediation / Escalated to Tier 2 & SysAdmin |
| **Phân loại (Classification)** | **True Positive (TP - Account Compromised)** |
| **Người trực / Phân tích (Analyst)** | SOC Analyst Tier 1 |
| **Thời gian phát hiện** | 2026-10-29 14:20:25 (UTC+7) |
| **Hệ thống bị nhắm tới (Target)** | Web/App Server Ubuntu (`web-server`, IP `192.168.1.100`) |
| **Luật SIEM kích hoạt (Alert)** | Rule ID `100201` (SSH Brute Force) & Rule ID `100202` (Compromised Login) |

---

### 2. TÓM TẮT SỰ CỐ (EXECUTIVE SUMMARY)
Vào lúc 14:20:01, hệ thống giám sát Wazuh ghi nhận chuỗi cảnh báo đăng nhập thất bại liên tiếp qua dịch vụ SSH (`sshd`) nhắm vào máy chủ Linux `web-server` từ IP công cộng `203.0.113.45`. Kẻ tấn công tiến hành brute force với danh sách các tài khoản phổ biến (`admin`, `root`, `oracle`, `test`) và tài khoản nội bộ `devops`.

Cơ chế phòng thủ tự động **Wazuh Active Response** (`firewall-drop`) đã kích hoạt vào lúc 14:20:23 để chặn IP trên `iptables`. Tuy nhiên, ngay trước thời điểm kết nối bị ngắt hoàn toàn (14:20:25), kẻ tấn công đã dò trúng mật khẩu và nhận phản hồi `Accepted password for devops from 203.0.113.45 port 41258 ssh2`, mở ra phiên làm việc `session 42`. 

Đây là sự cố **ĐẶC BIỆT NGHIÊM TRỌNG** (True Positive: Tài khoản đã bị chiếm quyền truy cập). Analyst L1 lập tức tiến hành cô lập phiên kết nối, khóa tài khoản và chuyển tuyến khẩn cấp lên Tier 2 để điều tra dấu vết mã độc sau xâm nhập.

---

### 3. BẰNG CHỨNG LOG CHI TIẾT (/var/log/auth.log)
```log
Oct 29 14:20:01 web-server sshd[28412]: Failed password for invalid user admin from 203.0.113.45 port 41234 ssh2
Oct 29 14:20:05 web-server sshd[28415]: Failed password for root from 203.0.113.45 port 41238 ssh2
Oct 29 14:20:09 web-server sshd[28418]: Failed password for invalid user oracle from 203.0.113.45 port 41242 ssh2
Oct 29 14:20:14 web-server sshd[28421]: Failed password for invalid user test from 203.0.113.45 port 41246 ssh2
Oct 29 14:20:18 web-server sshd[28424]: Failed password for devops from 203.0.113.45 port 41250 ssh2
Oct 29 14:20:22 web-server sshd[28427]: Failed password for devops from 203.0.113.45 port 41254 ssh2
Oct 29 14:20:23 web-server ossec-execd[1120]: active-response/bin/firewall-drop.sh add - 203.0.113.45 100201
Oct 29 14:20:25 web-server sshd[28430]: Accepted password for devops from 203.0.113.45 port 41258 ssh2
Oct 29 14:20:25 web-server systemd-logind[789]: New session 42 of user devops.
```

---

### 4. KẾT QUẢ ĐIỀU TRA MỞ RỘNG (ENRICHMENT QUA SCRIPT TRIAGE)
Sử dụng công cụ `python scripts/triage_ioc_checker.py -i 203.0.113.45`:
- **AbuseIPDB:** Abuse Confidence Score đạt **100% (High Risk)**. Đã có 1,420 báo cáo về hành vi SSH Scanning/Brute force trên toàn cầu.
- **Tài khoản bị xâm phạm:** `devops` (có quyền chạy `sudo` trên máy chủ).

---

### 5. MITRE ATT&CK MAPPING
| Tactic | Technique ID | Tên kỹ thuật | Mô tả |
| :--- | :--- | :--- | :--- |
| **Credential Access** | `T1110.001` | Password Guessing / Brute Force | Dò quét mật khẩu qua cổng SSH (22) |
| **Initial Access** | `T1078.003` | Valid Accounts: Local Accounts | Đăng nhập thành công bằng tài khoản cục bộ `devops` |

---

### 6. QUY TRÌNH PHẢN ỨNG SỰ CỐ CỦA SOC TIER 1 (SOP RESPONSE)
1. **Ngắt phiên SSH đang hoạt động ngay lập tức:**
   ```bash
   sudo pkill -KILL -u devops
   ```
2. **Khóa tạm thời tài khoản bị lộ mật khẩu:**
   ```bash
   sudo passwd -l devops
   ```
3. **Xác nhận IP đã bị chặn trên Firewall iptables:**
   ```bash
   sudo iptables -L -n -v | grep 203.0.113.45
   ```
4. **Bàn giao khẩn cấp (Escalate to Tier 2 & Incident Response Team):**
   - Kiểm tra file `~devops/.bash_history` và các tiến trình con sinh ra trong khoảng thời gian từ `14:20:25` để xác định kẻ tấn công đã kịp thực thi lệnh gì.
   - Kiểm tra `~devops/.ssh/authorized_keys` xem kẻ tấn công có kịp ghi SSH public key để tạo persistence hay không.
5. **Khuyến nghị dài hạn:** Vô hiệu hóa tính năng đăng nhập SSH bằng Password (`PasswordAuthentication no`), bắt buộc sử dụng SSH Key và kích hoạt xác thực 2 yếu tố (2FA).

