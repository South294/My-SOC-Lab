# INCIDENT INVESTIGATION REPORT: INC-2026-002
## Linux SSH Brute Force with Compromised Login

---

### 1. THÔNG TIN CHUNG (INCIDENT METADATA)
| Thông tin | Chi tiết |
| :--- | :--- |
| **Ticket ID** | INC-2026-002 |
| **Mức độ nghiêm trọng (Severity)** | **Critical (P1)** |
| **Trạng thái (Status)** | Under Remediation / Escalated to Tier 2 |
| **Phân loại (Classification)** | **True Positive (TP - Account Compromised)** |
| **Người trực / Phân tích (Analyst)** | SOC Analyst Tier 1 |
| **Thời gian phát hiện** | 2026-12-10 06:55:59 |
| **Nguồn log (Log Source)** | `shared-logs/linux_auth.log` (OpenSSH Syslog) |
| **Luật SIEM kích hoạt (Alert)** | Rule ID `100201` (Level 10) & Rule ID `100202` (Level 13) |

---

### 2. TÓM TẮT SỰ CỐ (EXECUTIVE SUMMARY)
Hệ thống SIEM ghi nhận chuỗi xác thực thất bại liên tiếp qua dịch vụ SSH từ địa chỉ IP `218.188.2.4` nhắm vào nhiều tài khoản người dùng (`admin`, `guest`, `root`, `test`, `devops`). Sau 6 lần thử sai trong vòng 10 giây, Rule `100201` kích hoạt cảnh báo tấn công dò quét mật khẩu (Brute Force).

Ngay tại thời điểm 06:55:59, hệ thống tiếp tục ghi nhận sự kiện `Accepted password for devops from 218.188.2.4 port 41246 ssh2` và khởi tạo phiên làm việc `session 42`. Sự kiện này kích hoạt ngay lập tức Rule `100202` (Critical) do phát hiện đăng nhập thành công từ cùng địa chỉ IP vừa thực hiện brute force. Sự cố được xác nhận là **True Positive: Tài khoản `devops` đã bị chiếm đoạt**.

---

### 3. BẰNG CHỨNG LOG CHI TIẾT
```log
Dec 10 06:55:46 server sshd[24200]: Failed password for invalid user admin from 218.188.2.4 port 41234 ssh2
Dec 10 06:55:48 server sshd[24202]: Failed password for invalid user guest from 218.188.2.4 port 41236 ssh2
Dec 10 06:55:50 server sshd[24204]: Failed password for root from 218.188.2.4 port 41238 ssh2
Dec 10 06:55:52 server sshd[24206]: Failed password for invalid user test from 218.188.2.4 port 41240 ssh2
Dec 10 06:55:54 server sshd[24208]: Failed password for devops from 218.188.2.4 port 41242 ssh2
Dec 10 06:55:56 server sshd[24210]: Failed password for devops from 218.188.2.4 port 41244 ssh2
Dec 10 06:55:59 server sshd[24212]: Accepted password for devops from 218.188.2.4 port 41246 ssh2
Dec 10 06:55:59 server systemd-logind[789]: New session 42 of user devops.
```

---

### 4. MITRE ATT&CK MAPPING
| Tactic | Technique ID | Tên kỹ thuật | Mô tả |
| :--- | :--- | :--- | :--- |
| **Credential Access** | `T1110.001` | Password Guessing / Brute Force | Dò quét mật khẩu qua cổng SSH (22) |
| **Initial Access** | `T1078.003` | Valid Accounts: Local Accounts | Đăng nhập thành công bằng tài khoản cục bộ `devops` |

---

### 5. QUY TRÌNH PHẢN ỨNG SỰ CỐ (CONTAINMENT)
1. Cưỡng chế ngắt toàn bộ phiên SSH của tài khoản `devops`: `pkill -KILL -u devops`.
2. Khóa tạm thời tài khoản để ngăn truy cập tiếp theo: `passwd -l devops`.
3. Bổ sung luật cấm IP `218.188.2.4` trên Firewall iptables.
4. Chuyển tuyến khẩn cấp lên Tier 2 để rà soát tệp `~devops/.bash_history` và các tiến trình con sinh ra trong phiên 42.
