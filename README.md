# SOC Triage Toolkit và SIEM Configuration Lab

Hệ thống giả lập điều tra sự cố (Triage), phân tích log, giải mã mã độc và quản lý luật SIEM tối ưu hóa cho vị trí SOC Analyst Tier 1.

---

## 1. Nguồn Log & Luật Phát Hiện (Log Sources & Detection)

Hạ tầng giám sát an ninh thông tin sử dụng Wazuh SIEM kết hợp với Sysmon (System Monitor) trên các máy trạm Windows để thu thập dữ liệu hành vi sâu.

### Các nguồn sự kiện chính (Event IDs)
- **Event ID 4625 (Security Log):** Đăng nhập thất bại (xác định Brute Force).
- **Event ID 1 (Sysmon):** Khởi tạo tiến trình (Process Creation - ghi nhận dòng lệnh thực thi).
- **Event ID 11 (Sysmon):** Tạo tệp tin mới (File Creation - theo dõi tải file lạ).
- **Event ID 12/13 (Sysmon):** Tạo hoặc sửa đổi Registry (theo dõi cơ chế Persistence).
- **Event ID 2 (Sysmon):** Thay đổi thời gian tạo tệp tin (Timestomping - Defense Evasion).

### Danh mục Luật phát hiện Custom (local_rules.xml)
Tất cả các luật phát hiện được ánh xạ trực tiếp sang kỹ thuật tấn công trong ma trận MITRE ATT&CK:

| Rule ID | Tên luật phát hiện | Mức độ | Kỹ thuật MITRE ATT&CK | Mô tả |
| :--- | :--- | :--- | :--- | :--- |
| **100001** | Authentication Failure: Multiple SMB logon failures | Level 10 | T1110 (Brute Force) | Phát hiện dò quét mật khẩu qua giao thức SMB |
| **100002** | Ransomware Activity: Shadow Copies deletion attempt | Level 12 | T1490 (Inhibit System Recovery) | Phát hiện hành vi xóa bản sao lưu phục hồi hệ thống |
| **100003** | Persistence: Suspicious Registry Run Key Modification | Level 10 | T1547.001 (Registry Run Keys) | Phát hiện thiết lập tự khởi động của mã độc |
| **100004** | Defense Evasion: PowerShell Encoded Command | Level 10 | T1027 (Obfuscated Information) | Phát hiện lệnh PowerShell chạy mã hóa Base64 |
| **100005** | Suspicious File Download: Temp/Public directory | Level 11 | T1105 (Ingress Tool Transfer) | Phát hiện tải tệp thực thi vào thư mục tạm |

---

## 2. Quy Trình Triage & Phản Ứng (Triage & Response)

### Quy trình Triage Sự Cố chuẩn SOC L1
```
Alert (Nhận cảnh báo)
  └── Verify (Xác minh định dạng log thô)
        └── Scope (Bóc tách các chỉ số IOCs)
              └── Enrich (Tra cứu uy tín IP & Giải mã payload)
                    └── Classify TP/FP (Phân loại Sự cố thực / Cảnh báo giả)
                          └── Escalate / Ticket (Cách ly/Tuning & Xuất báo cáo điều tra)
```

### Phân loại mức độ nghiêm trọng (Severity Mapping)
- **Critical (Level 12+):** Hành vi phá hoại trực tiếp như Ransomware xóa sao lưu, mã hóa dữ liệu. Yêu cầu phản ứng trong 15 phút.
- **High (Level 10-11):** Thực thi mã hóa PowerShell, sửa đổi cơ chế khởi động Registry, hoặc tải file nhị phân đáng ngờ. Yêu cầu phản ứng trong 30 phút.
- **Medium (Level 5-9):** Đăng nhập sai nhiều lần từ IP nội bộ, thay đổi cấu hình hệ thống thông thường. Yêu cầu phản ứng trong 2 giờ.
- **Low (Level 3-4):** Các hành vi trinh sát cơ bản hoặc cảnh báo hệ thống thông thường.

### Tóm tắt Quy trình Phản ứng (SOP Playbooks)
1. **SOP-001 (SMB Brute Force):** Chặn IP nguồn trên tường lửa biên -> Truy vết Event ID 4624 thành công -> Khóa tài khoản nếu có đăng nhập thành công.
2. **SOP-002 (PowerShell Encoded):** Giải mã Base64 -> Rà soát lệnh rõ để tìm IP C2 hoặc tệp tải về -> Kết thúc tiến trình PowerShell và tiến trình cha.
3. **SOP-003 (Registry Run Key):** Xác định đường dẫn tệp thực thi độc hại -> Xóa khóa Registry -> Xóa tệp thực thi đích khỏi thư mục tạm.
4. **SOP-004 (Suspicious Download):** Kiểm tra SHA256 trên VirusTotal -> Xóa tệp -> Cô lập thiết bị nếu tệp đã chạy và có kết nối mạng ra ngoài.
5. **SOP-005 (Shadow Copy Deletion):** Cách ly mạng ngay lập tức (Host Isolation) -> Kết thúc tiến trình cha -> Kiểm tra tính toàn vẹn của dữ liệu sao lưu ngoại tuyến.

### Tinh chỉnh SIEM Rule (Rule Tuning Assistant)
- **Mục tiêu:** Loại bỏ cảnh báo giả (False Positives) sinh ra do các tiến trình nghiệp vụ hợp lệ của hệ thống hoặc quản trị viên IT.
- **Cơ chế:** Sử dụng thẻ `<if_sid>` để kế thừa và `<field>` kèm Regex để loại trừ các giá trị an toàn.
- **Hiệu quả thực tế:** Giảm thiểu số lượng cảnh báo trùng lặp từ 140+ mỗi ngày xuống dưới 5 sự kiện thực tế, giảm thiểu tình trạng quá tải cảnh báo (Alert Fatigue).

---

## 3. Triển Khai Lab & Báo Cáo (Lab Deployment & Reporting)

### Bước 1: Khởi động Wazuh SIEM Server
Di chuyển vào thư mục `deployment/` và khởi chạy container:
```bash
docker-compose up -d
```

### Bước 2: Cấu hình trên Endpoint Windows
1. Cài đặt **Wazuh Agent** và áp dụng cấu hình đẩy logs trong `configurations/agent/ossec.conf`.
2. Cài đặt **Sysmon** với file cấu hình chuẩn `configurations/agent/sysmonconfig.xml`:
```cmd
sysmon.exe -i sysmonconfig.xml
```

### Bước 3: Tích hợp Luật trên SIEM Manager
Copy nội dung luật trong `configurations/manager/local_rules.xml` vào mục cấu hình luật trên Wazuh Dashboard (`ruleset/decoders/rules`). Khởi động lại Wazuh Manager để áp dụng.

### Bước 4: Kiểm thử sự kiện và Xuất báo cáo
Sử dụng công cụ **Lab Event Generator** để lấy dòng lệnh kiểm thử an toàn, thực thi trên endpoint và nạp log thô thu được vào **Bảng Triage** để tập dượt phân tích, sau đó kết xuất báo cáo Markdown làm bằng chứng điều tra.

---

## 4. Phụ lục: Cheat Sheet dành cho SOC Analyst L1

### Mô hình OSI & Trách nhiệm Giám sát
- **Layer 7 (Application):** HTTP/HTTPS, DNS, SMB, SSH. Giám sát tấn công web, đánh cắp dữ liệu, trinh sát.
- **Layer 4 (Transport):** TCP, UDP. Kiểm soát luồng kết nối, phân tích Port Scan.
- **Layer 3 (Network):** IP, ICMP. Phân tích định tuyến, phát hiện IP độc hại bên ngoài.

### Danh mục Port phổ biến và Rủi ro
- **Port 22 (SSH):** Nguy cơ Brute Force, chiếm quyền điều khiển dòng lệnh.
- **Port 445 (SMB):** Lan truyền mã độc trong mạng nội bộ (Lateral Movement), khai thác lỗ hổng EternalBlue.
- **Port 3389 (RDP):** Chiếm quyền điều khiển giao diện người dùng, nguy cơ rò rỉ thông tin xác thực.
- **Port 80/443 (HTTP/HTTPS):** Kênh truyền tải mã độc chính từ Internet hoặc kết nối C2 của Hacker.

### Mô hình AAA và CIA Triad
- **CIA:** Confidentiality (Bảo mật), Integrity (Toàn vẹn), Availability (Sẵn sàng).
- **AAA:** Authentication (Xác thực danh tính), Authorization (Cấp quyền hạn), Accounting (Ghi nhật ký hoạt động - cơ sở cốt lõi của Log Auditing).

### Vòng đời tấn công (Attack Lifecycle - Cyber Kill Chain)
1. **Reconnaissance (Trinh sát):** Thu thập thông tin mục tiêu.
2. **Weaponization (Vũ khí hóa):** Đóng gói mã độc.
3. **Delivery (Phát tán):** Tải file độc hại về máy qua Web/Mail.
4. **Exploitation (Khai thác):** Kích hoạt thực thi mã độc.
5. **Installation (Cài đặt):** Thiết lập cơ chế chạy ngầm (Registry Run Key).
6. **Command & Control (C2):** Kết nối điều khiển từ xa qua mạng.
7. **Actions on Objectives (Phá hoại):** Xóa sao lưu, mã hóa dữ liệu đòi tiền chuộc (Ransomware).
