# 📘 KẾ HOẠCH TRIỂN KHAI VÀ VẬN HÀNH LAB SOC TIER 1 TRÊN DOCKER & WSL2
## Tiến trình kỹ thuật từ con số 0 đến làm chủ hệ thống giám sát và phản ứng sự cố

---

## 📑 MỤC LỤC
1. [Triết lý Kiến trúc: Docker Desktop trên nền WSL2 Tối ưu RAM](#1-triết-lý-kiến-trúc-docker-desktop-trên-nền-wsl2-tối-ưu-ram)
2. [Thiết lập Hạ tầng và Kết nối Mount Trực tiếp](#2-thiết-lập-hạ-tầng-và-kết-nối-mount-trực-tiếp)
3. [Xây dựng Bộ Luật Phát hiện Chuẩn Xác (`rules/local_rules.xml`)](#3-xây-dựng-bộ-luật-phát-hiện-chuẩn-xác-ruleslocal_rulesxml)
4. [Cơ chế Bơm Payload từ WSL2 và Làm giàu Dữ liệu Triage](#4-cơ-chế-bơm-payload-từ-wsl2-và-làm-giàu-dữ-liệu-triage)
5. [Quy trình Vận hành 4 Kịch bản Giám sát Trọng tâm](#5-quy-trình-vận-hành-4-kịch-bản-giám-sát-trọng-tâm)
6. [Kỹ thuật Lọc Cảnh báo trên Dashboard và Tinh chỉnh Luật (Rule Tuning)](#6-kỹ-thuật-lọc-cảnh-báo-trên-dashboard-và-tinh-chỉnh-luật-rule-tuning)
7. [Giải trình Kỹ thuật Cốt lõi](#7-giải-trình-kỹ-thuật-cốt-lõi)

---

## 1. TRIẾT LÝ KIẾN TRÚC: DOCKER DESKTOP TRÊN NỀN WSL2 TỐI ƯU RAM

### 1.1 Vấn đề tài nguyên và giải pháp
Việc cài đặt Wazuh trực tiếp lên hệ điều hành Windows hoặc chạy nhiều máy ảo cùng lúc (VMware/VirtualBox) thường tiêu tốn 8GB - 12GB RAM, gây giật lag và khó duy trì luồng log ổn định.

Giải pháp tối ưu nhất là triển khai cụm Wazuh Single-Node trên Docker Desktop sử dụng WSL2 backend:
- **Khống chế trần tài nguyên bằng `.wslconfig`:** Giới hạn 4GB RAM và 2 CPU cho toàn bộ máy ảo WSL2.
- **Tối ưu RAM cho OpenSearch Indexer:** Cấu hình biến môi trường `OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m` trong `docker-compose.yml`, giúp toàn bộ cụm SIEM chỉ tiêu tốn khoảng 2GB - 2.5GB RAM.
- **Tốc độ đọc log theo mili-giây:** Đặt thư mục dự án bên trong hệ thống tệp của WSL (`~/My-SOC-Lab`) hoặc mount trực tiếp thư mục `shared-logs/` vào container Wazuh Manager. Cơ chế bắt sự kiện thay đổi tệp (inotify) của nhân Linux giúp Wazuh xử lý dòng log ngay khi được ghi nhận.

---

## 2. THIẾT LẬP HẠ TẦNG VÀ KẾT NỐI MOUNT TRỰC TIẾP

### 2.1 Cấu hình `.wslconfig`
Tạo tệp `.wslconfig` tại thư mục gốc của người dùng Windows (`C:\Users\<Tên_User>\.wslconfig`):
```ini
[wsl2]
memory=4GB
processors=2
swap=2GB
```
Khởi động lại WSL:
```cmd
wsl --shutdown
```

### 2.2 Cấu hình Mount trong `docker-compose.yml`
Container `wazuh.manager` được thiết lập mount trực tiếp 3 điểm cốt lõi:
- `./shared-logs:/var/log/datasets`: Thư mục chia sẻ tệp log giữa môi trường WSL2 và SIEM.
- `./rules/local_rules.xml:/var/ossec/etc/rules/local_rules.xml:ro`: Nạp trực tiếp bộ luật tùy chỉnh.
- `./config/wazuh_manager.conf:/wazuh-config-mount/etc/ossec.conf`: Khai báo 3 khối `<localfile>` để SIEM theo dõi:
  - `/var/log/datasets/web_access.log` (định dạng `apache`)
  - `/var/log/datasets/linux_auth.log` (định dạng `syslog`)
  - `/var/log/datasets/windows_sysmon.json` (định dạng `json`)

---

## 3. XÂY DỰNG BỘ LUẬT PHÁT HIỆN CHUẨN XÁC (`rules/local_rules.xml`)

Bộ luật được thiết kế chuẩn xác theo mã nhận diện sự kiện (SID) của Wazuh:
1. **Luật Web Attack (100100, 100101, 100102):**
   Khai báo `<if_sid>31100, 31101, 31103, 31108</if_sid>` để không bị tệp luật mặc định `0250-web_rules.xml` phân nhánh mất sự kiện. Phân tách rõ ràng giữa HTTP 403 (WAF chặn) và HTTP 200 (Payload lọt qua).
2. **Luật SSH Brute Force (100201, 100202):**
   Khai báo `<if_matched_sid>5710, 5716</if_matched_sid>` với `frequency="5"` và `timeframe="60"` để bắt cả tài khoản không tồn tại lẫn tài khoản có thật. Tương quan với SID `5715` (Accepted password) từ cùng địa chỉ IP để phát hiện xâm nhập thành công.
3. **Luật Windows Sysmon (100301, 100302):**
   - Rule 100301 kế thừa SID `61603` (Process Create) bắt lệnh PowerShell chạy ngầm hoặc mang tham số che giấu.
   - Rule 100302 kế thừa đúng SID `61615` (Registry Value Set) bắt hành vi sửa đổi khóa `CurrentVersion\Run`.
4. **Luật Tinh chỉnh Loại trừ (100401):**
   Gán `level="0"` cho tiến trình sao lưu hợp lệ của `DOMAIN\svc_backup` được gọi bởi `svchost.exe` (Task Scheduler).

---

## 4. CƠ CHẾ BƠM PAYLOAD TỪ WSL2 VÀ LÀM GIÀU DỮ LIỆU TRIAGE

### 4.1 Bơm dữ liệu qua `scripts/feed_logs.sh`
Script đọc tuần tự từng dòng từ thư mục `datasets/` và ghi nối tiếp vào `shared-logs/` với độ trễ 0.05 giây. Điều này đảm bảo:
- Bộ giải mã của Wazuh không bị dồn nén dữ liệu.
- Các luật tính tần suất (Correlation & Frequency) hoạt động chuẩn xác theo thời gian thực.

Cú pháp thực hiện trên WSL:
```bash
bash scripts/feed_logs.sh web
bash scripts/feed_logs.sh ssh
bash scripts/feed_logs.sh sysmon
bash scripts/feed_logs.sh benign
```

### 4.2 Tra cứu Threat Intelligence qua `scripts/triage_ioc_checker.py`
Công cụ viết bằng Python thuần, tự nhận diện IPv4 hoặc File Hash:
- Truy vấn điểm uy tín từ AbuseIPDB.
- Truy vấn tỷ lệ phát hiện mã độc từ VirusTotal.
- Tự kích hoạt chế độ dự phòng ngoại tuyến khi không có mạng internet.

```bash
python scripts/triage_ioc_checker.py -i 203.0.113.45
python scripts/triage_ioc_checker.py -f 44d88612fea8a8f36de82e1278abb02f
```

---

## 5. QUY TRÌNH VẬN HÀNH 4 KỊCH BẢN GIÁM SÁT TRỌNG TÂM

### Kịch bản 1: OWASP Web SQL Injection & Đối chiếu WAF
- **Dữ liệu:** `datasets/owasp_sqli.log` (OWASP ModSecurity Core Rule Set).
- **Thực thi:** `bash scripts/feed_logs.sh web`.
- **Phân tích:** Quan sát trên Dashboard cảnh báo Level 6 (WAF chặn, HTTP 403) và cảnh báo Level 12 (HTTP 200, khai thác thành công).

### Kịch bản 2: Linux SSH Brute Force & Chiếm quyền Tài khoản
- **Dữ liệu:** `datasets/openssh_bruteforce.log` (OpenSSH dataset từ Loghub).
- **Thực thi:** `bash scripts/feed_logs.sh ssh`.
- **Phân tích:** Sau 5 lần đăng nhập lỗi liên tiếp trong 60 giây, Rule 100201 kích hoạt. Ngay sau đó, sự kiện đăng nhập thành công từ cùng IP kích hoạt Rule 100202 (Critical).

### Kịch bản 3: Windows Sysmon Obfuscated PowerShell & Persistence
- **Dữ liệu:** `datasets/windows_sysmon_execution.json` (OTRF Security Datasets).
- **Thực thi:** `bash scripts/feed_logs.sh sysmon`.
- **Phân tích:** Bắt Sysmon Event ID 1 chứa chuỗi Base64. Giải mã UTF-16LE phát hiện lệnh tải file từ C2. Bắt Sysmon Event ID 13 ghi nhận khóa khởi động `WindowsUpdateCheck`.

### Kịch bản 4: Điều tra Cảnh báo Giả & Tinh chỉnh Luật (Tuning)
- **Dữ liệu:** `datasets/windows_sysmon_benign.json` (Log Task Scheduler hợp lệ trên Windows 10).
- **Thực thi:** `bash scripts/feed_logs.sh benign`.
- **Phân tích:** Tiến trình được gọi bởi `svchost.exe -k netsvcs -p -s Schedule` dưới quyền `DOMAIN\svc_backup`. Rule 100401 với `level="0"` triệt tiêu cảnh báo, loại bỏ Alert Fatigue.

---

## 6. KỸ THUẬT LỌC CẢNH BÁO TRÊN DASHBOARD VÀ TINH CHỈNH LUẬT (RULE TUNING)

### 6.1 Lọc điều tra trên giao diện Web (KQL)
- `rule.groups: "custom_soc_lab"`: Thu hẹp danh sách vào các cảnh báo thuộc dự án.
- `rule.level >= 10`: Lọc các cảnh báo có độ ưu tiên cao cần xử lý ngay.
- `data.srcip: "203.0.113.45"`: Truy vết toàn bộ hành vi liên quan đến một IP nguồn nghi vấn.

### 6.2 Kiểm thử logic với `wazuh-logtest`
Trước khi đưa luật vào vận hành, kiểm tra phân tích log trực tiếp bằng công cụ nội bộ:
```bash
head -n 1 datasets/openssh_bruteforce.log | docker exec -i my-soc-lab-main-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

### 6.3 Nạp lại bộ luật sau khi cập nhật
```bash
docker exec my-soc-lab-main-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

---

## 7. GIẢI TRÌNH KỸ THUẬT CỐT LÕI

1. **Tại sao mount thư mục `shared-logs/` thay vì cài Agent lên máy ảo riêng?**
   Mount trực tiếp giúp hệ thống tinh gọn, tiết kiệm 80% RAM, không phụ thuộc vào kết nối mạng ảo nội bộ giữa các máy ảo, đồng thời cho phép bơm các bộ dataset chuẩn quốc tế để kiểm tra tính đúng đắn của luật phát hiện một cách nhanh chóng và có thể lặp lại (reproducible).

2. **Tại sao giải mã PowerShell phải dùng UTF-16LE?**
   Kiến trúc nội bộ của Windows PowerShell sử dụng chuẩn Unicode 16-bit Little Endian. Nếu giải mã Base64 bằng UTF-8 thông thường, các byte rỗng sẽ làm hỏng cấu trúc chuỗi câu lệnh.

3. **Nguyên lý hoạt động của cơ chế Tuning bằng `level="0"`?**
   Thẻ `<rule id="100401" level="0">` kế thừa luật gốc qua `<if_sid>100301</if_sid>`. Khi thỏa mãn đồng thời cả 3 điều kiện (User sao lưu, Tiến trình cha svchost, và tên file script hợp lệ), Wazuh hạ mức độ ưu tiên về 0 và không phát cảnh báo lên Dashboard. Nếu kẻ tấn công chạy cùng lệnh nhưng dưới danh nghĩa tài khoản khác, luật mẹ 100301 vẫn phát báo động bình thường.
