# SOC Lab Project
## Cấu trúc project
*   **deployment/**: File `docker-compose.yml` để chạy Wazuh Server.
*   **endpoint-config/**: File cấu hình cho máy Windows (Sysmon config & Wazuh Agent config).
*   **manager-config/**: Các đoạn config bổ sung cho Wazuh Manager (tích hợp VirusTotal, Slack).
*   **attacks/**: Các lệnh đơn giản để giả lập tấn công (test hệ thống).
*   **evidence/**: Ảnh chụp màn hình kết quả test.

## Cách sử dụng
1.  **Dựng Server:**
    Vào thư mục `deployment`, chạy: `docker-compose up -d`
2.  **Cài Agent:**
    Cài Wazuh Agent và Sysmon lên máy Windows. Dùng file config trong `endpoint-config/` để thay thế config mặc định.
3.  **Config Manager:**
    Thêm nội dung trong `manager-config/manager_ossec.conf` vào file config của Server. Nhớ điền API Key của bạn.
4.  **Test:**
    Dùng các lệnh trong `attacks/attack-scripts.md` để thử tấn công và xem cảnh báo trên Dashboard.