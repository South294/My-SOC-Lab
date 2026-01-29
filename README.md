# 🛡️ SOC Automation Lab

> **Project Portfolio: Security Operations Center (SOC) Implementation**
> *Mục tiêu: Xây dựng hệ thống giám sát, phát hiện và phản ứng sự cố an ninh mạng tự động.*

---

## 🚀 Giới Thiệu (Introduction)
Dự án này là một *Home Lab* sử dụng **Wazuh SIEM** kết hợp với **Sysmon** để giám sát các endpoint (Windows). Mục đích chính là thực hành các kỹ năng của một SOC Analyst:
1.  Triển khai hạ tầng giám sát.
2.  Giả lập tấn công (Attack Simulation).
3.  Phân tích logs và tối ưu hóa luật phát hiện (Detection Engineering).

## 🛠️ Kỹ Năng Đạt Được (Skills Gained)
Thông qua dự án này, mình đã rèn luyện các kỹ năng:
*   **SIEM Administration:** Triển khai và quản trị Wazuh Manager/Agent.
*   **Log Analysis:** Đọc hiểu Windows Event Logs, Sysmon Logs (Event ID 1, 3, 11...).
*   **Detection Engineering:** Viết và tùy chỉnh rules để phát hiện hành vi tấn công cụ thể.
*   **Attack Simulation:** Sử dụng Hydra, PowerShell để giả lập kỹ thuật tấn công (MITRE ATT&CK Mapping).
*   **Infrastructure as Code:** Sử dụng Docker Compose để deploy hệ thống.

---

## 🏗️ Kiến Trúc Hệ Thống (Architecture)

```mermaid
graph LR
    A[Attacker (Kali Linux)] -- Attack Traffic --> B[Victim (Windows 10)]
    B -- Logs (Sysmon/Ossec) --> C[Wazuh Agent]
    C -- Encrypted Traffic --> D[Wazuh Manager (Docker)]
    D -- Alert --> E[Dashboard / VirusTotal]
```

*   **Wazuh Manager:** Server trung tâm, nhận logs, phân tích và cảnh báo.
*   **Wazuh Agent:** Cài trên máy nạn nhân, thu thập logs từ hệ điều hành.
*   **Sysmon:** Công cụ nâng cao của Microsoft giúp ghi lại chi tiết hành vi process, network connections.

---

## 📂 Cấu Trúc Dự Án
| Thư mục | Mô tả |
| :--- | :--- |
| `attacks/` | **[Quan trọng]** Các kịch bản tấn công giả lập (Red Team). |
| `detections/` | **[Quan trọng]** Phân tích logic phát hiện cho từng kịch bản (Blue Team). |
| `deployment/` | File `docker-compose.yml` để khởi chạy Wazuh Server. |
| `endpoint-config/`| Cấu hình chi tiết cho Sysmon và Wazuh Agent. |
| `manager-config/` | Cấu hình tích hợp (VirusTotal, Slack...) cho Manager. |

---

## 📖 Hướng Dẫn Chạy Lab (Quick Start)
1.  **Dựng Server:** Vào `deployment/` chạy `docker-compose up -d`.
2.  **Cài Agent:** Cài đặt Wazuh Agent lên máy Windows và trỏ về IP Server.
3.  **Thực Thi Tấn Công:** Mở file [`attacks/attack-scripts.md`](attacks/attack-scripts.md) và chạy các lệnh test.
4.  **Kiểm Tra Kết Quả:** Đọc file [`detections/detection-logic.md`](detections/detection-logic.md) để hiểu tại sao Server lại cảnh báo.

---
*Project thực hiện bởi [Nguyễn Thanh Nam] - Aspiring SOC Analyst*