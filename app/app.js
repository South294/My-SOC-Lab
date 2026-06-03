let activeAlert = null;
let activeStep = 1;
let triageNotes = {};
let triageClassify = {};

function showToast(message, type) {
  const existing = document.querySelector('.toast-notification');
  if (existing) existing.remove();
  const toast = document.createElement('div');
  toast.className = 'toast-notification';
  const colors = {
    success: 'var(--success-color)',
    error: 'var(--danger-color)',
    info: 'var(--accent-color)'
  };
  const bgColors = {
    success: 'rgba(0, 230, 118, 0.12)',
    error: 'rgba(255, 23, 68, 0.12)',
    info: 'rgba(0, 229, 255, 0.12)'
  };
  const icons = { success: '✅', error: '❌', info: 'ℹ️' };
  toast.style.cssText = `
    position: fixed; bottom: 24px; right: 24px; z-index: 10000;
    background: ${bgColors[type] || bgColors.info};
    border: 1px solid ${colors[type] || colors.info};
    color: ${colors[type] || colors.info};
    padding: 12px 20px; border-radius: 8px;
    font-size: 0.85rem; font-weight: 600;
    backdrop-filter: blur(12px);
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    animation: fadeIn 0.3s ease-out;
    font-family: var(--font-sans);
    max-width: 400px;
  `;
  toast.textContent = `${icons[type] || icons.info} ${message}`;
  document.body.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transition = 'opacity 0.3s ease'; }, 2500);
  setTimeout(() => toast.remove(), 2800);
}

const navButtons = document.querySelectorAll(".nav-btn");
const tabContents = document.querySelectorAll(".tab-content");

navButtons.forEach(btn => {
  btn.addEventListener("click", () => {
    navButtons.forEach(b => b.classList.remove("active"));
    tabContents.forEach(c => c.classList.remove("active"));
    btn.classList.add("active");
    const tabId = btn.getAttribute("data-tab");
    document.getElementById(tabId).classList.add("active");
  });
});

function initDashboard() {
  renderAlertQueue();
  selectAlert(0);
}

function renderAlertQueue() {
  const tbody = document.getElementById("alert-queue-body");
  tbody.innerHTML = "";
  incidentAlerts.forEach((alert, index) => {
    const tr = document.createElement("tr");
    tr.className = "alert-row";
    if (activeAlert && activeAlert.id === alert.id) {
      tr.classList.add("selected");
    }
    const sevClass = `sev-${alert.severity.toLowerCase()}`;
    const statusClass = `status-${alert.status.toLowerCase().replace(/\s+/g, '-')}`;
    tr.innerHTML = `
      <td>${alert.id}</td>
      <td><span class="sev-badge ${sevClass}">${alert.severity}</span></td>
      <td class="rule-name-cell" title="${alert.ruleDesc}">${alert.ruleDesc}</td>
      <td><code>${alert.host}</code></td>
      <td><span class="status-badge ${statusClass}">${alert.status}</span></td>
    `;
    tr.addEventListener("click", () => {
      selectAlert(index);
    });
    tbody.appendChild(tr);
  });
}

function selectAlert(index) {
  activeAlert = incidentAlerts[index];
  activeStep = 1;
  renderAlertQueue();
  updateTriageWorkspace();
  const workspace = document.querySelector('.workspace-card');
  if (workspace && window.innerWidth < 1300) {
    workspace.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

function updateTriageWorkspace() {
  if (!activeAlert) return;
  document.getElementById("workspace-title").textContent = `Không gian xử lý: ${activeAlert.id}`;
  document.getElementById("ws-meta-rule").textContent = `Rule ID: ${activeAlert.ruleId} | Level ${activeAlert.level}`;
  document.getElementById("ws-meta-host").textContent = `Host: ${activeAlert.host} (${activeAlert.ip})`;
  const steps = [1, 2, 3, 4, 5];
  steps.forEach(step => {
    const node = document.getElementById(`step-node-${step}`);
    node.className = "step-node";
    if (step < activeStep) {
      node.classList.add("completed");
    } else if (step === activeStep) {
      node.classList.add("active");
    }
  });
  document.querySelectorAll(".triage-step-content").forEach(el => el.classList.add("hidden"));
  document.getElementById(`triage-step-${activeStep}`).classList.remove("hidden");
  if (activeStep === 1) {
    document.getElementById("triage-raw-log").value = JSON.stringify(activeAlert.rawLog, null, 2);
  } else if (activeStep === 2) {
    parseAlertLog(activeAlert);
  } else if (activeStep === 3) {
    runEnrichment(activeAlert);
  } else if (activeStep === 4) {
    loadPlaybookAndTuning(activeAlert);
  } else if (activeStep === 5) {
    loadReportGeneration(activeAlert);
  }
  document.getElementById("btn-prev-step").disabled = (activeStep === 1);
  if (activeStep === 5) {
    document.getElementById("btn-next-step").classList.add("hidden");
  } else {
    document.getElementById("btn-next-step").classList.remove("hidden");
    document.getElementById("btn-next-step").disabled = false;
  }
}

document.getElementById("btn-prev-step").addEventListener("click", () => {
  if (activeStep > 1) {
    activeStep--;
    updateTriageWorkspace();
  }
});

document.getElementById("btn-next-step").addEventListener("click", () => {
  if (activeStep < 5) {
    activeStep++;
    updateTriageWorkspace();
  }
});

document.getElementById("btn-verify-log").addEventListener("click", () => {
  activeStep = 2;
  updateTriageWorkspace();
});

function parseAlertLog(alert) {
  const log = alert.rawLog;
  document.getElementById("p-agent").textContent = log.agent?.name || "N/A";
  document.getElementById("p-ip").textContent = log.agent?.ip || "N/A";
  document.getElementById("p-eventid").textContent = log.data?.win?.system?.eventID || "N/A";
  document.getElementById("p-rule").textContent = `Rule ${log.rule?.id} - Level ${log.rule?.level}`;
  document.getElementById("p-desc").textContent = log.rule?.description || "N/A";
  const image = log.data?.win?.eventdata?.image || "N/A";
  const cmdLine = log.data?.win?.eventdata?.commandLine || "N/A";
  const parentImage = log.data?.win?.eventdata?.parentImage || "N/A";
  const target = log.data?.win?.eventdata?.targetObject || log.data?.win?.eventdata?.targetFilename || log.data?.win?.eventdata?.details || "N/A";
  const mitreIds = log.rule?.mitre?.id ? log.rule.mitre.id.join(", ") : "N/A";
  document.getElementById("p-image").textContent = image;
  document.getElementById("p-cmdline").textContent = cmdLine;
  document.getElementById("p-parent").textContent = parentImage;
  document.getElementById("p-target").textContent = target;
  document.getElementById("p-mitre").textContent = mitreIds;
}

function runEnrichment(alert) {
  const log = alert.rawLog;
  const ip = alert.srcIp;
  const cmdLine = log.data?.win?.eventdata?.commandLine || "";
  document.getElementById("enrich-ip-val").textContent = ip;
  const isPrivate = isPrivateIP(ip);
  const ipTypeEl = document.getElementById("enrich-ip-type");
  const ipDescEl = document.getElementById("enrich-ip-desc");
  const intelLinksEl = document.getElementById("enrich-intel-links");
  if (isPrivate) {
    ipTypeEl.textContent = "Private IP (Dải mạng nội bộ)";
    ipTypeEl.className = "ip-type private";
    ipDescEl.textContent = "Đây là địa chỉ IP nội bộ theo RFC 1918. An toàn hoặc cần điều tra dịch chuyển ngang hàng (Lateral Movement).";
    intelLinksEl.classList.add("hidden");
  } else {
    ipTypeEl.textContent = "Public IP (Địa chỉ Internet)";
    ipTypeEl.className = "ip-type public";
    ipDescEl.textContent = "Cảnh báo kết nối từ/đến Internet. Hãy tra cứu danh tiếng nguồn để xác định IP độc hại.";
    intelLinksEl.classList.remove("hidden");
    document.getElementById("e-link-vt").href = `https://www.virustotal.com/gui/ip-address/${ip}`;
    document.getElementById("e-link-abuse").href = `https://www.abuseipdb.com/check/${ip}`;
    document.getElementById("e-link-otx").href = `https://otx.alienvault.com/indicator/ip/${ip}`;
  }
  const psCard = document.getElementById("enrich-ps-card");
  const isPowerShell = cmdLine.toLowerCase().includes("-encodedcommand") || cmdLine.toLowerCase().includes("-enc");
  if (isPowerShell) {
    psCard.classList.remove("hidden");
    const regex = /-(e|en|enc|encoded|encodedcommand)\s+([A-Za-z0-9+/=]+)/i;
    const match = cmdLine.match(regex);
    if (match && match[2]) {
      const decodedText = decodeUTF16LE(match[2]);
      document.getElementById("enrich-ps-output").textContent = decodedText || "Lỗi giải mã Base64";
      const suspiciousKeywords = [
        { word: "invoke-webrequest", desc: "Tải file từ Internet sử dụng PowerShell WebRequest." },
        { word: "downloadfile", desc: "Sử dụng Net.WebClient để tải tệp độc hại." },
        { word: "iex", desc: "Thực thi trực tiếp mã lệnh trong bộ nhớ (Invoke-Expression)." },
        { word: "evil.com", desc: "Kết nối Command & Control (C2) độc hại." }
      ];
      const flags = [];
      suspiciousKeywords.forEach(item => {
        if (decodedText.toLowerCase().includes(item.word)) {
          flags.push(`<li><strong>Phát hiện: ${item.word}</strong> - ${item.desc}</li>`);
        }
      });
      document.getElementById("enrich-ps-flags").innerHTML = flags.length > 0 ? flags.join("") : "<li>Chưa phát hiện hành vi độc hại trực diện trong từ khóa kiểm tra.</li>";
    } else {
      document.getElementById("enrich-ps-output").textContent = "Không tìm thấy tham số mã hóa.";
      document.getElementById("enrich-ps-flags").innerHTML = "<li>N/A</li>";
    }
  } else {
    psCard.classList.add("hidden");
  }
}

function loadPlaybookAndTuning(alert) {
  const playbook = playbooks[alert.sopKey];
  if (playbook) {
    document.getElementById("sop-triage-view").innerHTML = `<h3>${playbook.title}</h3>${playbook.content}`;
  } else {
    document.getElementById("sop-triage-view").innerHTML = "<p>Không tìm thấy SOP cụ thể cho loại cảnh báo này.</p>";
  }
  const savedClass = triageClassify[alert.id] || "";
  const savedNotes = triageNotes[alert.id] || "";
  if (savedClass === "TP") {
    document.getElementById("classify-tp").checked = true;
    showTriageResponseArea("TP");
  } else if (savedClass === "FP") {
    document.getElementById("classify-fp").checked = true;
    showTriageResponseArea("FP");
  } else {
    document.getElementById("classify-tp").checked = false;
    document.getElementById("classify-fp").checked = false;
    document.getElementById("response-tp-area").classList.add("hidden");
    document.getElementById("response-fp-area").classList.add("hidden");
  }
  document.getElementById("ws-notes").value = savedNotes;
  const log = alert.rawLog;
  document.getElementById("ws-tune-parent-id").value = alert.ruleId;
  document.getElementById("ws-tune-rule-id").value = parseInt(alert.ruleId) + 500;
  const image = log.data?.win?.eventdata?.image || "";
  const user = log.data?.win?.eventdata?.user || "";
  const originalFileName = log.data?.win?.eventdata?.originalFileName || "";
  if (originalFileName) {
    document.getElementById("ws-tune-field").value = "win.eventdata.originalFileName";
    document.getElementById("ws-tune-value").value = originalFileName.replace(/\./g, "\\.");
  } else if (image) {
    document.getElementById("ws-tune-field").value = "win.eventdata.image";
    const parts = image.split('\\');
    document.getElementById("ws-tune-value").value = parts[parts.length - 1].replace(/\./g, "\\.");
  } else if (user) {
    document.getElementById("ws-tune-field").value = "win.eventdata.user";
    document.getElementById("ws-tune-value").value = user;
  }
}

function showTriageResponseArea(type) {
  if (type === "TP") {
    document.getElementById("response-tp-area").classList.remove("hidden");
    document.getElementById("response-fp-area").classList.add("hidden");
  } else {
    document.getElementById("response-tp-area").classList.add("hidden");
    document.getElementById("response-fp-area").classList.remove("hidden");
    generateTuningRuleInline();
  }
}

document.getElementById("classify-tp").addEventListener("change", () => {
  triageClassify[activeAlert.id] = "TP";
  activeAlert.status = "Investigating";
  renderAlertQueue();
  showTriageResponseArea("TP");
});

document.getElementById("classify-fp").addEventListener("change", () => {
  triageClassify[activeAlert.id] = "FP";
  activeAlert.status = "Investigating";
  renderAlertQueue();
  showTriageResponseArea("FP");
});

function generateTuningRuleInline() {
  const parentId = document.getElementById("ws-tune-parent-id").value.trim();
  const ruleId = document.getElementById("ws-tune-rule-id").value.trim();
  const field = document.getElementById("ws-tune-field").value;
  const val = document.getElementById("ws-tune-value").value.trim();
  const desc = document.getElementById("ws-tune-desc").value.trim();
  const xml = `<rule id="${ruleId}" level="0">
  <if_sid>${parentId}</if_sid>
  <field name="${field}" type="pcre2">(?i)${val}</field>
  <description>False Positive: ${desc}</description>
</rule>`;
  document.getElementById("ws-generated-rule").textContent = xml;
}

document.getElementById("ws-tune-field").addEventListener("change", generateTuningRuleInline);
document.getElementById("ws-tune-value").addEventListener("input", generateTuningRuleInline);
document.getElementById("ws-tune-desc").addEventListener("input", generateTuningRuleInline);
document.getElementById("ws-btn-generate-rule").addEventListener("click", generateTuningRuleInline);
document.getElementById("ws-btn-copy-rule").addEventListener("click", () => {
  const xml = document.getElementById("ws-generated-rule").textContent;
  navigator.clipboard.writeText(xml).then(() => {
    showToast("Đã sao chép rule XML loại trừ.", "success");
  });
});

function loadReportGeneration(alert) {
  triageNotes[alert.id] = document.getElementById("ws-notes").value;
  const classification = triageClassify[alert.id] || "Investigating";
  const notes = triageNotes[alert.id] || "";
  const severity = alert.severity;
  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  const log = alert.rawLog;
  const image = log.data?.win?.eventdata?.image || "N/A";
  const cmdLine = log.data?.win?.eventdata?.commandLine || "N/A";
  const md = `# BÁO CÁO ĐIỀU TRA SỰ CỐ: ${alert.id}
  
## 1. THÔNG TIN CHUNG
- **Incident Ticket ID:** ${alert.id}
- **Tên cảnh báo:** ${alert.ruleDesc}
- **Mức độ nghiêm trọng (Severity):** ${severity}
- **Trạng thái phân loại:** ${classification === "TP" ? "True Positive (Sự cố thực tế)" : "False Positive (Cảnh báo giả)"}
- **Người xử lý (Analyst):** L1 SOC Analyst
- **Thời gian phân tích:** ${timestamp}

## 2. ĐỐI TƯỢNG BỊ ẢNH HƯỞNG (SCOPE & ENRICHMENT)
- **Thiết bị:** ${alert.host} (Địa chỉ IP: \`${alert.ip}\`)
- **Nguồn tấn công (Source IP):** \`${alert.srcIp}\`
- **Wazuh Rule ID:** ${alert.ruleId} (Sysmon Event ID: ${log.data?.win?.system?.eventID || "N/A"})
- **MITRE ATT&CK Mapping:** ${alert.mitre}

## 3. CHI TIẾT KỸ THUẬT (TECHNICAL EVIDENCE)
- **Tiến trình thực thi (Image):** \`${image}\`
- **Dòng lệnh (CommandLine):** \`${cmdLine}\`

## 4. QUY TRÌNH XỬ LÝ (INVESTIGATION LOGS)
${notes || "Chưa ghi chép nhật ký phân tích."}

${classification === "FP" ? `## 5. PHƯƠNG ÁN SIEM TUNING (RULE SUPPRESSION)
- Đã tạo rule loại trừ Wazuh để tối ưu hóa hệ thống, giảm thiểu cảnh báo lặp lại cho tiến trình này.
- Custom Rule ID được tạo: \`${parseInt(alert.ruleId) + 500}\`
` : `## 5. PHƯƠNG ÁN NGĂN CHẶN (CONTAINMENT & REMEDIATION)
- Cách ly thiết bị ảnh hưởng khỏi mạng (Host Isolation).
- Kết thúc (Kill) các tiến trình nghi ngờ liên đới.
- Thực hiện thu hồi phiên hoạt động và thay đổi thông tin xác thực tài khoản.
`}
`;
  document.getElementById("ws-report-preview").textContent = md;
}

document.getElementById("ws-btn-download-report").addEventListener("click", () => {
  const md = document.getElementById("ws-report-preview").textContent;
  const classification = triageClassify[activeAlert.id] || "TP";
  activeAlert.status = (classification === "TP") ? "Closed - TP" : "Closed - FP";
  renderAlertQueue();
  const blob = new Blob([md], { type: "text/markdown;charset=utf-8;" });
  const link = document.createElement("a");
  if (link.download !== undefined) {
    const url = URL.createObjectURL(blob);
    link.setAttribute("href", url);
    link.setAttribute("download", `${activeAlert.id}_Report.md`);
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }
  showToast(`Đã xuất báo cáo và đóng sự cố: ${activeAlert.status}`, "success");
});

function decodeUTF16LE(base64Str) {
  try {
    const binaryString = atob(base64Str.trim());
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return new TextDecoder('utf-16le').decode(bytes);
  } catch (e) {
    return null;
  }
}

document.getElementById("decode-btn").addEventListener("click", () => {
  const input = document.getElementById("ps-input").value.trim();
  const placeholder = document.getElementById("decoder-result-placeholder");
  const dataPanel = document.getElementById("decoder-result-data");
  const output = document.getElementById("decoded-output");
  const flagsList = document.getElementById("suspicious-flags");
  if (!input) {
    showToast("Vui lòng nhập mã lệnh PowerShell.", "error");
    return;
  }
  flagsList.innerHTML = "";
  let decodedText = "";
  let hasBase64 = false;
  const regex = /-(e|en|enc|encoded|encodedcommand)\s+([A-Za-z0-9+/=]+)/i;
  const match = input.match(regex);
  if (match && match[2]) {
    decodedText = decodeUTF16LE(match[2]);
    hasBase64 = true;
  } else {
    try {
      const attemptDirect = decodeUTF16LE(input);
      if (attemptDirect && /^[a-zA-Z0-9\s_\-\.\$\(\)\{\}\[\]\\\/:"',;+=*&^%#@!~`?|<>]*$/.test(attemptDirect.replace(/[^\x20-\x7E]/g, ""))) {
        decodedText = attemptDirect;
        hasBase64 = true;
      } else {
        decodedText = input;
      }
    } catch (e) {
      decodedText = input;
    }
  }
  if (!decodedText) {
    decodedText = "Lỗi: Không thể giải mã chuỗi Base64. Định dạng không hợp lệ.";
  }
  output.textContent = decodedText;
  const suspiciousKeywords = [
    { word: "invoke-webrequest", desc: "Tải file từ Internet sử dụng PowerShell WebRequest.", class: "danger" },
    { word: "downloadfile", desc: "Sử dụng Net.WebClient để tải tệp tin chạy ngầm.", class: "danger" },
    { word: "vssadmin", desc: "Thao tác trên các bản sao lưu Volume Shadow Copy (Ransomware).", class: "danger" },
    { word: "delete shadows", desc: "Xóa các bản sao lưu phục hồi hệ thống.", class: "danger" },
    { word: "currentversion\\run", desc: "Can thiệp khởi động cùng hệ điều hành qua Registry Run Key.", class: "warning" },
    { word: "hidden", desc: "Chạy PowerShell ẩn giao diện màn hình.", class: "warning" },
    { word: "bypass", desc: "Bỏ qua cấu hình Execution Policy của hệ thống.", class: "warning" },
    { word: "iex", desc: "Thực thi trực tiếp một chuỗi câu lệnh (Invoke-Expression).", class: "danger" },
    { word: "evil.com", desc: "Kết nối Command & Control (C2) độc hại.", class: "danger" }
  ];
  let foundFlags = 0;
  suspiciousKeywords.forEach(item => {
    if (decodedText.toLowerCase().includes(item.word)) {
      const li = document.createElement("li");
      li.innerHTML = `<strong>Phát hiện từ khóa: ${item.word}</strong> - ${item.desc}`;
      li.className = (item.class === "warning") ? "warning" : "";
      flagsList.appendChild(li);
      foundFlags++;
    }
  });
  if (hasBase64) {
    const li = document.createElement("li");
    li.innerHTML = `<strong>Encoded Command Detected</strong> - Sử dụng tham số mã hóa Base64 để vượt qua hệ thống giám sát.`;
    li.className = "warning";
    flagsList.insertBefore(li, flagsList.firstChild);
    foundFlags++;
  }
  if (foundFlags === 0) {
    const li = document.createElement("li");
    li.innerHTML = `Không phát hiện từ khóa nguy hiểm nào trong danh sách kiểm tra.`;
    li.style.borderLeftColor = "var(--success-color)";
    li.style.backgroundColor = "rgba(16, 185, 129, 0.1)";
    flagsList.appendChild(li);
  }
  placeholder.classList.add("hidden");
  dataPanel.classList.remove("hidden");
});

document.getElementById("generate-rule-btn").addEventListener("click", () => {
  const parentId = document.getElementById("tune-parent-id").value.trim();
  const ruleId = document.getElementById("tune-rule-id").value.trim();
  const field = document.getElementById("tune-field").value;
  const val = document.getElementById("tune-value").value.trim();
  const desc = document.getElementById("tune-desc").value.trim();
  if (!parentId || !ruleId || !val || !desc) {
    showToast("Vui lòng điền đầy đủ các trường để sinh rule.", "error");
    return;
  }
  const xml = `<rule id="${ruleId}" level="0">
  <if_sid>${parentId}</if_sid>
  <field name="${field}" type="pcre2">(?i)${val}</field>
  <description>False Positive: ${desc}</description>
</rule>`;
  document.getElementById("generated-rule-output").textContent = xml;
  document.getElementById("rule-result-placeholder").classList.add("hidden");
  document.getElementById("rule-result-data").classList.remove("hidden");
  document.getElementById("tuning-impact-metrics").classList.remove("hidden");
});

document.getElementById("copy-rule-btn").addEventListener("click", () => {
  const xml = document.getElementById("generated-rule-output").textContent;
  navigator.clipboard.writeText(xml).then(() => {
    showToast("Đã sao chép rule XML loại trừ vào Clipboard.", "success");
  });
});

const sopButtons = document.querySelectorAll(".sop-nav-btn");
const sopContentArea = document.getElementById("sop-content-area");

function loadSop(sopKey) {
  const sop = playbooks[sopKey];
  if (sop) {
    sopContentArea.innerHTML = `<h2>${sop.title}</h2>${sop.content}`;
  }
}

sopButtons.forEach(btn => {
  btn.addEventListener("click", () => {
    sopButtons.forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    loadSop(btn.getAttribute("data-sop"));
  });
});

loadSop("sop-smb");

const genButtons = document.querySelectorAll(".gen-nav-btn");

function loadGenEvent(genKey) {
  const event = eventGenData[genKey];
  if (event) {
    document.getElementById("gen-event-title").textContent = event.title;
    document.getElementById("gen-cmd-output").textContent = event.cmd;
    document.getElementById("gen-log-output").textContent = JSON.stringify(event.log, null, 2);
  }
}

genButtons.forEach(btn => {
  btn.addEventListener("click", () => {
    genButtons.forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    loadGenEvent(btn.getAttribute("data-gen"));
  });
});

document.getElementById("btn-copy-gen-cmd").addEventListener("click", () => {
  const cmd = document.getElementById("gen-cmd-output").textContent;
  navigator.clipboard.writeText(cmd).then(() => {
    showToast("Đã sao chép lệnh giả lập.", "success");
  });
});

document.getElementById("btn-copy-gen-log").addEventListener("click", () => {
  const log = document.getElementById("gen-log-output").textContent;
  navigator.clipboard.writeText(log).then(() => {
    showToast("Đã sao chép log JSON.", "success");
  });
});

document.getElementById("btn-load-to-triage").addEventListener("click", () => {
  const key = document.querySelector(".gen-nav-btn.active").getAttribute("data-gen");
  const event = eventGenData[key];
  if (!event) return;
  const newId = `ALR-GEN-${Math.floor(100 + Math.random() * 900)}`;
  const mappedSop = (event.log.rule.id === "100001") ? "sop-smb" :
                    (event.log.rule.id === "100002") ? "sop-ransomware" :
                    (event.log.rule.id === "100003") ? "sop-registry" :
                    (event.log.rule.id === "100004") ? "sop-powershell" : "sop-malware";
  const newAlert = {
    id: newId,
    time: new Date().toISOString().replace('T', ' ').substring(0, 19),
    ruleId: event.log.rule.id,
    ruleDesc: event.log.rule.description,
    level: event.log.rule.level,
    severity: (event.log.rule.level >= 12) ? "Critical" : "High",
    host: event.log.agent.name,
    ip: event.log.agent.ip,
    srcIp: event.log.data.win.eventdata.ipAddress || "127.0.0.1",
    status: "New",
    mitre: event.log.rule.mitre.id.join(", "),
    sopKey: mappedSop,
    rawLog: event.log
  };
  incidentAlerts.push(newAlert);
  renderAlertQueue();
  selectAlert(incidentAlerts.length - 1);
  document.querySelector('[data-tab="dashboard-triage"]').click();
  showToast(`Đã nạp thành công sự cố ${newId} vào Bảng Triage.`, "success");
});

loadGenEvent("gen-smb");

function isPrivateIP(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  return false;
}

window.addEventListener("DOMContentLoaded", () => {
  initDashboard();
});
