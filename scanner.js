/**
 * scanner.js — Main frontend logic for the URL Security Scanner
 * Communicates with the Flask backend at /api/scan
 */

"use strict";

// ── State ──────────────────────────────────────────────────────────────────
const state = {
  history:     [],
  lastResult:  null,
  scanning:    false,
};

// ── DOM refs ───────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const urlInput    = $("url-input");
const scanBtn     = $("scan-btn");
const btnText     = scanBtn.querySelector(".btn-text");
const btnSpinner  = scanBtn.querySelector(".btn-spinner");
const emptyState  = $("empty-state");
const scanState   = $("scanning-state");
const resultState = $("result-state");
const tabResult   = $("tab-result");
const tabHistory  = $("tab-history");

// ── Typing header animation ────────────────────────────────────────────────
(function typeHeader() {
  const el   = document.querySelector(".site-title");
  const text = "SMART URL SECURITY SCANNER";
  let i = 0;
  el.textContent = "";
  const t = setInterval(() => {
    el.textContent = text.slice(0, ++i);
    if (i >= text.length) clearInterval(t);
  }, 55);
})();

// ── Backend health check ───────────────────────────────────────────────────
async function checkBackend() {
  const dot  = $("status-dot");
  const text = $("status-text");
  try {
    const r = await fetch("/api/health", { signal: AbortSignal.timeout(4000) });
    if (r.ok) {
      const d = await r.json();
      dot.className  = "status-dot online";
      text.textContent = `BACKEND ONLINE · VT:${d.vt_ready ? "✓" : "✗"} · ZAP:${d.zap_url}`;
      return true;
    }
  } catch (_) {}
  dot.className   = "status-dot offline";
  text.textContent = "BACKEND OFFLINE — run: python app.py";
  text.style.color = "#ff3550";
  return false;
}
checkBackend();

// ── Tab switching ──────────────────────────────────────────────────────────
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    const target = btn.dataset.tab;
    tabResult.classList.toggle ("hidden", target !== "result");
    tabHistory.classList.toggle("hidden", target !== "history");
  });
});

// ── Quick test buttons ─────────────────────────────────────────────────────
document.querySelectorAll(".quick-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    urlInput.value = btn.dataset.url;
    urlInput.focus();
  });
});

// ── Enter key ─────────────────────────────────────────────────────────────
urlInput.addEventListener("keydown", e => {
  if (e.key === "Enter" && !state.scanning) startScan();
});

// ── Scan button ────────────────────────────────────────────────────────────
scanBtn.addEventListener("click", () => {
  if (!state.scanning) startScan();
});

// ── Scan steps ─────────────────────────────────────────────────────────────
const STEPS = [
  "Resolving domain…",
  "Checking HTTPS & structure…",
  "Detecting phishing patterns…",
  "Testing injection vectors…",
  "Querying VirusTotal…",
  "Running OWASP ZAP…",
  "Building report…",
];

let stepIndex = 0, stepTimer = null;

function startStepAnimation() {
  const items = document.querySelectorAll(".scan-steps li");
  stepIndex = 0;
  items.forEach(li => { li.className = ""; });

  stepTimer = setInterval(() => {
    if (stepIndex > 0) items[stepIndex - 1].className = "done";
    if (stepIndex < items.length) {
      items[stepIndex].className = "current";
      stepIndex++;
    }
  }, 600);
}

function stopStepAnimation() {
  clearInterval(stepTimer);
  document.querySelectorAll(".scan-steps li").forEach(li => li.className = "done");
}

// ── Main scan function ─────────────────────────────────────────────────────
async function startScan() {
  const url = urlInput.value.trim();
  if (!url) { urlInput.focus(); return; }

  state.scanning = true;
  setScanningUI(true);
  showPanel("scanning");
  startStepAnimation();

  try {
    const runVT  = $("opt-vt").checked;
    const runZAP = $("opt-zap").checked;

    const resp = await fetch("/api/scan", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url, virustotal: runVT, zap: runZAP }),
    });

    stopStepAnimation();

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.error || `Server returned ${resp.status}`);
    }

    const data = await resp.json();
    state.lastResult = data;
    renderResult(data);
    addToHistory(url, data);
    showPanel("result");

  } catch (err) {
    stopStepAnimation();
    showPanel("empty");
    showError(err.message || "Could not reach backend. Is Flask running on port 5000?");
  } finally {
    state.scanning = false;
    setScanningUI(false);
  }
}

// ── UI helpers ─────────────────────────────────────────────────────────────
function setScanningUI(isScanning) {
  scanBtn.disabled          = isScanning;
  btnText.classList.toggle  ("hidden", isScanning);
  btnSpinner.classList.toggle("hidden", !isScanning);
  if (!isScanning) btnSpinner.innerHTML = "";
  else btnSpinner.innerHTML = '<span class="spinner"></span>';
}

function showPanel(name) {
  emptyState .classList.toggle("hidden", name !== "empty");
  scanState  .classList.toggle("hidden", name !== "scanning");
  resultState.classList.toggle("hidden", name !== "result");
}

function showError(msg) {
  emptyState.innerHTML = `
    <div class="empty-icon" style="color:#ff355033">⚠</div>
    <div class="empty-text" style="color:#ff3550">${escHtml(msg)}</div>
    <div class="empty-sub">Check that <code>python app.py</code> is running</div>`;
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ── Render result ──────────────────────────────────────────────────────────
function renderResult(data) {
  const local = data.local;
  const score = data.aggregate_score ?? local.score;
  const color = riskColor(score);

  // Gauge
  const gaugeScore = $("gauge-score");
  const gaugeLabel = $("gauge-label");
  const gaugeBar   = $("gauge-bar");
  gaugeScore.textContent   = score;
  gaugeScore.style.color   = color;
  gaugeScore.style.textShadow = `0 0 30px ${color}88`;
  gaugeLabel.textContent   = `RISK: ${riskLabel(score)}`;
  gaugeLabel.style.color   = color;
  gaugeBar.style.width     = score + "%";
  gaugeBar.style.background= `linear-gradient(90deg, #00ff6a, ${color})`;

  // Source labels
  const sources = [];
  if (data.virustotal?.available) sources.push('<span style="color:#9b59ff">🛡 VT included</span>');
  if (data.zap?.available)        sources.push('<span style="color:#ffb300">⚡ ZAP included</span>');
  $("gauge-sources").innerHTML = sources.join(" · ");

  // Checks
  const checksList = $("checks-list");
  checksList.innerHTML = local.checks.map(c => `
    <div class="check-row">
      <span class="clabel">${escHtml(c.label)}</span>
      <span class="cstatus ${c.status}">${statusIcon(c.status)} ${c.status.toUpperCase()}</span>
    </div>`).join("");

  // Issues
  const issuesList = $("issues-list");
  $("issues-count").textContent = local.issues.length;
  if (local.issues.length === 0) {
    issuesList.innerHTML = '<span class="tag tag-ok">✓ No issues detected</span>';
  } else {
    issuesList.innerHTML = local.issues.map((iss, i) => `
      <div class="issue-item ${iss.type}" style="animation-delay:${i * 0.06}s">
        <span class="tag tag-${iss.type === 'bad' ? 'bad' : iss.type === 'warn' ? 'warn' : 'ok'}">${escHtml(iss.cat)}</span>
        <span class="issue-msg">${escHtml(iss.msg)}</span>
      </div>`).join("");
  }

  // VirusTotal
  renderVT(data.virustotal);

  // ZAP
  renderZAP(data.zap);

  // Recommendations
  $("recs-list").innerHTML = local.recommendations
    .map(r => `<li>${escHtml(r)}</li>`).join("");

  // URL meta
  $("url-meta").innerHTML = `
    <span>HOSTNAME:</span>${escHtml(local.hostname)}<br>
    <span>PROTOCOL:</span>${escHtml(local.protocol)}<br>
    <span>PATH:</span>${escHtml((local.path || "").slice(0, 100))}`;

  // Export
  $("export-btn").onclick = () => exportReport(data, score);
}

// ── VirusTotal renderer ────────────────────────────────────────────────────
function renderVT(vt) {
  const panel   = $("vt-panel");
  const content = $("vt-content");
  if (!vt) { panel.style.display = "none"; return; }
  panel.style.display = "block";

  if (!vt.available) {
    content.innerHTML = `<div style="color:#ff3550;font-size:12px">⚠ ${escHtml(vt.error || "Unavailable")}</div>
      ${vt.setup ? `<div style="color:#3a6a4a;font-size:11px;margin-top:6px">${escHtml(vt.setup)}</div>` : ""}`;
    return;
  }
  if (vt.status === "timeout") {
    content.innerHTML = `<div style="color:#ffb300;font-size:12px">⏱ ${escHtml(vt.error)}</div>`;
    return;
  }

  const malColor = vt.malicious > 0 ? "#ff3550" : "#00ff6a";
  const flagHTML = (vt.flagged_by || []).map(f =>
    `<span class="tag tag-bad" style="font-size:9px">${escHtml(f.engine)}: ${escHtml(f.result)}</span>`
  ).join("");

  content.innerHTML = `
    <div class="vt-grid">
      <div class="vt-stat"><div class="vt-num" style="color:#ff3550">${vt.malicious}</div><div class="vt-lbl">Malicious</div></div>
      <div class="vt-stat"><div class="vt-num" style="color:#ffb300">${vt.suspicious}</div><div class="vt-lbl">Suspicious</div></div>
      <div class="vt-stat"><div class="vt-num" style="color:#00ff6a">${vt.harmless}</div><div class="vt-lbl">Harmless</div></div>
      <div class="vt-stat"><div class="vt-num" style="color:#4a7a5a">${vt.undetected}</div><div class="vt-lbl">Undetected</div></div>
    </div>
    <div class="vt-info">
      Scanned by <strong style="color:#c8ffd4">${vt.total_engines}</strong> engines ·
      Detection rate: <strong style="color:${malColor}">${vt.detection_rate ?? 0}%</strong>
    </div>
    ${flagHTML ? `<div style="font-family:'Orbitron',monospace;font-size:9px;color:#4a7a5a;letter-spacing:2px;margin-bottom:8px">FLAGGED BY</div>
      <div class="vt-engines">${flagHTML}</div>` : ""}
    ${vt.vt_link && vt.vt_link !== "#" ? `<a class="vt-link" href="${escHtml(vt.vt_link)}" target="_blank" rel="noopener">↗ View full report on VirusTotal</a>` : ""}`;
}

// ── ZAP renderer ──────────────────────────────────────────────────────────
function renderZAP(zap) {
  const panel   = $("zap-panel");
  const content = $("zap-content");
  if (!zap) { panel.style.display = "none"; return; }
  panel.style.display = "block";

  $("zap-version").textContent = zap.zap_version ? `v${zap.zap_version}` : "";

  if (!zap.available) {
    content.innerHTML = `<div style="color:#ff3550;font-size:12px">⚠ ${escHtml(zap.error || "ZAP unavailable")}</div>
      ${zap.setup ? `<div style="color:#3a6a4a;font-size:11px;margin-top:6px">$ ${escHtml(zap.setup)}</div>` : ""}`;
    return;
  }

  const rc = zap.risk_counts || {};
  const RISK_COLORS = { High:"#ff3550", Medium:"#ffb300", Low:"#00b4ff", Informational:"#4a7a5a" };

  const summaryHTML = Object.entries(rc).filter(([,v]) => v > 0).map(([k, v]) => `
    <div class="zap-stat">
      <div class="znum" style="color:${RISK_COLORS[k]}">${v}</div>
      <div class="zlbl">${k}</div>
    </div>`).join("");

  const alertsHTML = (zap.alerts || []).map((a, i) => `
    <div class="alert-item">
      <div class="alert-header" onclick="toggleAlert(this)">
        <div class="alert-header-left">
          <span class="tag" style="background:${RISK_COLORS[a.risk]}18;color:${RISK_COLORS[a.risk]};border:1px solid ${RISK_COLORS[a.risk]}44;font-size:9px">${escHtml(a.risk)}</span>
          <span class="alert-name">${escHtml(a.name)}</span>
        </div>
        <span class="alert-chevron">▼</span>
      </div>
      <div class="alert-body">
        ${a.description ? `<div class="alert-field"><span>DESC: </span>${escHtml(a.description)}</div>` : ""}
        ${a.solution    ? `<div class="alert-field"><span>FIX:  </span>${escHtml(a.solution)}</div>` : ""}
        ${a.evidence    ? `<div class="alert-field"><span>EVIDENCE: </span>${escHtml(a.evidence)}</div>` : ""}
        <div class="alert-cwe-row">
          ${a.cweid  ? `<span class="tag tag-info" style="font-size:9px">CWE-${escHtml(a.cweid)}</span>` : ""}
          ${a.wascid ? `<span class="tag tag-warn" style="font-size:9px">WASC-${escHtml(a.wascid)}</span>` : ""}
        </div>
      </div>
    </div>`).join("");

  content.innerHTML = `
    <div class="zap-summary">${summaryHTML}</div>
    ${zap.total_alerts > 0
      ? `<div style="font-family:'Orbitron',monospace;font-size:9px;color:#4a7a5a;letter-spacing:2px;margin-bottom:10px">
          ALERTS (${zap.total_alerts})
        </div>${alertsHTML}`
      : '<span class="tag tag-ok">✓ No alerts found by ZAP</span>'}`;
}

// ── Alert accordion ────────────────────────────────────────────────────────
window.toggleAlert = function(header) {
  const body    = header.nextElementSibling;
  const chevron = header.querySelector(".alert-chevron");
  const isOpen  = body.classList.toggle("open");
  chevron.classList.toggle("open", isOpen);
};

// ── History ────────────────────────────────────────────────────────────────
function addToHistory(url, data) {
  const score = data.aggregate_score ?? data.local.score;
  state.history.unshift({ url, score, data, ts: Date.now() });
  if (state.history.length > 20) state.history.pop();
  renderHistory();
}

function renderHistory() {
  const list = $("history-list");
  $("history-count").textContent = `(${state.history.length})`;

  if (state.history.length === 0) {
    list.innerHTML = '<div class="empty-sub" style="text-align:center;padding:30px 0">No scans yet.</div>';
    return;
  }

  list.innerHTML = state.history.map((item, i) => {
    const color = riskColor(item.score);
    const tags  = [
      item.data.virustotal?.available ? '<span class="tag tag-purple" style="font-size:8px">VT</span>' : "",
      item.data.zap?.available        ? '<span class="tag tag-warn" style="font-size:8px">ZAP</span>' : "",
    ].filter(Boolean).join("");

    return `
      <div class="history-item" onclick="loadHistory(${i})">
        <div class="history-item-top">
          <span class="history-url">${escHtml(item.url)}</span>
          <span class="history-score" style="color:${color}">${riskEmoji(item.score)} ${item.score}</span>
        </div>
        <div class="history-meta">
          ${new Date(item.ts).toLocaleString()}
          <span class="history-tags">${tags}</span>
        </div>
      </div>`;
  }).join("");
}

window.loadHistory = function(index) {
  const item = state.history[index];
  if (!item) return;
  urlInput.value = item.url;
  state.lastResult = item.data;
  renderResult(item.data);
  showPanel("result");
  // Switch to result tab
  document.querySelectorAll(".tab-btn").forEach(b => {
    b.classList.toggle("active", b.dataset.tab === "result");
  });
  tabResult .classList.remove("hidden");
  tabHistory.classList.add   ("hidden");
};

// ── Export report ──────────────────────────────────────────────────────────
function exportReport(data, score) {
  const local = data.local;
  const vt    = data.virustotal;
  const zap   = data.zap;

  const lines = [
    "══════════════════════════════════════════════════════",
    "   SMART URL SECURITY SCANNER — FULL REPORT",
    "══════════════════════════════════════════════════════",
    `URL        : ${local.url}`,
    `Scanned    : ${new Date().toLocaleString()}`,
    `Risk Score : ${score}/100  [${riskLabel(score)}]`,
    "",
    "── LOCAL ANALYSIS ────────────────────────────────────",
    ...(local.issues.length
      ? local.issues.map(i => `[${i.type.toUpperCase()}][${i.cat}] ${i.msg}`)
      : ["No issues detected."]),
    "",
    "── SECURITY CHECKS ───────────────────────────────────",
    ...local.checks.map(c => `${c.status === "pass" ? "✓" : c.status === "fail" ? "✗" : "⚠"} ${c.label}: ${c.status.toUpperCase()}`),
    "",
    "── VIRUSTOTAL ────────────────────────────────────────",
    vt?.available && vt.status === "completed"
      ? `Malicious:${vt.malicious} / Suspicious:${vt.suspicious} / Harmless:${vt.harmless} / Total:${vt.total_engines} engines`
      : (vt?.error || "Not run"),
    ...(vt?.flagged_by || []).map(f => `  [${f.category}] ${f.engine}: ${f.result}`),
    "",
    "── OWASP ZAP ─────────────────────────────────────────",
    zap?.available
      ? `Alerts: ${zap.total_alerts} | High:${zap.risk_counts?.High || 0} Med:${zap.risk_counts?.Medium || 0} Low:${zap.risk_counts?.Low || 0}`
      : (zap?.error || "Not run"),
    ...(zap?.alerts || []).map(a => `  [${a.risk}] ${a.name} ${a.cweid ? `(CWE-${a.cweid})` : ""}`),
    "",
    "── RECOMMENDATIONS ───────────────────────────────────",
    ...local.recommendations.map(r => `• ${r}`),
    "",
    "══════════════════════════════════════════════════════",
    "⚠ FOR EDUCATIONAL & SECURITY AWARENESS PURPOSES ONLY",
    "══════════════════════════════════════════════════════",
  ];

  const blob = new Blob([lines.join("\n")], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `scan-report-${Date.now()}.txt`;
  a.click();

  // Also save to sessionStorage so report.html can read it
  sessionStorage.setItem("lastScanData", JSON.stringify({ data, score }));
}

// ── Helpers ────────────────────────────────────────────────────────────────
function riskColor(s) { return s >= 70 ? "#ff3550" : s >= 40 ? "#ffb300" : "#00ff6a"; }
function riskLabel(s) { return s >= 70 ? "HIGH" : s >= 40 ? "MEDIUM" : "LOW"; }
function riskEmoji(s) { return s >= 70 ? "🔴" : s >= 40 ? "🟡" : "🟢"; }
function statusIcon(s) { return s === "pass" ? "✓" : s === "fail" ? "✗" : "⚠"; }
