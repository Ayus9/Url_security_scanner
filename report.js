/**
 * report.js — Populates the printable report page
 * Reads scan data stored by scanner.js in sessionStorage
 */

"use strict";

(function () {
  const raw = sessionStorage.getItem("lastScanData");

  if (!raw) {
    document.getElementById("report-meta").innerHTML =
      'No scan data found. <a href="/" style="color:#00ff6a">← Go back and run a scan first</a>';
    return;
  }

  const { data, score } = JSON.parse(raw);
  const local = data.local;
  const vt    = data.virustotal;
  const zap   = data.zap;

  const escHtml = s => String(s)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");

  const riskColor = s => s >= 70 ? "#ff3550" : s >= 40 ? "#ffb300" : "#00ff6a";
  const riskLabel = s => s >= 70 ? "HIGH" : s >= 40 ? "MEDIUM" : "LOW";

  // Meta
  document.getElementById("report-meta").innerHTML = `
    <strong style="color:#c8ffd4">${escHtml(local.url)}</strong><br>
    Scanned: ${new Date().toLocaleString()}<br>
    Hostname: ${escHtml(local.hostname)} · Protocol: ${escHtml(local.protocol)}`;

  // Risk summary
  const color = riskColor(score);
  document.getElementById("report-risk").innerHTML = `
    <span class="risk-badge-report" style="background:${color}22;color:${color};border:2px solid ${color}55">
      ${riskLabel(score)} RISK — ${score}/100
    </span>
    <div style="font-size:12px;color:#7a9a8a;margin-top:12px;line-height:2">
      Local score: ${local.score}/100 &nbsp;|&nbsp;
      ${vt?.available ? `VirusTotal: ${vt.malicious} malicious` : "VirusTotal: not run"} &nbsp;|&nbsp;
      ${zap?.available ? `ZAP alerts: ${zap.total_alerts}` : "ZAP: not run"}
    </div>`;

  // Issues
  const issuesTbody = document.getElementById("report-issues");
  if (local.issues.length === 0) {
    issuesTbody.innerHTML = '<tr><td colspan="3" style="color:#4a7a5a">No issues detected.</td></tr>';
  } else {
    issuesTbody.innerHTML = local.issues.map(iss => {
      const c = iss.type === "bad" ? "#ff3550" : iss.type === "warn" ? "#ffb300" : "#00ff6a";
      return `<tr>
        <td>${escHtml(iss.cat)}</td>
        <td style="color:${c}">${iss.type.toUpperCase()}</td>
        <td>${escHtml(iss.msg)}</td>
      </tr>`;
    }).join("");
  }

  // Checks
  const checksTbody = document.getElementById("report-checks");
  checksTbody.innerHTML = local.checks.map(c => {
    const col = c.status === "pass" ? "#00ff6a" : c.status === "fail" ? "#ff3550" : "#ffb300";
    const ico = c.status === "pass" ? "✓" : c.status === "fail" ? "✗" : "⚠";
    return `<tr>
      <td>${escHtml(c.label)}</td>
      <td style="color:${col}">${ico} ${c.status.toUpperCase()}</td>
    </tr>`;
  }).join("");

  // VirusTotal
  if (vt?.available && vt.status === "completed") {
    document.getElementById("report-vt-section").style.display = "block";
    document.getElementById("report-vt").innerHTML = `
      <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:14px">
        <div><span style="color:#ff3550;font-size:20px;font-family:Orbitron,monospace;font-weight:700">${vt.malicious}</span> <span style="color:#4a7a5a;font-size:11px">Malicious</span></div>
        <div><span style="color:#ffb300;font-size:20px;font-family:Orbitron,monospace;font-weight:700">${vt.suspicious}</span> <span style="color:#4a7a5a;font-size:11px">Suspicious</span></div>
        <div><span style="color:#00ff6a;font-size:20px;font-family:Orbitron,monospace;font-weight:700">${vt.harmless}</span> <span style="color:#4a7a5a;font-size:11px">Harmless</span></div>
        <div><span style="color:#4a7a5a;font-size:20px;font-family:Orbitron,monospace;font-weight:700">${vt.total_engines}</span> <span style="color:#4a7a5a;font-size:11px">Total Engines</span></div>
      </div>
      ${vt.vt_link && vt.vt_link !== "#"
        ? `<a href="${escHtml(vt.vt_link)}" target="_blank" style="color:#9b59ff;font-size:12px">↗ Full VirusTotal Report</a>`
        : ""}`;
  }

  // ZAP
  if (zap?.available && zap.total_alerts > 0) {
    document.getElementById("report-zap-section").style.display = "block";
    const RISK_COLORS = { High:"#ff3550", Medium:"#ffb300", Low:"#00b4ff", Informational:"#4a7a5a" };
    document.getElementById("report-zap").innerHTML = (zap.alerts || []).map(a => `
      <tr>
        <td>${escHtml(a.name)}</td>
        <td style="color:${RISK_COLORS[a.risk]}">${escHtml(a.risk)}</td>
        <td>${a.cweid ? `CWE-${escHtml(a.cweid)}` : "—"}</td>
        <td style="font-size:11px">${escHtml((a.description || "").slice(0,120))}</td>
      </tr>`).join("");
  }

  // Recommendations
  document.getElementById("report-recs").innerHTML =
    local.recommendations.map(r => `<li>${escHtml(r)}</li>`).join("");
})();
