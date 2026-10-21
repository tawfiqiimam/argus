/* ============================================================
   T4WF1Q VMS — dashboard app (vanilla JS, no build step)
   ============================================================ */
const S = {
  key: localStorage.getItem("t4wf1q_key") || "",
  view: "overview",
  assets: [], findings: [], ws: null,
  logBuf: [], feedBuf: [], liveScan: null,
  owasp: {},
  settings: {},
};
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => (s == null ? "" : String(s).replace(/[&<>"]/g, c => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])));
const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// ---- API ----------------------------------------------------
async function api(path, opts = {}) {
  const r = await fetch(path, {
    ...opts,
    headers: { "x-api-key": S.key, "content-type": "application/json", ...(opts.headers || {}) },
  });
  if (r.status === 401) { openGate("Invalid API key."); throw new Error("401"); }
  if (!r.ok) { const t = await r.text(); throw new Error(t || r.status); }
  const ct = r.headers.get("content-type") || "";
  return ct.includes("json") ? r.json() : r.text();
}

// ---- auth gate ----------------------------------------------
function openGate(msg) { $("#gate").classList.remove("hide"); if (msg) $("#keyErr").textContent = msg; }
$("#keyBtn").onclick = async () => {
  S.key = $("#keyInput").value.trim();
  try {
    await api("/api/stats");
    localStorage.setItem("t4wf1q_key", S.key);
    $("#gate").classList.add("hide");
    boot();
  } catch { $("#keyErr").textContent = "Could not connect — check the key."; }
};
$("#keyInput").addEventListener("keydown", e => { if (e.key === "Enter") $("#keyBtn").click(); });

// ---- websocket ----------------------------------------------
// Realtime indicator in the top bar.
function setLive(on, text) {
  $("#liveDot").classList.toggle("on", on);
  $("#liveText").textContent = text || (on ? "Live" : "Offline");
}
// Sidebar badge that shows while a scan is queued or running.
function setActive(on) { $("#liveBadge").classList.toggle("hide", !on); }

function connectWS() {
  if (S.ws) try { S.ws.close(); } catch {}
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws?key=${encodeURIComponent(S.key)}`);
  S.ws = ws;
  ws.onopen = () => setLive(true, "Live");
  ws.onclose = () => { setLive(false, "Reconnecting"); setTimeout(connectWS, 3000); };
  ws.onmessage = (e) => handleEvent(JSON.parse(e.data));
}

function handleEvent(ev) {
  if (ev.kind === "log") {
    S.logBuf.push(ev);
    if (S.logBuf.length > 500) S.logBuf.shift();
    if (S.view === "live") appendLog(ev);
  } else if (ev.kind === "finding") {
    S.feedBuf.unshift(ev);
    if (S.feedBuf.length > 60) S.feedBuf.pop();
    toast(`${ev.severity.toUpperCase()}: ${ev.title}`);
    if (S.view === "live") prependFeed(ev);
    if (S.view === "overview" || S.view === "findings") softRefresh();
  } else if (ev.kind === "scan_update") {
    S.liveScan = { ...(S.liveScan || {}), ...ev };
    setActive(ev.status === "running" || ev.status === "queued");
    if (S.view === "live") updateScanHeader();
    if (ev.status === "done") { toast("Scan complete. Results are ready."); softRefresh(); }
    if (ev.status === "failed") toast("Scan failed. Check the console for details.");
    if (ev.status === "cancelled") toast("Scan cancelled.");
  } else if (ev.kind === "subdomain") {
    if (S.view === "live") appendLog({ level: "info", message: `↳ live host: ${ev.host} [${ev.status || "?"}] ${ev.title || ""}` });
  } else if (ev.kind === "emergency_stop") {
    S.settings.emergency_stop = !!ev.engaged;
    renderBanner();
    toast(ev.engaged ? `Emergency stop on. ${ev.cancelled || 0} scan(s) cancelled.` : "Emergency stop cleared.");
    if (S.view === "scope" || S.view === "live") render(true);
  } else if (ev.kind === "report_ready") {
    toast("Report generated ✓");
  }
}

let softTimer = null;
function softRefresh() { clearTimeout(softTimer); softTimer = setTimeout(() => render(true), 600); }

// ---- navigation ---------------------------------------------
const TITLES = {
  overview: ["Overview", "Your program's security posture at a glance"],
  live: ["Live scan", "Watch a scan move through its stages, and stop it if needed"],
  assets: ["Assets", "Targets under assessment"],
  findings: ["Findings", "Review what was found, then confirm, accept, or close it"],
  checklist: ["Manual checklist", "Hands-on checks that scanners can't cover"],
  reports: ["Reports", "Assessment reports built from scan results"],
  scope: ["Scope & safety", "What Argus may test, and the guardrails around it"],
  tools: ["Scanner tools", "Security tools detected on this machine"],
  audit: ["Audit log", "A record of scans, scope changes, and settings"],
};
const PROFILE_LABELS = {
  "owasp-full": "Full hunt (OWASP + network)", web: "Web application", recon: "Recon only",
  network: "Network", quick: "Quick scan", passive: "Passive", api: "API security",
  wordpress: "WordPress", infra: "Infrastructure", code: "Source code", dependency: "Dependencies",
  full: "Everything authorized",
};
const STATUS_LABELS = {
  new: "New", confirmed: "Confirmed", false_positive: "False positive", accepted_risk: "Accepted risk",
  fixed: "Fixed", reopened: "Reopened", queued: "Queued", running: "Running", done: "Complete",
  failed: "Failed", cancelled: "Cancelled",
};
const STAGE_LABELS = {
  recon: "Subdomain discovery", amass: "Passive enumeration", takeover: "Takeover check",
  probe: "Live host probe", whatweb: "Fingerprinting", discover: "Crawling", params: "Parameter review",
  http: "Security headers", paths: "Exposed paths", xss: "XSS pattern check", dalfox: "XSS testing",
  zap: "ZAP passive scan", nuclei: "Template scanning", nikto: "Web server checks", testssl: "TLS review",
  wpscan: "WordPress checks", sqlmap: "SQL injection check", nmap: "Port scan", gitleaks: "Secret scan",
  semgrep: "Code analysis", depcheck: "Dependency check", trivy: "Dependency scan",
};
const humanStage = (s) => STAGE_LABELS[s] || (s ? String(s).replace(/[_-]/g, " ") : "Preparing");
const errText = (e) => String((e && e.message) || e || "").replace(/[{}"]/g, "").replace("detail:", "").trim().slice(0, 180);

// One place to change views: keeps the sidebar, title and content in step.
function go(view) {
  S.view = view;
  $$("#nav button").forEach(x => {
    const on = x.dataset.view === view;
    x.classList.toggle("active", on);
    if (on) x.setAttribute("aria-current", "page"); else x.removeAttribute("aria-current");
  });
  const [t, s] = TITLES[view] || TITLES.overview;
  $("#viewTitle").textContent = t; $("#viewSub").textContent = s;
  render();
}
$$("#nav button").forEach(b => b.onclick = () => go(b.dataset.view));

// ---- boot ---------------------------------------------------
async function boot() {
  connectWS();
  await refreshChrome();
  await loadActiveScan();
  render();
}

// Scope chip and emergency banner, kept in sync with the server.
async function refreshChrome() {
  try {
    const [sc, set] = await Promise.all([api("/api/scope"), api("/api/settings")]);
    S.settings = set;
    const chip = $("#scopeChip");
    chip.textContent = sc.enforce ? `${sc.allow.length} allowed` : "Enforcement off";
    chip.classList.toggle("warn", !sc.enforce);
    chip.title = sc.enforce
      ? "Scans only run against allowed targets."
      : "Scope enforcement is off. Turn it on in Scope & safety.";
  } catch {}
  renderBanner();
}
function renderBanner() {
  const on = !!S.settings.emergency_stop;
  $("#banner").classList.toggle("hide", !on);
  $("#stopBtn").disabled = on;
}
async function emergencyStop() {
  if (!confirm("Stop all scans?\n\nThis cancels every queued and running scan and turns automation off. You can resume later.")) return;
  try {
    const r = await api("/api/emergency-stop", { method: "POST" });
    S.settings.emergency_stop = true;
    S.settings.automation_enabled = false;
    renderBanner();
    toast(`Stopped. ${r.cancelled} scan(s) cancelled.`);
    await loadActiveScan();
    if (S.view === "live") updateScanHeader();
    if (S.view === "scope") render(true);
  } catch (e) { toast("Could not stop scans: " + errText(e)); }
}
async function resumeScanning() {
  try {
    await api("/api/emergency-stop/clear", { method: "POST" });
    S.settings.emergency_stop = false;
    renderBanner();
    toast("Scanning resumed. Automation stays off until you turn it back on.");
  } catch (e) { toast("Could not resume: " + errText(e)); }
}
$("#stopBtn").onclick = emergencyStop;
$("#resumeBtn").onclick = resumeScanning;
$("#newScanBtn").onclick = () => openScanDialog();

// ---- render dispatcher --------------------------------------
async function render(soft = false) {
  const v = $("#views");
  if (!soft) v.innerHTML = `<div class="empty">loading…</div>`;
  try {
    if (S.view === "overview") return renderOverview(v);
    if (S.view === "assets") return renderAssets(v);
    if (S.view === "findings") return renderFindings(v);
    if (S.view === "live") return renderLive(v);
    if (S.view === "checklist") return renderChecklist(v);
    if (S.view === "reports") return renderReports(v);
    if (S.view === "scope") return renderScope(v);
    if (S.view === "tools") return renderTools(v);
    if (S.view === "audit") return renderAudit(v);
  } catch (e) {
    v.innerHTML = `<div class="empty"><strong>This view could not load</strong>${esc(errText(e))}
      <div><button class="btn sm ghost" onclick="render()">Try again</button></div></div>`;
  }
}

// ---- OVERVIEW -----------------------------------------------
const OWASP_NAMES = {
  A01: "Broken Access Control", A02: "Cryptographic Failures", A03: "Injection",
  A04: "Insecure Design", A05: "Security Misconfiguration", A06: "Vulnerable Components",
  A07: "Auth Failures", A08: "Integrity Failures", A09: "Logging Failures", A10: "SSRF",
};
async function renderOverview(v) {
  const s = await api("/api/stats");
  const c = s.counts;
  v.innerHTML = `
    <div class="huntbar">
      <p class="hb-title">Start a hunt</p>
      <div class="hb-row">
        <span class="hb-ico">🎯</span>
        <input id="huntInput" autocomplete="off" spellcheck="false"
               placeholder="Enter a domain or URL and press Enter to hunt —  e.g. example.com">
        <button class="btn hb-go" onclick="quickHunt()">Start hunt</button>
      </div>
      <div class="hb-foot">
        <label class="chkline"><input type="checkbox" id="huntAuth">
          <span>I own this target or I'm <b>authorized</b> to test it (adds it to scope)</span></label>
        <span id="huntErr" class="sev-crit" style="font-size:12px"></span>
      </div>
    </div>
    <div class="row cols-5" style="margin-bottom:14px">
      <div class="panel stat riskcard"><div class="n">${s.risk}</div><div class="l">Risk score</div><div class="spark">▲</div></div>
      ${statCard("Critical", c.critical, "crit")}
      ${statCard("High", c.high, "high")}
      ${statCard("Medium", c.medium, "med")}
      ${statCard("Low", c.low, "low")}
    </div>
    <div class="row cols-2b" style="margin-bottom:14px">
      <div class="panel">
        <h2>OWASP Top 10 exposure</h2>
        <div class="owasp-grid">
          ${Object.keys(OWASP_NAMES).map(code => {
            const n = s.owasp[code] || 0;
            return `<div class="owasp-cell ${n ? "hot" : ""}" onclick="gotoOwasp('${code}')">
              <div class="code">${code}</div><div class="nm">${OWASP_NAMES[code]}</div>
              <div class="ct ${n ? "sev-crit" : "muted"}">${n || "—"}</div></div>`;
          }).join("")}
        </div>
      </div>
      <div class="panel">
        <h2>Assets · ${s.assets}</h2>
        <div id="ovAssets"></div>
      </div>
    </div>
    <div class="row cols-2">
      <div class="panel"><h2>Recent findings</h2>${findingsTable(s.recent_findings, true)}</div>
      <div class="panel"><h2>Recent scans</h2>${scansTable(s.recent_scans)}</div>
    </div>`;
  const hi = $("#huntInput");
  if (hi) hi.addEventListener("keydown", e => { if (e.key === "Enter") quickHunt(); });
  const al = await api("/api/assets");
  $("#ovAssets").innerHTML = al.length ? al.slice(0, 6).map(a => `
    <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--line)">
      <div style="flex:1"><div style="font-weight:600">${esc(a.name)}</div>
        <div class="mono muted" style="font-size:11px">${esc(a.target)}</div></div>
      <div class="right"><div style="font-weight:800">${a.risk}</div>
        <div class="muted" style="font-size:10px">risk</div></div>
    </div>`).join("") : `<div class="empty">No assets yet. Click “New Scan”.</div>`;
}
function statCard(label, n, cls) {
  return `<div class="panel stat"><div class="n sev-${cls}">${n}</div><div class="l">${label}</div></div>`;
}
window.gotoOwasp = (code) => {
  S.view = "findings";
  $$("#nav button").forEach(x => x.classList.toggle("active", x.dataset.view === "findings"));
  render().then(() => { const sel = $("#fOwasp"); if (sel) { sel.value = code; sel.onchange(); } });
};
window.quickHunt = async () => {
  const target = ($("#huntInput").value || "").trim();
  const err = $("#huntErr"); if (err) err.textContent = "";
  if (!target) return;
  const authorized = $("#huntAuth").checked;
  const go = $(".hb-go"); if (go) { go.disabled = true; go.textContent = "Starting…"; }
  try {
    const asset = await api("/api/assets", { method: "POST", body: JSON.stringify({
      target, kind: "program", add_to_scope: authorized, authorized }) });
    await api(`/api/assets/${asset.id}/scan`, { method: "POST", body: JSON.stringify({ profile: "owasp-full" }) });
    toast("Hunt started ✓ — watching live");
    S.view = "live"; $$("#nav button").forEach(x => x.classList.toggle("active", x.dataset.view === "live"));
    const [t, sub] = TITLES.live; $("#viewTitle").textContent = t; $("#viewSub").textContent = sub;
    render();
  } catch (e) {
    let msg = e.message.replace(/[{}"]/g, "").replace("detail:", "").trim().slice(0, 220);
    if (msg.toLowerCase().includes("out of scope"))
      msg = "Out of scope — tick the authorization box below, then press Hunt.";
    if (err) err.textContent = msg;
    if (go) { go.disabled = false; go.textContent = "Start hunt"; }
  }
};

// ---- ASSETS -------------------------------------------------
async function renderAssets(v) {
  const al = await api("/api/assets"); S.assets = al;
  v.innerHTML = `<div class="panel">
    <div style="display:flex;justify-content:space-between;margin-bottom:12px">
      <h2 style="margin:0">Assets (${al.length})</h2>
      <button class="btn sm" onclick="openScanDialog()">+ Add target</button>
    </div>
    ${al.length ? `<table><thead><tr><th>Asset</th><th>Kind</th><th>Risk</th>
      <th>Findings</th><th>Last scan</th><th></th></tr></thead><tbody>
      ${al.map(a => `<tr>
        <td><div style="font-weight:600">${esc(a.name)}</div>
          <div class="mono muted" style="font-size:11px">${esc(a.target)}</div></td>
        <td><span class="tag">${esc(a.kind)}</span></td>
        <td style="font-weight:800">${a.risk}</td>
        <td>${sevDots(a.counts)}</td>
        <td class="muted" style="font-size:12px">${a.last_scan ? timeAgo(a.last_scan) : "never"}</td>
        <td class="right">
          <button class="btn sm" onclick="runScan('${a.id}')">Scan</button>
          <button class="btn sm ghost" onclick="viewAsset('${a.id}')">Open</button>
        </td></tr>`).join("")}
      </tbody></table>` : `<div class="empty"><strong>No assets yet</strong>Add a target to start assessing it.<div><button class="btn sm" onclick="openScanDialog()">New scan</button></div></div>`}
  </div>`;
}
function sevDots(c) {
  return ["critical", "high", "medium", "low"].map(k =>
    c[k] ? `<span class="pill p-${k}" style="margin-right:3px">${c[k]}</span>` : "").join("") || `<span class="muted">—</span>`;
}

// ---- FINDINGS -----------------------------------------------
async function renderFindings(v) {
  v.innerHTML = `<div class="panel">
    <div style="display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap">
      <select id="fSev"><option value="">All severities</option>
        ${["critical", "high", "medium", "low", "info"].map(s => `<option>${s}</option>`).join("")}</select>
      <select id="fStatus"><option value="">All statuses</option>
        ${["new", "confirmed", "false_positive", "accepted_risk", "fixed", "reopened"].map(s => `<option value="${s}">${STATUS_LABELS[s]}</option>`).join("")}</select>
      <select id="fOwasp"><option value="">All OWASP</option>
        ${Object.keys(OWASP_NAMES).map(c => `<option value="${c}">${c} ${OWASP_NAMES[c]}</option>`).join("")}</select>
    </div>
    <div id="fList"></div></div>`;
  const load = async () => {
    const q = new URLSearchParams();
    if ($("#fSev").value) q.set("severity", $("#fSev").value);
    if ($("#fStatus").value) q.set("status", $("#fStatus").value);
    if ($("#fOwasp").value) q.set("owasp", $("#fOwasp").value);
    const fs = await api("/api/findings?" + q);
    $("#fList").innerHTML = findingsTable(fs);
  };
  $("#fSev").onchange = $("#fStatus").onchange = $("#fOwasp").onchange = load;
  load();
}
function findingsTable(fs, compact) {
  if (!fs || !fs.length) return `<div class="empty"><strong>No findings match these filters</strong>Clear a filter, or run a scan to look for issues.</div>`;
  return `<table><thead><tr><th>Sev</th><th>Title</th>${compact ? "" : "<th>OWASP</th><th>Location</th><th>Status</th>"}</tr></thead><tbody>
    ${fs.map(f => `<tr class="clickable" onclick="viewFinding('${f.id}')">
      <td><span class="pill p-${f.severity}">${f.severity}</span></td>
      <td>${esc(f.title)}${compact ? `<div class="mono muted" style="font-size:11px">${esc(f.location || f.host || "")}</div>` : ""}</td>
      ${compact ? "" : `<td class="mono muted">${f.owasp || "—"}</td>
      <td class="mono muted" style="font-size:11px">${esc(f.location || f.host || "—")}</td>
      <td><span class="tag">${esc(STATUS_LABELS[f.status] || f.status)}</span></td>`}
    </tr>`).join("")}</tbody></table>`;
}

// ---- LIVE ---------------------------------------------------
async function renderLive(v) {
  v.innerHTML = `
    <div class="panel" id="scanHead" style="margin-bottom:16px"></div>
    <div class="row cols-2b">
      <div class="panel">
        <div class="panel-head"><h2>Console</h2><span class="faint" style="font-size:12px">Newest at the bottom</span></div>
        <div class="console" id="console" role="log"></div>
      </div>
      <div class="panel">
        <div class="panel-head"><h2>Findings as they land</h2></div>
        <div class="feed" id="feed"></div>
      </div>
    </div>`;
  if (!S.liveScan) await loadActiveScan();
  updateScanHeader();
  const con = $("#console"); con.innerHTML = "";
  S.logBuf.slice(-200).forEach(appendLog);
  const feed = $("#feed");
  feed.innerHTML = S.feedBuf.length ? "" : `<div class="empty"><strong>No findings yet</strong>Results appear here while a scan runs.</div>`;
  S.feedBuf.forEach(f => feed.insertAdjacentHTML("beforeend", feedItem(f)));
}
function updateScanHeader() {
  const h = $("#scanHead"); if (!h) return;
  const s = S.liveScan;
  if (!s) {
    h.innerHTML = `<div class="empty"><strong>No scan is running</strong>Start a hunt from Overview, or press “New scan”.</div>`;
    return;
  }
  const status = s.status || "queued";
  const active = status === "running" || status === "queued";
  const pct = Math.max(0, Math.min(100, Number(s.progress) || 0));
  const step = active ? humanStage(s.stage) : (STATUS_LABELS[status] || status);
  const id = esc(s.scan_id || "");
  h.innerHTML = `
    <div class="scan-head">
      <div>
        <div class="inline">
          <span class="status ${esc(status)}">${esc(STATUS_LABELS[status] || status)}</span>
          <strong style="font-size:15px">${esc(PROFILE_LABELS[s.profile] || s.profile || "Scan")}</strong>
        </div>
        <div class="meta">
          <span>Current step <b>${esc(step)}</b></span>
          <span>Progress <b>${pct}%</b></span>
          <span>Started <b>${s.created_at ? timeAgo(s.created_at) : "just now"}</b></span>
          <span class="mono faint">${id}</span>
        </div>
      </div>
      <div class="inline">
        ${active && id ? `<button class="btn danger-ghost sm" onclick="cancelScan('${id}')">Cancel scan</button>` : ""}
        ${!active && id && (status === "failed" || status === "cancelled") ? `<button class="btn ghost sm" onclick="retryScan('${id}')">Retry scan</button>` : ""}
      </div>
    </div>
    <div class="bar" style="margin-top:14px" role="progressbar" aria-label="Scan progress"
         aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct}"><i style="width:${pct}%"></i></div>`;
}
// Load the newest scan from the server, so the live view works after a page reload.
async function loadActiveScan() {
  try {
    const rows = await api("/api/scans");
    const live = rows.find(r => r.status === "running" || r.status === "queued");
    setActive(!!live);
    const s = live || rows[0];
    if (s) S.liveScan = { scan_id: s.id, asset_id: s.asset_id, profile: s.profile, status: s.status,
      stage: s.stage, progress: s.progress, created_at: s.created_at };
  } catch {}
}
window.cancelScan = async (sid) => {
  if (!confirm("Cancel this scan?\n\nA running scan stops at its next stage. Findings already saved are kept.")) return;
  try {
    await api(`/api/scans/${sid}/cancel`, { method: "POST" });
  } catch (e) { toast("Could not cancel: " + errText(e)); return; }
  await loadActiveScan();
  if (S.view === "live") updateScanHeader();
  softRefresh();
};
window.retryScan = async (sid) => {
  try {
    await api(`/api/scans/${sid}/retry`, { method: "POST" });
    toast("Scan queued again.");
  } catch (e) { toast("Could not retry: " + errText(e)); return; }
  await loadActiveScan();
  if (S.view === "live") updateScanHeader();
  softRefresh();
};
function appendLog(ev) {
  const con = $("#console"); if (!con) return;
  const t = new Date().toLocaleTimeString();
  const div = document.createElement("div");
  div.className = `ln lvl-${ev.level || "info"}`;
  div.innerHTML = `<span class="t">${t}</span> ${esc(ev.message)}`;
  con.appendChild(div); con.scrollTop = con.scrollHeight;
}
function prependFeed(ev) {
  const feed = $("#feed"); if (!feed) return;
  if (feed.querySelector(".empty")) feed.innerHTML = "";
  feed.insertAdjacentHTML("afterbegin", feedItem(ev));
}
function feedItem(f) {
  return `<div class="item clickable" onclick="viewFinding('${f.id}')">
    <span class="pill p-${f.severity}">${f.severity}</span>
    <div style="flex:1"><div style="font-weight:600;font-size:13px">${esc(f.title)}</div>
    <div class="mono muted" style="font-size:11px">${esc(f.location || f.host || "")}</div></div>
    <span class="tag">${f.owasp || ""}</span></div>`;
}

// ---- CHECKLIST ----------------------------------------------
async function renderChecklist(v) {
  const al = S.assets.length ? S.assets : await api("/api/assets"); S.assets = al;
  if (!al.length) { v.innerHTML = `<div class="panel"><div class="empty">Add an asset first.</div></div>`; return; }
  v.innerHTML = `<div class="panel">
    <div style="display:flex;gap:10px;align-items:center;margin-bottom:14px">
      <label>Asset</label>
      <select id="clAsset">${al.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join("")}</select>
      <div style="flex:1"></div><div id="clCov" class="muted"></div>
    </div><div id="clBody"></div></div>`;
  const load = async () => {
    const aid = $("#clAsset").value;
    const d = await api(`/api/assets/${aid}/checklist`);
    $("#clCov").innerHTML = `${d.coverage.reviewed}/${d.coverage.total} reviewed · <span class="sev-crit">${d.coverage.failed} failed</span>`;
    const groups = {};
    d.items.forEach(i => (groups[i.owasp] ||= []).push(i));
    $("#clBody").innerHTML = Object.keys(groups).sort().map(code => `
      <div class="chk-group"><h3>${code} · ${OWASP_NAMES[code] || ""}</h3>
      ${groups[code].map(i => `<div class="chk">
        <div class="ttl">${esc(i.title)}</div>
        <div class="seg" data-key="${i.item_key}">
          ${["pass", "fail", "na", "todo"].map(st =>
            `<button class="${i.state === st ? "on-" + st : ""}" onclick="setChk('${aid}','${i.item_key}','${st}',this)">${st.toUpperCase()}</button>`).join("")}
        </div></div>`).join("")}</div>`).join("");
  };
  $("#clAsset").onchange = load; load();
}
window.setChk = async (aid, key, state, btn) => {
  $$(".seg[data-key='" + key + "'] button").forEach(b => b.className = "");
  btn.className = "on-" + state;
  await api(`/api/assets/${aid}/checklist`, { method: "POST", body: JSON.stringify({ item_key: key, state }) });
  const d = await api(`/api/assets/${aid}/checklist`);
  $("#clCov").innerHTML = `${d.coverage.reviewed}/${d.coverage.total} reviewed · <span class="sev-crit">${d.coverage.failed} failed</span>`;
};

// ---- REPORTS ------------------------------------------------
async function renderReports(v) {
  const al = S.assets.length ? S.assets : await api("/api/assets"); S.assets = al;
  const reps = await api("/api/reports");
  v.innerHTML = `<div class="panel">
    <div style="display:flex;gap:10px;align-items:center;margin-bottom:14px">
      <label>Generate for</label>
      <select id="rAsset">${al.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join("")}</select>
      <button class="btn sm" onclick="genReport()">Generate report</button><button class="btn sm ghost" onclick="exportAsset('json')">JSON</button><button class="btn sm ghost" onclick="exportAsset('csv')">CSV</button>
    </div>
    ${reps.length ? `<table><thead><tr><th>Report</th><th>Size</th><th>Created</th><th></th></tr></thead><tbody>
      ${reps.map(r => `<tr><td class="mono">${esc(r.name)}</td>
        <td class="muted">${(r.size / 1024).toFixed(0)} KB</td>
        <td class="muted">${timeAgo(new Date(r.mtime * 1000).toISOString())}</td>
        <td class="right"><a class="btn sm ghost" href="/api/reports/${encodeURIComponent(r.name)}?key=${encodeURIComponent(S.key)}" target="_blank">Open</a></td>
      </tr>`).join("")}</tbody></table>`
      : `<div class="empty">No reports yet. Reports also auto-generate after each scan.</div>`}
  </div>`;
}
window.genReport = async () => {
  const aid = $("#rAsset").value;
  await api(`/api/assets/${aid}/report`, { method: "POST" });
  toast("Report generated ✓"); render();
};

// ---- SCOPE + SETTINGS --------------------------------------
async function renderScope(v) {
  const [sc, set] = await Promise.all([api("/api/scope"), api("/api/settings")]);
  const rules = sc.rules || [];
  const allowRules = rules.filter(r => r.kind === "allow");
  const denyRules = rules.filter(r => r.kind === "deny");
  const ruleRow = (r) => `<div class="rule">
    <span class="mono">${esc(r.pattern)}</span>
    ${r.note ? `<span class="muted" style="font-size:10px">${esc(r.note)}</span>` : ""}
    <button class="xrule" title="remove" onclick="delScope('${r.id}')">✕</button></div>`;

  v.innerHTML = `<div class="row cols-2b">
    <div class="panel">
      <h2>Authorized targets</h2>
      <p class="muted" style="font-size:12px;margin-top:-6px">Scans only run against hosts matching an allow rule. A root domain authorizes all of its subdomains.</p>

      <label>Add a target to scope</label>
      <div style="display:flex;gap:8px;margin:6px 0 8px">
        <input id="scPattern" placeholder="example.com  /  10.0.0.0/24  /  *.example.com" style="flex:1">
        <select id="scKind" style="width:90px"><option value="allow">allow</option><option value="deny">deny</option></select>
      </div>
      <label class="chkline" style="margin-bottom:8px"><input type="checkbox" id="scAuth">
        <span>I own this target or I'm <b>authorized</b> to test it</span></label>
      <button class="btn sm" onclick="addScope()">Add rule</button>
      <span id="scAddErr" class="sev-crit" style="font-size:11px;margin-left:8px"></span>

      <h2 style="margin-top:20px">Allowlist (${allowRules.length})</h2>
      <div class="rulelist">${allowRules.map(ruleRow).join("") || `<div class="empty">No allow rules yet. Add a target above.</div>`}</div>
      <h2 style="margin-top:16px">Denylist (${denyRules.length})</h2>
      <div class="rulelist">${denyRules.map(ruleRow).join("") || `<div class="empty">Nothing is excluded.</div>`}</div>
    </div>

    <div>
      <div class="panel" style="margin-bottom:16px">
        <h2>Safety controls</h2>
        ${switchRow("scope_enforce", "Enforce scope", "Scans only reach targets on your allowlist. Keep this on.", set.scope_enforce)}
        ${switchRow("allow_private", "Allow private and local targets", "Lets scans reach localhost, your LAN and other internal addresses. Only for machines you own.", set.allow_private)}
        ${switchRow("automation_enabled", "Continuous assessment", `A full scan around ${String(set.full_scan_cron_hour).padStart(2, "0")}:00 each day, plus a change watch every ${set.change_watch_minutes} minutes.`, set.automation_enabled)}
        ${switchRow("allow_intrusive", "Intrusive checks", "Enables low-impact SQL injection testing with sqlmap. Requires written authorization for every target.", set.allow_intrusive)}
      </div>
      <div class="panel danger-zone">
        <h2>Emergency stop</h2>
        <p class="muted" style="font-size:12px;margin:0 0 14px">${set.emergency_stop
          ? "Emergency stop is on. No scans start, and automation stays off until you resume."
          : "Cancels every queued and running scan and turns automation off straight away."}</p>
        ${set.emergency_stop
          ? `<button class="btn ghost" onclick="resumeScanning()">Resume scanning</button>`
          : `<button class="btn danger" onclick="emergencyStop()">Stop all scans</button>`}
      </div>
      <div class="panel"><h2>Scope checker</h2>
        <p class="muted" style="font-size:12px">Would a target be allowed?</p>
        <div style="display:flex;gap:8px"><input id="scTest" placeholder="example.com or https://host" style="flex:1">
        <button class="btn sm" onclick="checkScope()">Check</button></div>
        <div id="scRes" style="margin-top:14px"></div>
      </div>
    </div></div>`;
}
window.addScope = async () => {
  const pattern = $("#scPattern").value.trim();
  const kind = $("#scKind").value;
  const authorized = $("#scAuth").checked;
  if (!pattern) return;
  if (kind === "allow" && !authorized) { $("#scAddErr").textContent = "Tick the authorization box first."; return; }
  try {
    await api("/api/scope", { method: "POST", body: JSON.stringify({ pattern, kind, authorized }) });
    toast("Scope updated ✓"); renderScope($("#views"));
  } catch (e) { $("#scAddErr").textContent = e.message.replace(/[{}"]/g, "").replace("detail:", "").slice(0, 120); }
};
window.delScope = async (id) => {
  await api(`/api/scope/${id}`, { method: "DELETE" }); toast("Rule removed"); renderScope($("#views"));
};
// One labelled on/off row. The input is the whole switch, so it is keyboard and screen-reader friendly.
function switchRow(key, title, desc, on) {
  const id = `sw_${key}`;
  return `<div class="setting">
    <div class="txt"><strong id="${id}_t">${title}</strong><span>${desc}</span></div>
    <span class="switch"><input type="checkbox" id="${id}" aria-labelledby="${id}_t" ${on ? "checked" : ""}
      onchange="toggleSetting('${key}', this.checked, this)"><span class="track" aria-hidden="true"></span></span>
  </div>`;
}
// Risky switches ask first. Intrusive checks also send intrusive_ack, which the server requires.
window.toggleSetting = async (key, val, el) => {
  const body = { [key]: val };
  const revert = () => { if (el) el.checked = !val; };
  if (key === "scope_enforce" && !val &&
      !confirm("Turn off scope enforcement?\n\nScans could then reach hosts that are not on your allowlist. Only do this while you set things up.")) return revert();
  if (key === "allow_private" && val &&
      !confirm("Allow private and local targets?\n\nScans can then reach localhost, your LAN and internal addresses. Only do this for machines you own.")) return revert();
  if (key === "allow_intrusive" && val) {
    if (!confirm("Enable intrusive checks?\n\nSQL injection testing sends crafted requests that can change or slow a target. Only enable this if you hold written authorization for every target in scope.")) return revert();
    body.intrusive_ack = true;
  }
  try {
    S.settings = await api("/api/settings", { method: "POST", body: JSON.stringify(body) });
    renderBanner();
    toast(val ? "Turned on." : "Turned off.");
  } catch (e) {
    revert();
    toast("Not saved: " + errText(e));
  }
};
window.checkScope = async () => {
  const r = await api("/api/scope/check", { method: "POST", body: JSON.stringify({ pattern: $("#scTest").value }) });
  $("#scRes").innerHTML = `<div class="block">
    <div><strong class="${r.allowed ? "sev-info" : "sev-crit"}">${r.allowed ? "✓ IN SCOPE" : "✗ OUT OF SCOPE"}</strong></div>
    <div class="muted" style="margin-top:6px">host: <span class="mono">${esc(r.host)}</span></div>
    <div class="muted" style="margin-top:4px">${esc(r.reason)}</div></div>`;
};

// ---- drawers ------------------------------------------------
function openDrawer(html) {
  $("#drawer").innerHTML = `<button class="x" aria-label="Close panel" onclick="closeDrawer()">✕</button>${html}`;
  $("#drawer").setAttribute("aria-hidden", "false");
  $("#drawer").classList.add("open"); $("#overlay").classList.add("on");
}
window.closeDrawer = () => {
  $("#drawer").classList.remove("open");
  $("#drawer").setAttribute("aria-hidden", "true");
  $("#overlay").classList.remove("on");
};
$("#overlay").onclick = closeDrawer;
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

window.viewFinding = async (fid) => {
  const f = await api(`/api/findings/${fid}`);
  let refs = []; try { refs = JSON.parse(f.reference || "[]"); } catch {}
  const statuses = ["new", "confirmed", "false_positive", "accepted_risk", "fixed", "reopened"];
  openDrawer(`
    <span class="pill p-${f.severity}">${f.severity}</span>
    <h2 style="margin:12px 0 4px">${esc(f.title)}</h2>
    <div class="kv2">
      <div class="k">OWASP</div><div>${f.owasp || "—"} ${OWASP_NAMES[f.owasp] ? "· " + OWASP_NAMES[f.owasp] : ""}</div>
      <div class="k">Location</div><div class="mono">${esc(f.location || f.host || "—")}</div>
      <div class="k">Source</div><div>${esc(f.source || "—")}</div>
      <div class="k">CVSS</div><div>${f.cvss || "—"}</div>
      <div class="k">Seen</div><div>${f.seen_count}× · first ${timeAgo(f.first_seen)}</div>
    </div>
    ${f.description ? `<div class="block">${esc(f.description)}</div>` : ""}
    ${f.evidence ? `<label>Evidence</label><div class="block mono">${esc(f.evidence)}</div>` : ""}
    ${f.remediation ? `<label>Remediation</label><div class="block">${esc(f.remediation)}</div>` : ""}
    ${refs.length ? `<label>References</label><div class="block">${refs.map(r => `<div><a href="${esc(r)}" target="_blank">${esc(r)}</a></div>`).join("")}</div>` : ""}
    <label>Status</label>
    <div class="statusbtns">${statuses.map(s =>
      `<button class="btn sm ${s === f.status ? "" : "ghost"}" aria-pressed="${s === f.status}" onclick="setFindingStatus('${f.id}','${s}')">${STATUS_LABELS[s]}</button>`).join("")}</div>
  `);
};
window.setFindingStatus = async (fid, st) => {
  await api(`/api/findings/${fid}/status`, { method: "POST", body: JSON.stringify({ status: st }) });
  toast(`Marked ${st}`); viewFinding(fid); softRefresh();
};

window.viewAsset = async (aid) => {
  const a = await api(`/api/assets/${aid}`);
  openDrawer(`
    <h2 style="margin:0 0 4px">${esc(a.name)}</h2>
    <div class="mono muted">${esc(a.target)}</div>
    <div class="kv2"><div class="k">Risk</div><div style="font-weight:800">${a.risk}/100</div>
      <div class="k">Kind</div><div>${esc(a.kind)}</div>
      <div class="k">Findings</div><div>${sevDots(a.counts)}</div></div>
    <div style="display:flex;gap:8px;margin:10px 0 18px">
      <button class="btn sm" onclick="runScan('${a.id}')">Run scan</button>
      <button class="btn sm ghost" onclick="api('/api/assets/${a.id}/report',{method:'POST'}).then(()=>toast('Report ✓'))">Report</button>
      <button class="btn sm ghost" onclick="delAsset('${a.id}')">Delete</button>
    </div>
    <label>Attack surface (${a.subdomains.length})</label>
    <div class="block" style="max-height:200px;overflow:auto">
      ${a.subdomains.length ? a.subdomains.map(s => `<div class="mono" style="font-size:12px;padding:2px 0">
        ${s.alive ? "🟢" : "⚪"} ${esc(s.host)} <span class="muted">${s.status_code || ""} ${esc(s.title || "")}</span></div>`).join("")
        : "<span class='muted'>Run a recon scan to map subdomains.</span>"}
    </div>`);
};
window.delAsset = async (aid) => {
  if (!confirm("Delete this asset and all its findings?")) return;
  await api(`/api/assets/${aid}`, { method: "DELETE" }); closeDrawer(); toast("Deleted"); render();
};

// ---- scan dialog --------------------------------------------
function openScanDialog() {
  openDrawer(`
    <p class="muted" style="font-size:12px;margin:0 0 2px">New assessment</p>
    <h2 style="font-size:18px">Start a scan</h2>
    <div class="field">
      <label for="nsTarget">Target</label>
      <input id="nsTarget" autocomplete="off" spellcheck="false" placeholder="example.com, https://app.example.com or 203.0.113.10">
      <span class="hint">A root domain also covers all of its subdomains.</span>
    </div>
    <div class="field">
      <label for="nsName">Name <span class="faint" style="font-weight:400">(optional)</span></label>
      <input id="nsName" placeholder="e.g. Partner portal">
    </div>
    <div class="form-grid">
      <div class="field">
        <label for="nsKind">Target type</label>
        <select id="nsKind">
          <option value="program">Bug-bounty program (domain)</option>
          <option value="web">Web application</option>
          <option value="host">Single host</option>
        </select>
      </div>
      <div class="field">
        <label for="nsProfile">Scan profile</label>
        <select id="nsProfile">
          <option value="owasp-full">Full hunt (OWASP + network)</option>
          <option value="web">Web application</option>
          <option value="recon">Recon only (subdomains)</option>
          <option value="network">Network (nmap)</option>
          <option value="quick">Quick scan</option>
          <option value="passive">Passive (subdomains + takeover)</option>
          <option value="api">API security</option>
          <option value="wordpress">WordPress</option>
          <option value="infra">Infrastructure</option>
          <option value="code">Source code (local path)</option>
          <option value="dependency">Dependencies (local path)</option>
          <option value="full">Everything authorized</option>
        </select>
      </div>
    </div>
    <div class="authbox">
      <label class="chkline"><input type="checkbox" id="nsAuth">
        <span>I own this target or I'm <b>authorized</b> to test it. It will be added to scope.</span></label>
    </div>
    <button class="btn" style="width:100%;margin-top:16px" onclick="submitScan()">Add to scope and start</button>
    <p id="nsErr" class="err" role="alert" style="margin-top:10px"></p>
    <p class="muted" style="font-size:12px;margin-top:14px">A root domain runs the full pipeline: subdomain discovery, live-host probe, then OWASP Top 10 and CVE checks on every in-scope host. Argus only scans targets that are in scope.</p>`);
  setTimeout(() => { const t = $("#nsTarget"); if (t) t.focus(); }, 240);
}
window.submitScan = async () => {
  const target = $("#nsTarget").value.trim();
  if (!target) return;
  const authorized = $("#nsAuth").checked;
  try {
    const asset = await api("/api/assets", { method: "POST", body: JSON.stringify({
      target, name: $("#nsName").value.trim() || null, kind: $("#nsKind").value,
      add_to_scope: authorized, authorized }) });
    await api(`/api/assets/${asset.id}/scan`, { method: "POST", body: JSON.stringify({ profile: $("#nsProfile").value }) });
    closeDrawer(); toast("Hunt started ✓");
    S.view = "live"; $$("#nav button").forEach(x => x.classList.toggle("active", x.dataset.view === "live"));
    const [t, s] = TITLES.live; $("#viewTitle").textContent = t; $("#viewSub").textContent = s;
    render();
  } catch (e) {
    let msg = e.message.replace(/[{}"]/g, "").replace("detail:", "").slice(0, 220);
    if (msg.includes("out of scope"))
      msg = "Out of scope. Tick the authorization box above to add this target and scan it.";
    $("#nsErr").textContent = msg;
  }
};
window.runScan = async (aid) => {
  const profile = "owasp-full";
  await api(`/api/assets/${aid}/scan`, { method: "POST", body: JSON.stringify({ profile }) });
  closeDrawer(); toast("Scan queued ✓");
  S.view = "live"; $$("#nav button").forEach(x => x.classList.toggle("active", x.dataset.view === "live"));
  render();
};

function scansTable(ss) {
  if (!ss || !ss.length) return `<div class="empty"><strong>No scans yet</strong>Scans you start will be listed here.</div>`;
  return `<div class="table-wrap"><table><tbody>${ss.map(s => {
    let stats = {}; try { stats = JSON.parse(s.stats || "{}"); } catch {}
    const active = s.status === "running" || s.status === "queued";
    const retryable = s.status === "failed" || s.status === "cancelled";
    return `<tr>
      <td>${esc(PROFILE_LABELS[s.profile] || s.profile)}</td>
      <td><span class="status ${esc(s.status)}">${esc(STATUS_LABELS[s.status] || s.status)}</span></td>
      <td class="muted nowrap">${stats.total != null ? stats.total + " findings" : "—"}</td>
      <td class="muted nowrap" style="font-size:12px">${timeAgo(s.created_at)}</td>
      <td class="right nowrap">
        ${active ? `<button class="btn sm danger-ghost" onclick="cancelScan('${esc(s.id)}')">Cancel</button>` : ""}
        ${retryable ? `<button class="btn sm ghost" onclick="retryScan('${esc(s.id)}')">Retry</button>` : ""}
      </td></tr>`;
  }).join("")}</tbody></table></div>`;
}

// ---- TOOLS --------------------------------------------------
async function renderTools(v) {
  const tools = await api("/api/tools");
  const installed = tools.filter(t => t.installed).length;
  const groups = {};
  tools.forEach(t => (groups[t.category || "Other"] ||= []).push(t));
  v.innerHTML = `<div class="panel">
    <div class="panel-head">
      <div>
        <h2>Tool status</h2>
        <p class="panel-sub" style="margin:0">${installed} of ${tools.length} installed. A missing tool is skipped during a scan, and the console says so.</p>
      </div>
      <span class="faint" style="font-size:12px">Install or update with <code>./update.sh</code></span>
    </div>
    ${Object.keys(groups).map(cat => `
      <h3 style="font-size:12px;color:var(--text-2);margin:20px 0 10px;font-weight:650">${esc(cat)}</h3>
      <div class="tool-grid">${groups[cat].map(t => `
        <div class="tool">
          <div class="head">
            <span class="name">${esc(t.binary)}</span>
            <span class="status ${t.installed ? "done" : "cancelled"}">${t.installed ? "Installed" : "Missing"}</span>
          </div>
          ${t.installed
            ? `<div class="ver">${esc(t.version || "installed")}</div>`
            : `<div class="hint">${esc(t.install_hint || "Run ./update.sh to install.")}</div>`}
        </div>`).join("")}
      </div>`).join("")}
  </div>`;
}

// ---- AUDIT --------------------------------------------------
async function renderAudit(v) {
  const rows = await api("/api/audit?limit=300");
  v.innerHTML = `<div class="panel">
    <div class="panel-head">
      <div>
        <h2>Audit log</h2>
        <p class="panel-sub" style="margin:0">Newest first. Records scans, scope and settings changes, and emergency stops, with the caller's IP.</p>
      </div>
    </div>
    ${rows.length ? `<div class="table-wrap"><table>
      <thead><tr><th>When (UTC)</th><th>Action</th><th>Target</th><th>Detail</th><th>From</th></tr></thead>
      <tbody>${rows.map(r => `<tr>
        <td class="nowrap muted" style="font-size:12px">${esc(String(r.ts || "").replace("T", " ").slice(0, 19))}</td>
        <td><span class="tag">${esc(r.action)}</span></td>
        <td class="mono" style="font-size:12px;overflow-wrap:anywhere">${esc(r.target || "—")}</td>
        <td class="muted" style="font-size:12px">${esc(r.detail || "")}</td>
        <td class="mono faint nowrap" style="font-size:11px">${esc(r.ip || "")}</td>
      </tr>`).join("")}</tbody></table></div>`
      : `<div class="empty"><strong>Nothing recorded yet</strong>Actions you take in Argus, such as starting scans or changing scope, appear here.</div>`}
  </div>`;
}

// ---- utils --------------------------------------------------
function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.classList.add("show");
  clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove("show"), 2600);
}
function timeAgo(iso) {
  if (!iso) return "—";
  const d = (Date.now() - new Date(iso).getTime()) / 1000;
  if (d < 60) return "just now";
  if (d < 3600) return Math.floor(d / 60) + "m ago";
  if (d < 86400) return Math.floor(d / 3600) + "h ago";
  return Math.floor(d / 86400) + "d ago";
}

// ---- start --------------------------------------------------
if (S.key) {
  api("/api/stats").then(() => { $("#gate").classList.add("hide"); boot(); })
    .catch(() => openGate());
} else openGate();


window.exportAsset = async (fmt) => {
  const aid = $("#rAsset").value;
  const r = await fetch(`/api/assets/${aid}/export/${fmt}`, { headers: { "x-api-key": S.key } });
  if (!r.ok) { toast("Export failed"); return; }
  const blob = await r.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `argus-${aid}.${fmt}`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
};
