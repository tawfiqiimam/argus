/* ============================================================
   T4WF1Q VMS — dashboard app (vanilla JS, no build step)
   ============================================================ */
const S = {
  key: localStorage.getItem("t4wf1q_key") || "",
  view: "overview",
  assets: [], findings: [], ws: null,
  logBuf: [], feedBuf: [], liveScan: null,
  owasp: {},
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
function connectWS() {
  if (S.ws) try { S.ws.close(); } catch {}
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws?key=${encodeURIComponent(S.key)}`);
  S.ws = ws;
  ws.onopen = () => $("#liveDot").classList.add("on");
  ws.onclose = () => { $("#liveDot").classList.remove("on"); setTimeout(connectWS, 3000); };
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
    if (S.view === "live") updateScanHeader();
    if (ev.status === "done") { toast("Scan complete ✓"); softRefresh(); }
  } else if (ev.kind === "subdomain") {
    if (S.view === "live") appendLog({ level: "info", message: `↳ live host: ${ev.host} [${ev.status || "?"}] ${ev.title || ""}` });
  } else if (ev.kind === "report_ready") {
    toast("Report generated ✓");
  }
}

let softTimer = null;
function softRefresh() { clearTimeout(softTimer); softTimer = setTimeout(() => render(true), 600); }

// ---- navigation ---------------------------------------------
const TITLES = {
  overview: ["Overview", "Program-wide security posture"],
  assets: ["Assets", "Targets under continuous assessment"],
  findings: ["Findings", "Deduplicated, triaged vulnerabilities"],
  live: ["Live Scan", "Real-time scan console & finding feed"],
  checklist: ["OWASP Checklist", "Manual review coverage per asset"],
  reports: ["Reports", "Auto-generated assessment reports"],
  scope: ["Scope", "Authorized targets & safety guard"],
};
$$("#nav button").forEach(b => b.onclick = () => {
  S.view = b.dataset.view;
  $$("#nav button").forEach(x => x.classList.toggle("active", x === b));
  const [t, s] = TITLES[S.view]; $("#viewTitle").textContent = t; $("#viewSub").textContent = s;
  render();
});

// ---- boot ---------------------------------------------------
async function boot() {
  connectWS();
  try {
    const sc = await api("/api/scope");
    $("#scopeChip").textContent = sc.enforce
      ? `scope: ${sc.allow.length} allowed`
      : "scope: OFF ⚠";
  } catch {}
  render();
}

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
  } catch (e) { v.innerHTML = `<div class="empty">error: ${esc(e.message)}</div>`; }
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
      <div class="hb-row">
        <span class="hb-ico">🎯</span>
        <input id="huntInput" autocomplete="off" spellcheck="false"
               placeholder="Enter a domain or URL and press Enter to hunt —  e.g. example.com">
        <button class="btn hb-go" onclick="quickHunt()">Hunt ▸</button>
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
    if (go) { go.disabled = false; go.textContent = "Hunt ▸"; }
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
      </tbody></table>` : `<div class="empty">No assets. Add your first target.</div>`}
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
        ${["open", "triaged", "in_progress", "fixed", "verified", "false_positive", "accepted"].map(s => `<option>${s}</option>`).join("")}</select>
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
  if (!fs || !fs.length) return `<div class="empty">No findings.</div>`;
  return `<table><thead><tr><th>Sev</th><th>Title</th>${compact ? "" : "<th>OWASP</th><th>Location</th><th>Status</th>"}</tr></thead><tbody>
    ${fs.map(f => `<tr class="clickable" onclick="viewFinding('${f.id}')">
      <td><span class="pill p-${f.severity}">${f.severity}</span></td>
      <td>${esc(f.title)}${compact ? `<div class="mono muted" style="font-size:11px">${esc(f.location || f.host || "")}</div>` : ""}</td>
      ${compact ? "" : `<td class="mono muted">${f.owasp || "—"}</td>
      <td class="mono muted" style="font-size:11px">${esc(f.location || f.host || "—")}</td>
      <td><span class="tag">${f.status}</span></td>`}
    </tr>`).join("")}</tbody></table>`;
}

// ---- LIVE ---------------------------------------------------
function renderLive(v) {
  v.innerHTML = `
    <div class="panel" id="scanHead" style="margin-bottom:14px"></div>
    <div class="row cols-2b">
      <div class="panel"><h2>Scan console</h2><div class="console" id="console"></div></div>
      <div class="panel"><h2>Live finding feed</h2><div class="feed" id="feed"></div></div>
    </div>`;
  updateScanHeader();
  const con = $("#console"); con.innerHTML = "";
  S.logBuf.slice(-200).forEach(appendLog);
  const feed = $("#feed");
  feed.innerHTML = S.feedBuf.length ? "" : `<div class="empty">Findings stream here during a scan.</div>`;
  S.feedBuf.forEach(f => feed.insertAdjacentHTML("beforeend", feedItem(f)));
}
function updateScanHeader() {
  const h = $("#scanHead"); if (!h) return;
  const s = S.liveScan;
  if (!s) { h.innerHTML = `<div class="empty" style="padding:14px">No active scan. Start one from Assets or “New Scan”.</div>`; return; }
  const pct = s.progress || 0;
  h.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <div><strong>${(s.stage || s.status || "running").toUpperCase()}</strong>
        <span class="muted mono" style="font-size:11px">· ${esc(s.scan_id || "")}</span></div>
      <div class="muted">${pct}%</div></div>
    <div class="bar"><i style="width:${pct}%"></i></div>`;
}
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
      <button class="btn sm" onclick="genReport()">Generate report</button>
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
      <h2>Scope — authorized targets</h2>
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
      <div class="rulelist">${allowRules.map(ruleRow).join("") || "<div class='muted'>none</div>"}</div>
      <h2 style="margin-top:16px">Denylist (${denyRules.length})</h2>
      <div class="rulelist">${denyRules.map(ruleRow).join("") || "<div class='muted'>none</div>"}</div>
    </div>

    <div>
      <div class="panel" style="margin-bottom:14px">
        <h2>Automation</h2>
        <label class="chkline"><input type="checkbox" id="setAuto" ${set.automation_enabled ? "checked" : ""} onchange="toggleSetting('automation_enabled',this.checked)">
          <span>Continuous assessment — daily full scan + ${set.change_watch_minutes}-min change-watch</span></label>
        <label class="chkline" style="margin-top:10px"><input type="checkbox" id="setEnforce" ${set.scope_enforce ? "checked" : ""} onchange="toggleSetting('scope_enforce',this.checked)">
          <span>Enforce scope (strongly recommended)</span></label>
        <p class="muted" style="font-size:11px;margin-top:10px">Daily full scan runs around ${String(set.full_scan_cron_hour).padStart(2,'0')}:00. Changes apply live — no restart needed.</p>
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
window.toggleSetting = async (key, val) => {
  await api("/api/settings", { method: "POST", body: JSON.stringify({ [key]: val }) });
  toast(val ? "Enabled" : "Disabled");
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
  $("#drawer").innerHTML = `<span class="x" onclick="closeDrawer()">✕</span>${html}`;
  $("#drawer").classList.add("open"); $("#overlay").classList.add("on");
}
window.closeDrawer = () => { $("#drawer").classList.remove("open"); $("#overlay").classList.remove("on"); };
$("#overlay").onclick = closeDrawer;

window.viewFinding = async (fid) => {
  const f = await api(`/api/findings/${fid}`);
  let refs = []; try { refs = JSON.parse(f.reference || "[]"); } catch {}
  const statuses = ["open", "triaged", "in_progress", "fixed", "verified", "false_positive", "accepted"];
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
      `<button class="btn sm ${s === f.status ? "" : "ghost"}" onclick="setFindingStatus('${f.id}','${s}')">${s}</button>`).join("")}</div>
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
    <h2>New scan &amp; hunt</h2>
    <label>Target — URL, host, or root domain</label>
    <input id="nsTarget" placeholder="example.com   (root domain = full subdomain hunt)" style="width:100%;margin:6px 0 12px">
    <label>Name (optional)</label>
    <input id="nsName" placeholder="My app" style="width:100%;margin:6px 0 12px">
    <div class="cols-2" style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
      <div><label>Kind</label>
        <select id="nsKind" style="width:100%;margin:6px 0 12px">
          <option value="program">bug-bounty program (domain)</option>
          <option value="web">web app</option><option value="host">single host</option></select></div>
      <div><label>Profile</label>
        <select id="nsProfile" style="width:100%;margin:6px 0 12px">
          <option value="owasp-full">owasp-full — hunt + web + network</option>
          <option value="web">web — http + nuclei</option>
          <option value="recon">recon — subdomains only</option>
          <option value="network">network — nmap</option>
          <option value="quick">quick</option></select></div>
    </div>
    <div class="authbox">
      <label class="chkline"><input type="checkbox" id="nsAuth">
        <span>I own this target or I'm <b>authorized</b> to test it (e.g. a bug-bounty scope). It will be added to scope.</span></label>
    </div>
    <button class="btn" style="width:100%;text-align:center;margin-top:14px" onclick="submitScan()">Add to scope &amp; start hunt</button>
    <p id="nsErr" class="sev-crit" style="font-size:12px"></p>
    <p class="muted" style="font-size:11px;margin-top:10px">A root domain runs the full pipeline: subdomain discovery → live-host probe → OWASP Top 10 + CVE scan on every in-scope host. Only authorized targets are ever scanned.</p>`);
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
  if (!ss || !ss.length) return `<div class="empty">No scans yet.</div>`;
  return `<table><tbody>${ss.map(s => {
    let stats = {}; try { stats = JSON.parse(s.stats || "{}"); } catch {}
    return `<tr><td><span class="tag">${s.profile}</span></td>
      <td>${s.status === "done" ? "✓" : s.status === "failed" ? "✗" : "⟲"} ${s.status}</td>
      <td class="muted">${stats.total != null ? stats.total + " found" : ""}</td>
      <td class="muted right" style="font-size:12px">${timeAgo(s.created_at)}</td></tr>`;
  }).join("")}</tbody></table>`;
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
