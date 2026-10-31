"use strict";

// =====================================================================
// helpers
// =====================================================================
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const icon = (name, cls = "") => `<svg class="ic ${cls}"><use href="/static/icons.svg#i-${name}"/></svg>`;
const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MODES = ["Normal", "Lockdown", "Free access"];
const MODE_LABEL = { pin: "PIN", card: "Card", card_or_pin: "Card or PIN", card_and_pin: "Card + PIN", face: "Face", face_and_pin: "Face + PIN" };
const MODE_HINT = { face: "Convenience tier: a single camera cannot rule out a photo of a face.", face_and_pin: "Recommended secure biometric mode." };
let ME = null;

async function api(path, opts = {}) {
  const isBody = opts.body !== undefined && !(opts.body instanceof Blob);
  const res = await fetch(path, {
    method: opts.method || (opts.body !== undefined ? "POST" : "GET"),
    headers: isBody ? { "Content-Type": "application/json" } : (opts.headers || {}),
    body: isBody ? JSON.stringify(opts.body) : opts.body,
    credentials: "same-origin",
  });
  if (res.status === 401 && !path.startsWith("/api/login")) { showLogin(); throw new Error("Signed out"); }
  const data = res.headers.get("content-type")?.includes("json") ? await res.json() : null;
  if (!res.ok) {
    const d = data?.detail;
    throw new Error(Array.isArray(d) ? d.map((x) => x.msg.replace(/^Value error, /, "")).join("; ") : d || res.statusText);
  }
  return data;
}

function toast(msg, kind = "") {
  const t = document.createElement("div");
  t.className = `toast ${kind}`;
  t.innerHTML = `${icon(kind === "bad" ? "alert-triangle" : "circle-check")}<span>${esc(msg)}</span>`;
  $("#toasts").append(t);
  setTimeout(() => t.remove(), kind === "bad" ? 6000 : 3500);
}
const fail = (e) => { if (e.message !== "Signed out") toast(e.message, "bad"); };

const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const fmtDate = (ts) => new Date(ts * 1000).toLocaleString([], { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
const fmtDay = (ts) => new Date(ts * 1000).toLocaleDateString([], { day: "numeric", month: "short", year: "numeric" });
const ago = (ts) => {
  if (!ts) return "never";
  const s = Date.now() / 1000 - ts;
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return fmtDay(ts);
};
const hhmm = (m) => `${String(Math.floor(m / 60) % 24).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;
const parseHHMM = (s) => { const [h, m] = s.split(":").map(Number); return h * 60 + m; };
const initials = (name) => (name || "?").split(/\s+/).filter(Boolean).slice(0, 2).map((p) => p[0].toUpperCase()).join("");
const isAdmin = () => ME?.role === "admin";
const canOperate = () => ME && ME.role !== "viewer";
const fmtBytes = (n) => n == null ? "—" : n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.round(n / 1024)} KB`;
const fmtUptime = (s) => { if (s == null) return "—"; const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60); return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`; };
const kv = (label, value) => `<div class="kv"><span>${label}</span><b>${value ?? "—"}</b></div>`;
const emptyState = (ic, title, text) => `<div class="empty">${icon(ic, "xl")}<b>${title}</b>${text}</div>`;

// ---------- modal dialogs (promise based) ----------
function dialog({ title, text = "", tone = "", ic = "info-circle", confirm = "Confirm", danger = false, input = null, cancel = "Cancel" }) {
  return new Promise((resolve) => {
    const m = $("#modal");
    $("#modal-body").innerHTML = `<div class="modal-ico ${tone}">${icon(ic, "lg")}</div><h3>${esc(title)}</h3><p>${text}</p>
      ${input ? `<label class="field"><span>${esc(input.label)}</span><input id="dlg-input" placeholder="${esc(input.placeholder || "")}"></label>` : ""}
      <div class="modal-acts">${cancel ? `<button class="btn" data-r="0">${esc(cancel)}</button>` : ""}<button class="btn ${danger ? "solid-danger" : "primary"}" data-r="1">${esc(confirm)}</button></div>`;
    m.classList.remove("hidden");
    $("#dlg-input")?.focus();
    const done = (ok) => { m.classList.add("hidden"); m.onclick = null; resolve(ok ? (input ? $("#dlg-input").value : true) : null); };
    m.onclick = (e) => { const b = e.target.closest("[data-r]"); if (b) done(b.dataset.r === "1"); else if (e.target === m) done(false); };
    $("#dlg-input")?.addEventListener("keydown", (e) => { if (e.key === "Enter") done(true); });
  });
}

// ---------- side panel ----------
let panelState = null;
function openPanel(html, state = {}) {
  $("#panel-body").innerHTML = html;
  $("#panel").classList.remove("hidden");
  panelState = state;
}
function closePanel() { $("#panel").classList.add("hidden"); panelState = null; }
$("#panel").addEventListener("click", (e) => { if (e.target.id === "panel" || e.target.closest(".close")) closePanel(); });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { closePanel(); $("#lightbox").classList.add("hidden"); hideMenus(); }
  if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) { e.preventDefault(); $("#search").focus(); }
});
function panelShell({ avatar = "", title, sub = "", tabs = [] }) {
  return `<div class="panel-head"><div class="panel-title">${avatar}<div><h2>${title}</h2><p>${sub}</p></div>
    <button class="icon-btn close" title="Close">${icon("x")}</button></div>
    ${tabs.length ? `<div class="tabs">${tabs.map((t, i) => `<button data-tab="${i}" class="${i === 0 ? "on" : ""}">${t}</button>`).join("")}</div>` : ""}</div>
    <div class="panel-content" id="panel-content"></div>`;
}
function bindTabs(renderTab) {
  $$("#panel-body .tabs button").forEach((b) => b.addEventListener("click", () => {
    $$("#panel-body .tabs button").forEach((x) => x.classList.toggle("on", x === b));
    renderTab(Number(b.dataset.tab));
  }));
  renderTab(0);
}

// ---------- lightbox ----------
document.addEventListener("click", (e) => {
  const img = e.target.closest("img.thumb, .shot img");
  if (img) {
    $("#lightbox img").src = img.src;
    $("#lightbox figcaption").textContent = img.dataset.cap || "";
    $("#lightbox").classList.remove("hidden");
    e.stopPropagation();
  }
}, true);
$("#lightbox").addEventListener("click", () => $("#lightbox").classList.add("hidden"));

// =====================================================================
// auth
// =====================================================================
function showLogin() { $("#app").classList.add("hidden"); $("#login").classList.remove("hidden"); closePanel(); }
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const r = await api("/api/login", { body: { username: f.get("username"), password: f.get("password"), code: f.get("code") || "" } });
    if (r.mfa_required) { $("#code-field").classList.remove("hidden"); $("#login-error").textContent = ""; $("[name=code]").focus(); return; }
    $("#login-error").textContent = "";
    e.target.reset(); $("#code-field").classList.add("hidden");
    await boot();
    if (r.mfa_setup_required) securityPanel(true);
  } catch (err) { $("#login-error").textContent = err.message; }
});

// =====================================================================
// chrome: theme, menus, mode, search, live
// =====================================================================
function setTheme(t) {
  document.documentElement.dataset.theme = t;
  $("#theme").innerHTML = icon(t === "dark" ? "sun" : "moon");
  try { localStorage.setItem("lintel-theme", t); } catch { /* storage unavailable */ }
}
try { setTheme(localStorage.getItem("lintel-theme") || "light"); } catch { setTheme("light"); }
$("#theme").addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));

function hideMenus() { $("#mode-menu").classList.add("hidden"); $("#user-menu").classList.add("hidden"); $("#search-results").classList.add("hidden"); }
document.addEventListener("click", (e) => { if (!e.target.closest(".top-right, .search")) hideMenus(); });
$("#mode-btn").addEventListener("click", () => { const m = $("#mode-menu"); const show = m.classList.contains("hidden"); hideMenus(); m.classList.toggle("hidden", !show); });
$("#user-btn").addEventListener("click", () => { const m = $("#user-menu"); const show = m.classList.contains("hidden"); hideMenus(); m.classList.toggle("hidden", !show); });
$("#user-menu").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-act]"); if (!b) return; hideMenus();
  if (b.dataset.act === "logout") { await api("/api/logout", { method: "POST" }); location.reload(); }
  if (b.dataset.act === "security") securityPanel();
});
$("#mode-menu").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-mode]"); if (!b) return; hideMenus();
  const mode = Number(b.dataset.mode);
  if (!canOperate()) return toast("Viewer accounts cannot change the site mode", "bad");
  if (mode !== 0) {
    const ok = await dialog({ title: `Switch the site to ${MODES[mode]}?`, tone: "bad", ic: "alert-octagon", danger: true, confirm: MODES[mode],
      text: mode === 1 ? "Every door refuses everyone except cardholders with lockdown override. This raises a critical alarm and is recorded against your account."
        : "Every door is released and schedules stop applying. Use for evacuations. This is recorded against your account." });
    if (!ok) return;
  }
  try { await api("/api/mode", { body: { mode } }); setMode(mode); toast(`Site mode: ${MODES[mode]}`); } catch (err) { fail(err); }
});
function setMode(mode) {
  $("#mode-text").textContent = MODES[mode];
  $("#mode-btn").className = `mode-btn ${mode === 1 ? "lockdown" : mode === 2 ? "free" : ""}`;
  const b = $("#banner");
  b.className = `banner ${mode === 1 ? "bad" : "warn"} ${mode ? "" : "hidden"}`;
  b.innerHTML = mode === 1 ? `${icon("alert-octagon")} Site lockdown is active. Only override cardholders can enter.`
    : `${icon("alert-triangle")} Free access is active. Doors are released and schedules are suspended.`;
}

// global search: people and doors
let searchTimer;
$("#search").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(runSearch, 150); });
$("#search").addEventListener("focus", runSearch);
async function runSearch() {
  const q = $("#search").value.trim();
  const box = $("#search-results");
  if (!q) { box.classList.add("hidden"); return; }
  const [people, doors] = await Promise.all([api(`/api/cardholders?q=${encodeURIComponent(q)}`), api("/api/doors")]);
  const ds = doors.filter((d) => `${d.name} ${d.area} ${d.serial || ""}`.toLowerCase().includes(q.toLowerCase()));
  box.innerHTML = (people.length ? `<div class="grp">People</div>` + people.slice(0, 6).map((p) =>
    `<a href="#" data-person="${p.id}"><span class="avatar">${initials(p.first_name + " " + p.last_name)}</span><span>${esc(p.first_name)} ${esc(p.last_name)}<br><small class="muted">${esc(p.department || p.email || "")}</small></span></a>`).join("") : "")
    + (ds.length ? `<div class="grp">Doors</div>` + ds.slice(0, 5).map((d) =>
      `<a href="#" data-door="${d.id}"><span class="door-ico">${icon("door")}</span><span>${esc(d.name)}<br><small class="muted">Door ${d.id}${d.area ? " · " + esc(d.area) : ""}</small></span></a>`).join("") : "")
    || `<div class="empty" style="padding:16px">No matches for “${esc(q)}”</div>`;
  box.classList.remove("hidden");
}
$("#search-results").addEventListener("click", (e) => {
  const a = e.target.closest("a"); if (!a) return; e.preventDefault(); hideMenus(); $("#search").value = "";
  if (a.dataset.person) cardholderPanel(Number(a.dataset.person));
  if (a.dataset.door) doorPanel(Number(a.dataset.door));
});

// live updates
function connectWs() {
  const socket = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
  socket.onopen = () => setSys();
  socket.onclose = () => { $("#sys-dot").className = "dot warn"; $("#sys-text").textContent = "Reconnecting…"; setTimeout(connectWs, 2000); };
  socket.onmessage = (m) => onLive(JSON.parse(m.data));
}
async function setSys() {
  try {
    const o = await api("/api/overview");
    const off = o.doors.filter((d) => !d.online).length;
    $("#sys-dot").className = `dot ${off ? "warn" : "ok"}`;
    $("#sys-text").textContent = !o.doors.length ? "No doors yet" : off ? `${off} door${off > 1 ? "s" : ""} offline` : "All doors online";
    $("#site-name").textContent = o.site_name;
    $("#site-doors").textContent = `${o.doors.length} door${o.doors.length === 1 ? "" : "s"}`;
    setMode(o.mode);
  } catch { /* signed out */ }
}
function onLive(msg) {
  if (msg.type === "event") {
    const body = $("#live-body");
    if (body && msg.event.kind.startsWith("access.")) { $(".empty-row", body)?.remove(); body.insertAdjacentHTML("afterbegin", eventRow(msg.event, true)); trimRows(body, 60); }
    if (msg.event.kind.startsWith("access.") && current === "monitor") refreshStats();
  }
  if (msg.type === "photo") $$(`tr[data-seq="${msg.seq}"] .ph`).forEach((c) => (c.innerHTML = photoCell({ seq: msg.seq, photo: 1 })));
  if (msg.type === "alarm" && msg.alarm.priority === 1) { toast(`Critical: ${msg.alarm.title}`, "bad"); chime(); }
  if (["alarm", "alarms"].includes(msg.type)) { refreshBadges(); if ($("#queue")) loadQueue(current === "monitor"); }
  if (["doors", "devices"].includes(msg.type)) { setSys(); refreshBadges(); if (["monitor", "doors"].includes(current) && $("#panel").classList.contains("hidden")) render(); }
  if (msg.type === "mode") setMode(msg.mode);
  if (["diag", "media"].includes(msg.type) && panelState?.door === msg.door && panelState.tab === 2) panelState.refresh?.();
}
const trimRows = (body, n) => { while (body.children.length > n) body.lastElementChild.remove(); };
function chime() {
  try {
    const ctx = new AudioContext(), o = ctx.createOscillator(), g = ctx.createGain();
    o.connect(g); g.connect(ctx.destination); g.gain.value = 0.06; o.frequency.value = 880; o.start();
    setTimeout(() => (o.frequency.value = 660), 160); setTimeout(() => o.stop(), 380);
  } catch { /* audio blocked until the page is interacted with */ }
}
async function refreshBadges() {
  try {
    const [al, devs] = await Promise.all([api("/api/alarms"), api("/api/devices")]);
    const active = al.filter((a) => a.state === "active").length;
    for (const el of [$("#nav-alarms"), $("#bell-count")]) { el.textContent = active; el.classList.toggle("hidden", !active); }
    const waiting = devs.filter((d) => d.door_id == null).length;
    $("#nav-devices").textContent = waiting; $("#nav-devices").classList.toggle("hidden", !waiting);
  } catch { /* ignore */ }
}

// =====================================================================
// events
// =====================================================================
function eventInfo(e) {
  const k = e.kind;
  if (k === "access.granted") return ["ok", "lock-open", "Access granted"];
  if (k === "access.denied") return e.reason === "locked_out" ? ["bad", "alert-octagon", "Keypad locked out"] : ["bad", "lock", "Access denied"];
  if (k === "credential.enrolled") return ["accent", "id-badge-2", "Card enrolled"];
  if (k === "door.online") return ["ok", "plug-connected", "Door online"];
  if (k === "door.offline") return ["warn", "plug-connected-x", "Door offline"];
  if (k === "link.rejected") return ["bad", "shield-lock", "Rejected traffic"];
  if (k === "site.mode") return ["violet", "broadcast", "Site mode"];
  if (k === "photo.attached") return ["", "photo", "Photo stored"];
  if (k.startsWith("device.")) return ["info", "cpu", "Device " + k.split(".")[1].replace(/_/g, " ")];
  if (k.startsWith("alarm.")) return ["warn", "bell", "Alarm " + k.split(".")[1]];
  if (k.startsWith("operator.")) return ["", "user-shield", "Operator " + k.split(".")[1].replace(/_/g, " ")];
  if (k.startsWith("door.")) return ["", "door", "Door " + k.split(".")[1]];
  if (k.startsWith("cardholder.")) return ["", "user", "Cardholder " + k.split(".")[1].replace(/_/g, " ")];
  return ["", "activity", k];
}
const photoCell = (e) => e.photo
  ? `<img class="thumb" src="/api/photos/${e.seq}.jpg" data-cap="Event #${e.seq}" loading="lazy" alt="">`
  : `<span class="thumb empty">${icon("photo", "sm")}</span>`;
function eventRow(e, fresh = false) {
  const [tone, ic, label] = eventInfo(e);
  const method = (e.detail.match(/\(([^)]*)\)$/) || [])[1];
  const detail = e.kind.startsWith("access.") || e.kind === "credential.enrolled" ? (e.detail.split(": ")[1] || "").replace(/ \([^)]*\)$/, "") : e.detail;
  return `<tr data-seq="${e.seq}" class="${fresh ? "fresh" : ""}">
    <td class="muted" style="white-space:nowrap">${fmtTime(e.ts)}<br><small>${fmtDay(e.ts)}</small></td>
    <td><span class="badge ${tone}">${icon(ic)}${label}</span></td>
    <td>${e.cardholder_name ? `<a href="#" data-person="${e.cardholder_id}">${esc(e.cardholder_name)}</a>` : e.operator ? `<span class="muted">${esc(e.operator)}</span>` : `<span class="muted">—</span>`}</td>
    <td>${e.door_name ? `<a href="#" data-door="${e.door_id}">${esc(e.door_name)}</a>` : `<span class="muted">—</span>`}</td>
    <td class="muted">${esc(detail)}${method ? ` <span class="badge">${esc(method)}</span>` : ""}</td>
    <td class="ph">${photoCell(e)}</td></tr>`;
}
const eventTable = (rows, id = "live-body") => `<div class="table-wrap"><table><thead><tr><th style="width:110px">Time</th><th>Event</th><th>Person</th><th>Door</th><th>Details</th><th style="width:70px">Photo</th></tr></thead>
  <tbody id="${id}">${rows.length ? rows.map((e) => eventRow(e)).join("") : `<tr class="empty-row"><td colspan="6">${emptyState("activity", "No activity yet", "Events appear here the moment they happen.")}</td></tr>`}</tbody></table></div>`;
document.addEventListener("click", (e) => {
  const p = e.target.closest("a[data-person]"), d = e.target.closest("a[data-door]");
  if (p && !p.closest("#search-results")) { e.preventDefault(); cardholderPanel(Number(p.dataset.person)); }
  if (d && !d.closest("#search-results")) { e.preventDefault(); doorPanel(Number(d.dataset.door)); }
});

// =====================================================================
// pages
// =====================================================================
let current = "monitor";
const PAGES = {};
const TITLES = { monitor: "Monitor", alarms: "Alarms", activity: "Activity", cardholders: "Cardholders", groups: "Access groups", schedules: "Schedules", doors: "Doors & devices", operators: "Operators", settings: "Settings", audit: "Audit trail" };
async function render() {
  current = (location.hash || "#monitor").slice(1);
  if (!PAGES[current]) current = "monitor";
  $$("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.page === current));
  document.title = `${TITLES[current]} · Lintel Command`;
  try { await PAGES[current]($("#page")); } catch (e) { fail(e); }
}
window.addEventListener("hashchange", render);
const head = (title, sub, actions = "") => `<div class="page-head"><div><h1>${title}</h1><p>${sub}</p></div><div class="actions">${actions}</div></div>`;

// ---------- monitor ----------
PAGES.monitor = async (el) => {
  el.innerHTML = head("Monitor", "Live state of every door, alarm and access decision")
    + `<div id="stats" class="grid stats"></div>
    <div class="grid monitor">
      <div class="card"><div class="card-head"><h2>Live access</h2><a href="#activity" class="btn sm ghost">All activity ${icon("chevron-right", "sm")}</a></div><div id="live"></div></div>
      <div class="grid" style="gap:16px">
        <div class="card"><div class="card-head"><h2>Alarm queue</h2><a href="#alarms" class="btn sm ghost">History</a></div><div id="queue"></div></div>
        <div class="card"><div class="card-head"><h2>Doors</h2><a href="#doors" class="btn sm ghost">Manage</a></div><div id="door-list"></div></div>
      </div>
    </div>`;
  $("#live").innerHTML = eventTable(await api("/api/events?limit=40&kind=access.*"));
  await Promise.all([refreshStats(), loadQueue(true)]);
};
async function refreshStats() {
  const o = await api("/api/overview");
  if (!$("#stats")) return;
  const online = o.doors.filter((d) => d.online).length;
  $("#stats").innerHTML = `
    <div class="card stat"><div class="stat-ico ${online === o.doors.length && o.doors.length ? "ok" : "warn"}">${icon("door")}</div><div><div class="label">Doors online</div><div class="value">${online}<small> / ${o.doors.length}</small></div></div></div>
    <div class="card stat"><div class="stat-ico ${o.active_alarms ? "bad" : ""}">${icon("bell")}</div><div><div class="label">Active alarms</div><div class="value">${o.active_alarms}</div></div></div>
    <div class="card stat"><div class="stat-ico ok">${icon("lock-open")}</div><div><div class="label">Granted today</div><div class="value">${o.granted_today}</div></div></div>
    <div class="card stat"><div class="stat-ico ${o.denied_today ? "warn" : ""}">${icon("lock")}</div><div><div class="label">Denied today</div><div class="value">${o.denied_today}</div></div></div>`;
  $("#door-list").innerHTML = o.doors.length ? o.doors.map((d) => `<div class="door-row" data-open-door="${d.id}">
      <div class="door-ico">${icon("door")}</div><div class="grow"><b>${esc(d.name)}</b><small>${MODE_LABEL[d.credential_mode] || "PIN"}${d.area ? " · " + esc(d.area) : ""}</small></div>
      <span class="badge ${d.online ? "ok" : "bad"}"><span class="dot ${d.online ? "ok" : "bad"}"></span>${d.online ? "Online" : "Offline"}</span></div>`).join("")
    : emptyState("door", "No doors", "Adopt a keypad under Doors & devices.");
  $$("[data-open-door]").forEach((r) => r.addEventListener("click", () => doorPanel(Number(r.dataset.openDoor))));
}

// ---------- alarms ----------
async function loadQueue(compact = false) {
  const el = $("#queue");
  if (!el) return;
  const al = await api(`/api/alarms${compact ? "" : "?state=all"}`);
  el.innerHTML = al.length ? al.slice(0, compact ? 8 : 300).map(alarmItem).join("") : emptyState("shield-check", "All clear", "No open alarms.");
  $$("[data-ack]", el).forEach((b) => b.addEventListener("click", () => alarmAction(b.dataset.ack, "ack")));
  $$("[data-clear]", el).forEach((b) => b.addEventListener("click", () => alarmAction(b.dataset.clear, "clear")));
}
function alarmItem(a) {
  const st = a.state === "active" ? `<span class="badge bad">Active</span>` : a.state === "acknowledged" ? `<span class="badge warn">Acknowledged</span>` : `<span class="badge">Cleared</span>`;
  const acts = canOperate() && a.state !== "cleared"
    ? `<div class="alarm-acts">${a.state === "active" ? `<button class="btn sm" data-ack="${a.id}">Acknowledge</button>` : ""}<button class="btn sm ghost" data-clear="${a.id}">Clear</button></div>` : "";
  return `<div class="alarm p${a.priority} ${a.state}"><div class="stripe"></div><div class="alarm-main">
    <div class="alarm-top"><div class="alarm-title">${esc(a.title)}</div><span class="badge ${a.priority === 1 ? "bad" : a.priority === 2 ? "warn" : ""}">P${a.priority}</span></div>
    <div class="alarm-meta">${st}<span>${fmtDate(a.ts)}</span>${a.door_name ? `<span>· ${esc(a.door_name)}</span>` : ""}${a.ack_by ? `<span>· ${esc(a.ack_by)}</span>` : ""}${a.note ? `<span>· “${esc(a.note)}”</span>` : ""}</div>
    ${acts}</div></div>`;
}
async function alarmAction(id, what) {
  const note = await dialog({ title: what === "ack" ? "Acknowledge alarm" : "Clear alarm", ic: "bell", confirm: what === "ack" ? "Acknowledge" : "Clear",
    text: what === "ack" ? "Record what you are doing about it. The note goes into the audit trail." : "Record how it was resolved.",
    input: { label: what === "ack" ? "Response note" : "Resolution", placeholder: "Optional" } });
  if (note === null) return;
  try { await api(`/api/alarms/${id}/${what}`, { body: { note } }); loadQueue(current === "monitor"); refreshBadges(); } catch (e) { fail(e); }
}
PAGES.alarms = async (el) => {
  el.innerHTML = head("Alarms", "Every alarm and how it was handled, active first and by priority") + `<div class="card"><div id="queue"></div></div>`;
  await loadQueue(false);
};

// ---------- activity ----------
PAGES.activity = async (el) => {
  const doors = await api("/api/doors");
  el.innerHTML = head("Activity", "Search and export the event history", `<button id="csv" class="btn">${icon("download")}Export CSV</button>`)
    + `<div class="card"><div class="card-head" style="justify-content:flex-start;gap:8px;flex-wrap:wrap">
      <select id="f-kind" style="width:190px"><option value="">All events</option><option value="access.*">Access decisions</option><option value="access.granted">Granted</option>
        <option value="access.denied">Denied</option><option value="door.*">Door status</option><option value="device.*">Devices</option><option value="alarm.*">Alarm handling</option>
        <option value="operator.*">Operator actions</option><option value="cardholder.*">Cardholder changes</option></select>
      <select id="f-door" style="width:180px"><option value="">All doors</option>${doors.map((d) => `<option value="${d.id}">${esc(d.name)}</option>`).join("")}</select>
      <input id="f-from" type="date" style="width:150px"><span class="muted">to</span><input id="f-to" type="date" style="width:150px"></div>
      <div id="act"></div><div class="card-body" style="border-top:1px solid var(--line)"><button id="more" class="btn sm">Load older</button></div></div>`;
  let oldest = null;
  const params = () => {
    const p = new URLSearchParams();
    if ($("#f-kind").value) p.set("kind", $("#f-kind").value);
    if ($("#f-door").value) p.set("door", $("#f-door").value);
    if ($("#f-from").value) p.set("since", new Date($("#f-from").value + "T00:00").getTime() / 1000);
    if ($("#f-to").value) p.set("until", new Date($("#f-to").value + "T23:59:59").getTime() / 1000);
    return p;
  };
  const load = async (reset) => {
    const p = params(); p.set("limit", 100);
    if (!reset && oldest) p.set("before", oldest);
    const evs = await api("/api/events?" + p);
    if (reset) $("#act").innerHTML = eventTable(evs, "act-body");
    else $("#act-body").insertAdjacentHTML("beforeend", evs.map((e) => eventRow(e)).join(""));
    if (evs.length) oldest = evs[evs.length - 1].seq;
    $("#more").classList.toggle("hidden", evs.length < 100);
  };
  $$("#f-kind, #f-door, #f-from, #f-to").forEach((i) => i.addEventListener("change", () => { oldest = null; load(true); }));
  $("#more").addEventListener("click", () => load(false));
  $("#csv").addEventListener("click", () => { location.href = "/api/events.csv?" + params(); });
  await load(true);
};

// ---------- cardholders ----------
const credIcons = (c) => `<div class="creds">
  <span class="cred ${c.has_pin ? "on" : ""}" title="PIN">${icon("key")}</span>
  <span class="cred ${c.has_card ? "on" : ""}" title="Card">${icon("nfc")}</span>
  <span class="cred ${c.faces ? "on" : ""}" title="Face">${icon("face-id")}</span>
  <span class="cred duress ${c.has_duress ? "on" : ""}" title="Duress PIN">${icon("alert-triangle")}</span></div>`;
PAGES.cardholders = async (el) => {
  el.innerHTML = head("Cardholders", "People, their credentials and where they can go",
    isAdmin() ? `<button id="add" class="btn primary">${icon("plus")}New cardholder</button>` : "")
    + `<div class="card"><div class="card-head" style="justify-content:flex-start"><input id="q" placeholder="Filter by name, department or email" style="max-width:340px"><span id="count" class="muted"></span></div>
      <div class="table-wrap"><table><thead><tr><th>Name</th><th>Department</th><th>Credentials</th><th>Access groups</th><th>Status</th><th>Last access</th></tr></thead><tbody id="rows"></tbody></table></div></div>`;
  const groups = await api("/api/groups");
  const gname = Object.fromEntries(groups.map((g) => [g.id, g.name]));
  const load = async () => {
    const list = await api("/api/cardholders?q=" + encodeURIComponent($("#q").value));
    $("#count").textContent = `${list.length} ${list.length === 1 ? "person" : "people"}`;
    $("#rows").innerHTML = list.map((c) => {
      const expired = c.valid_until && c.valid_until < Date.now() / 1000;
      return `<tr class="click" data-id="${c.id}">
      <td><div class="person"><span class="avatar">${initials(c.first_name + " " + c.last_name)}</span><div class="two"><b>${esc(c.first_name)} ${esc(c.last_name)}</b><small>${esc(c.email)}</small></div></div></td>
      <td>${esc(c.department) || `<span class="muted">—</span>`}</td><td>${credIcons(c)}</td>
      <td>${c.groups.map((g) => `<span class="badge">${esc(gname[g] || g)}</span>`).join(" ") || `<span class="muted">None</span>`}</td>
      <td>${!c.active ? `<span class="badge bad">Disabled</span>` : expired ? `<span class="badge warn">Expired</span>` : c.override ? `<span class="badge violet">Override</span>` : `<span class="badge ok">Active</span>`}</td>
      <td class="muted">${c.last_access ? ago(c.last_access.ts) : "Never"}</td></tr>`;
    }).join("") || `<tr><td colspan="6">${emptyState("users", "No cardholders", "Add the people who use your doors.")}</td></tr>`;
    $$("#rows tr.click").forEach((tr) => tr.addEventListener("click", () => cardholderPanel(Number(tr.dataset.id))));
  };
  $("#q").addEventListener("input", () => { clearTimeout(load.t); load.t = setTimeout(load, 180); });
  $("#add")?.addEventListener("click", () => cardholderPanel(null));
  await load();
};
const toDateInput = (ts) => ts ? new Date(ts * 1000).toISOString().slice(0, 10) : "";
const fromDateInput = (s, end) => s ? new Date(s + (end ? "T23:59:59" : "T00:00")).getTime() / 1000 : null;

async function cardholderPanel(id) {
  const [groups, doors] = await Promise.all([api("/api/groups"), api("/api/doors")]);
  const c = id ? (await api("/api/cardholders")).find((x) => x.id === id) : null;
  if (id && !c) return toast("That cardholder no longer exists", "bad");
  const name = c ? `${c.first_name} ${c.last_name}` : "New cardholder";
  const ro = !isAdmin();
  openPanel(panelShell({ avatar: `<span class="avatar lg">${c ? initials(name) : icon("user")}</span>`, title: esc(name),
    sub: c ? `${esc(c.department || "No department")} · added ${fmtDay(c.created)}` : "Fill in the details, then add credentials",
    tabs: c ? ["Profile", "Credentials", "Access", "Activity"] : ["Profile"] }), { cardholder: id });
  const content = () => $("#panel-content");
  const reload = async () => { closePanel(); if (current === "cardholders") await render(); if (id) cardholderPanel(id); };

  const profile = () => {
    content().innerHTML = `<form id="chf" class="stack">
      <div class="row2"><label class="field"><span>First name</span><input name="first_name" required value="${esc(c?.first_name)}"></label>
        <label class="field"><span>Last name</span><input name="last_name" value="${esc(c?.last_name)}"></label></div>
      <div class="row2"><label class="field"><span>Department</span><input name="department" value="${esc(c?.department)}"></label>
        <label class="field"><span>Email</span><input name="email" type="email" value="${esc(c?.email)}"></label></div>
      <div class="row2"><label class="field"><span>Valid from</span><input name="valid_from" type="date" value="${toDateInput(c?.valid_from)}"></label>
        <label class="field"><span>Valid until</span><input name="valid_until" type="date" value="${toDateInput(c?.valid_until)}"><small>Leave empty for no end date</small></label></div>
      ${c ? "" : `<label class="field"><span>PIN (4–6 digits)</span><input name="pin" inputmode="numeric" maxlength="6" autocomplete="off"><small>Stored only as a keyed hash; nobody can read it back</small></label>`}
      <div class="checks"><label class="chk"><input type="checkbox" name="active" ${!c || c.active ? "checked" : ""}>Active</label>
        <label class="chk"><input type="checkbox" name="override" ${c?.override ? "checked" : ""}>Lockdown override</label></div>
      <label class="field"><span>Notes</span><textarea name="notes" rows="3">${esc(c?.notes)}</textarea></label>
      ${ro ? "" : `<div class="actions" style="justify-content:space-between">${c ? `<button type="button" id="del" class="btn danger">${icon("trash")}Delete</button>` : "<span></span>"}<button class="btn primary">${c ? "Save changes" : "Create cardholder"}</button></div>`}</form>`;
    if (ro) $$("#chf input, #chf textarea").forEach((i) => (i.disabled = true));
    $("#chf").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      const body = { first_name: f.get("first_name"), last_name: f.get("last_name"), department: f.get("department"), email: f.get("email"),
        active: f.has("active"), override: f.has("override"), notes: f.get("notes"),
        valid_from: fromDateInput(f.get("valid_from"), false), valid_until: fromDateInput(f.get("valid_until"), true) };
      if (!c && f.get("pin")) body.pin = f.get("pin");
      try {
        const r = await api(c ? `/api/cardholders/${c.id}` : "/api/cardholders", { method: c ? "PATCH" : "POST", body });
        toast(c ? "Saved" : "Cardholder created"); closePanel(); if (current === "cardholders") await render(); cardholderPanel(r.id);
      } catch (err) { fail(err); }
    });
    $("#del")?.addEventListener("click", async () => {
      if (!await dialog({ title: `Delete ${name}?`, tone: "bad", ic: "trash", danger: true, confirm: "Delete", text: "Their credentials stop working immediately. Their history stays in the audit trail." })) return;
      await api(`/api/cardholders/${c.id}`, { method: "DELETE" }); closePanel(); render();
    });
  };

  const credentials = async () => {
    content().innerHTML = `
      <div class="cred-row"><span class="cred ${c.has_pin ? "on" : ""}">${icon("key")}</span><div class="grow"><b>PIN</b><small>${c.has_pin ? "Set" : "Not set"}</small></div>
        ${ro ? "" : `<button class="btn sm" data-c="pin">${c.has_pin ? "Change" : "Set PIN"}</button>`}</div>
      <div class="cred-row"><span class="cred duress ${c.has_duress ? "on" : ""}">${icon("alert-triangle")}</span><div class="grow"><b>Duress PIN</b><small>${c.has_duress ? "Set: opens the door and raises a silent critical alarm" : "Not set"}</small></div>
        ${ro ? "" : `<button class="btn sm" data-c="duress">${c.has_duress ? "Change" : "Set"}</button>${c.has_duress ? `<button class="btn sm ghost" data-c="duress-off">Remove</button>` : ""}`}</div>
      <div class="cred-row"><span class="cred ${c.has_card ? "on" : ""}">${icon("nfc")}</span><div class="grow"><b>Access card</b><small id="card-state">${c.has_card ? "Enrolled" : "No card"}</small></div>
        ${ro || !doors.length ? "" : `<select id="enrol-door" style="width:150px">${doors.map((d) => `<option value="${d.id}">${esc(d.name)}</option>`).join("")}</select>
        <button class="btn sm" data-c="card">${c.has_card ? "Replace" : "Enrol"}</button>${c.has_card ? `<button class="btn sm ghost" data-c="card-off">Remove</button>` : ""}`}</div>
      <div class="cred-row"><span class="cred ${c.faces ? "on" : ""}">${icon("face-id")}</span><div class="grow"><b>Face</b><small>${c.faces ? `${c.faces} template${c.faces > 1 ? "s" : ""} enrolled` : "Not enrolled"}</small></div>
        ${ro ? "" : `<label class="btn sm">${icon("photo", "sm")}Upload<input type="file" accept="image/jpeg,image/png" id="face-file" class="hidden"></label>${c.faces ? `<button class="btn sm ghost" data-c="face-off">Remove</button>` : ""}`}</div>
      ${ro ? "" : `<div class="section">Enrol a face from recent entry photos</div><div id="pick" class="pick"></div><p class="muted" style="font-size:12.5px;margin-top:8px">Pick a clear, front-facing photo. Two or three from different days improve matching.</p>`}`;
    if (!ro) {
      const photos = await api(`/api/cardholders/${c.id}/photos`);
      $("#pick").innerHTML = photos.length ? photos.map((p) => `<img src="/api/photos/${p.seq}.jpg" data-seq="${p.seq}" title="${fmtDate(p.ts)}" alt="">`).join("")
        : `<span class="muted">No entry photos of ${esc(c.first_name)} yet.</span>`;
      $$("#pick img").forEach((img) => img.addEventListener("click", async () => {
        try { const r = await api(`/api/cardholders/${c.id}/faces/from-event/${img.dataset.seq}`, { method: "POST" }); toast(`Face enrolled (${r.faces} template${r.faces > 1 ? "s" : ""})`); reload(); }
        catch (err) { fail(err); }
      }));
      $("#face-file")?.addEventListener("change", async (e) => {
        const file = e.target.files[0]; if (!file) return;
        try { await api(`/api/cardholders/${c.id}/faces`, { body: file, headers: { "Content-Type": file.type } }); toast("Face enrolled"); reload(); }
        catch (err) { fail(err); }
      });
    }
    $$("[data-c]").forEach((b) => b.addEventListener("click", async () => {
      const what = b.dataset.c;
      try {
        if (what === "pin" || what === "duress") {
          const v = await dialog({ title: what === "pin" ? "Set PIN" : "Set duress PIN", ic: "key", confirm: "Save",
            text: what === "pin" ? "4–6 digits. Simple patterns like 1111 or 1234 are refused." : "Must differ from the PIN. Using it opens the door normally and silently alerts security.",
            input: { label: "New PIN", placeholder: "4–6 digits" } });
          if (v === null) return;
          await api(`/api/cardholders/${c.id}`, { method: "PATCH", body: what === "pin" ? { pin: v } : { duress_pin: v } });
          toast("Saved"); reload();
        } else if (what === "duress-off") {
          await api(`/api/cardholders/${c.id}`, { method: "PATCH", body: { duress_pin: "" } }); reload();
        } else if (what === "card") {
          await api(`/api/cardholders/${c.id}/card/enrol`, { body: { door_id: Number($("#enrol-door").value) } });
          $("#card-state").innerHTML = `<span style="color:var(--accent-text)">Waiting: tap the card at ${esc($("#enrol-door").selectedOptions[0].text)} within 60 s</span>`;
        } else if (what === "card-off") {
          await api(`/api/cardholders/${c.id}/card`, { method: "DELETE" }); reload();
        } else if (what === "face-off") {
          await api(`/api/cardholders/${c.id}/faces`, { method: "DELETE" }); reload();
        }
      } catch (err) { fail(err); }
    }));
  };

  const access = () => {
    content().innerHTML = `<form id="acf" class="stack">
      <div class="field"><span>Access groups</span><div class="checks">${groups.map((g) => `<label class="chk"><input type="checkbox" name="groups" value="${g.id}" ${c.groups.includes(g.id) ? "checked" : ""}>${esc(g.name)}</label>`).join("") || `<span class="muted">No access groups yet</span>`}</div></div>
      <div class="section">Resulting access</div>
      <div class="card table-wrap"><table><thead><tr><th>Group</th><th>Doors</th><th>Schedule</th></tr></thead><tbody>
      ${groups.filter((g) => c.groups.includes(g.id)).map((g) => `<tr><td>${esc(g.name)}</td><td>${g.doors.map((d) => esc(doors.find((x) => x.id === d)?.name || d)).join(", ") || "—"}</td><td>${esc(g.schedule)}</td></tr>`).join("")
        || `<tr><td colspan="3" class="muted">No doors</td></tr>`}</tbody></table></div>
      ${ro ? "" : `<div class="actions" style="justify-content:flex-end"><button class="btn primary">Save access</button></div>`}</form>`;
    if (ro) $$("#acf input").forEach((i) => (i.disabled = true));
    $("#acf").addEventListener("submit", async (e) => {
      e.preventDefault();
      try { await api(`/api/cardholders/${c.id}`, { method: "PATCH", body: { groups: new FormData(e.target).getAll("groups").map(Number) } }); toast("Access updated"); reload(); }
      catch (err) { fail(err); }
    });
  };

  const activity = async () => {
    content().innerHTML = `<div class="card">${eventTable(await api(`/api/events?cardholder=${c.id}&limit=50`), "ch-act")}</div>`;
  };
  bindTabs((t) => [profile, credentials, access, activity][t]());
}

// ---------- access groups ----------
PAGES.groups = async (el) => {
  const [groups, schedules, doors] = await Promise.all([api("/api/groups"), api("/api/schedules"), api("/api/doors")]);
  const dname = Object.fromEntries(doors.map((d) => [d.id, d.name]));
  el.innerHTML = head("Access groups", "A group is a set of doors and the schedule they open on",
    isAdmin() ? `<button id="add" class="btn primary">${icon("plus")}New group</button>` : "")
    + `<div class="card"><div class="table-wrap"><table><thead><tr><th>Group</th><th>Doors</th><th>Schedule</th><th>Members</th></tr></thead><tbody>
    ${groups.map((g) => `<tr class="click" data-id="${g.id}"><td><b>${esc(g.name)}</b></td><td>${g.doors.map((d) => `<span class="badge">${icon("door")}${esc(dname[d] || d)}</span>`).join(" ") || `<span class="muted">None</span>`}</td>
      <td>${esc(g.schedule)}</td><td>${g.members}</td></tr>`).join("") || `<tr><td colspan="4">${emptyState("users-group", "No access groups", "Create one, then add doors and people to it.")}</td></tr>`}</tbody></table></div></div>`;
  const form = (g) => {
    if (!isAdmin()) return;
    openPanel(panelShell({ title: g ? esc(g.name) : "New access group", sub: g ? `${g.members} member${g.members === 1 ? "" : "s"}` : "" }));
    $("#panel-content").innerHTML = `<form id="gf" class="stack">
      <label class="field"><span>Name</span><input name="name" required value="${esc(g?.name)}"></label>
      <label class="field"><span>Schedule</span><select name="schedule_id">${schedules.map((s) => `<option value="${s.id}" ${g?.schedule_id === s.id ? "selected" : ""}>${esc(s.name)}</option>`).join("")}</select></label>
      <div class="field"><span>Doors</span><div class="checks">${doors.map((d) => `<label class="chk"><input type="checkbox" name="doors" value="${d.id}" ${g?.doors.includes(d.id) ? "checked" : ""}>${esc(d.name)}</label>`).join("") || `<span class="muted">No doors yet</span>`}</div></div>
      <div class="actions" style="justify-content:space-between">${g ? `<button type="button" id="del" class="btn danger">${icon("trash")}Delete</button>` : "<span></span>"}<button class="btn primary">Save</button></div></form>`;
    $("#gf").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      try { await api(g ? `/api/groups/${g.id}` : "/api/groups", { method: g ? "PUT" : "POST", body: { name: f.get("name"), schedule_id: Number(f.get("schedule_id")), doors: f.getAll("doors").map(Number) } }); closePanel(); render(); }
      catch (err) { fail(err); }
    });
    $("#del")?.addEventListener("click", async () => {
      if (await dialog({ title: `Delete ${g.name}?`, tone: "bad", ic: "trash", danger: true, confirm: "Delete", text: "Members lose the access this group gave them." })) {
        await api(`/api/groups/${g.id}`, { method: "DELETE" }); closePanel(); render();
      }
    });
  };
  $("#add")?.addEventListener("click", () => form(null));
  $$("tr.click", el).forEach((tr) => tr.addEventListener("click", () => form(groups.find((g) => g.id == tr.dataset.id))));
};

// ---------- schedules ----------
function weekGrid(windows) {
  const on = (day, hour) => windows.some((w) => {
    const m = hour * 60 + 30;
    if (w.start_min < w.end_min) return (w.days & (1 << day)) && m >= w.start_min && m < w.end_min;
    return ((w.days & (1 << day)) && m >= w.start_min) || ((w.days & (1 << ((day + 6) % 7))) && m < w.end_min);
  });
  return `<div class="week"><span></span>${Array.from({ length: 24 }, (_, h) => `<span>${h % 6 === 0 ? h : ""}</span>`).join("")}
    ${DAYS.map((d, i) => `<span>${d}</span>${Array.from({ length: 24 }, (_, h) => `<span class="cell ${on(i, h) ? "on" : ""}"></span>`).join("")}`).join("")}</div>`;
}
PAGES.schedules = async (el) => {
  const schedules = await api("/api/schedules");
  el.innerHTML = head("Schedules", "When access groups are allowed through, in site local time",
    isAdmin() ? `<button id="add" class="btn primary">${icon("plus")}New schedule</button>` : "")
    + `<div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(420px,1fr))">${schedules.map((s) => `<div class="card sched" data-id="${s.id}" style="cursor:pointer">
      <div class="card-head"><h2>${esc(s.name)}</h2><span class="muted">${s.windows.length} window${s.windows.length === 1 ? "" : "s"}</span></div>
      <div class="card-body">${weekGrid(s.windows)}</div></div>`).join("")}</div>`;
  const winRow = (w) => `<div class="card win" style="padding:12px;display:flex;flex-direction:column;gap:10px">
    <div class="checks">${DAYS.map((d, i) => `<label class="chk"><input type="checkbox" value="${i}" ${w.days & (1 << i) ? "checked" : ""}>${d}</label>`).join("")}</div>
    <div class="row3"><label class="field"><span>From</span><input type="time" class="ws" value="${hhmm(w.start_min)}"></label>
      <label class="field"><span>Until</span><input type="time" class="we" value="${hhmm(w.end_min % 1440)}"></label>
      <div class="field"><span>&nbsp;</span><button type="button" class="btn ghost rm">${icon("trash")}Remove</button></div></div></div>`;
  const form = (s) => {
    if (!isAdmin()) return;
    openPanel(panelShell({ title: s ? esc(s.name) : "New schedule", sub: "00:00 to 00:00 means all day; an end before the start runs past midnight" }));
    $("#panel-content").innerHTML = `<form id="sf" class="stack"><label class="field"><span>Name</span><input name="name" required value="${esc(s?.name)}"></label>
      <div id="wins" class="stack">${(s?.windows || [{ days: 31, start_min: 480, end_min: 1020 }]).map(winRow).join("")}</div>
      <button type="button" id="addw" class="btn">${icon("plus")}Add time window</button>
      <div class="actions" style="justify-content:space-between">${s ? `<button type="button" id="del" class="btn danger">${icon("trash")}Delete</button>` : "<span></span>"}<button class="btn primary">Save</button></div></form>`;
    const bindRm = () => $$(".rm").forEach((b) => (b.onclick = () => b.closest(".win").remove()));
    bindRm();
    $("#addw").addEventListener("click", () => { $("#wins").insertAdjacentHTML("beforeend", winRow({ days: 31, start_min: 480, end_min: 1020 })); bindRm(); });
    $("#sf").addEventListener("submit", async (e) => {
      e.preventDefault();
      const windows = $$(".win").map((w) => {
        const days = $$("input[type=checkbox]:checked", w).reduce((m, x) => m | (1 << Number(x.value)), 0);
        const a = parseHHMM($(".ws", w).value), b = parseHHMM($(".we", w).value);
        return { days, start_min: a, end_min: a === 0 && b === 0 ? 1440 : b };
      });
      try { await api(s ? `/api/schedules/${s.id}` : "/api/schedules", { method: s ? "PUT" : "POST", body: { name: new FormData(e.target).get("name"), windows } }); closePanel(); render(); }
      catch (err) { fail(err); }
    });
    $("#del")?.addEventListener("click", async () => { try { await api(`/api/schedules/${s.id}`, { method: "DELETE" }); closePanel(); render(); } catch (err) { fail(err); } });
  };
  $("#add")?.addEventListener("click", () => form(null));
  $$(".sched", el).forEach((c) => c.addEventListener("click", () => form(schedules.find((s) => s.id == c.dataset.id))));
};

// ---------- doors & devices ----------
PAGES.doors = async (el) => {
  const [doors, devices, groups] = await Promise.all([api("/api/doors"), api("/api/devices"), api("/api/groups")]);
  const waiting = devices.filter((d) => d.door_id == null);
  el.innerHTML = head("Doors & devices", "Keypads, their health and how each door accepts credentials",
    isAdmin() ? `<button id="add" class="btn">${icon("plus")}Door without device</button>` : "")
    + (waiting.length ? `<div class="callout">${icon("cpu", "lg")}<div class="grow"><b>${waiting.length} new device${waiting.length > 1 ? "s" : ""} waiting for adoption</b>
        <span class="muted">Adopting delivers the door key encrypted to the panel itself. You need the pairing code shown on its screen.</span></div></div>
      <div class="card" style="margin-bottom:16px"><div class="table-wrap"><table><thead><tr><th>Serial</th><th>MAC address</th><th>Firmware</th><th>Controller</th><th>First seen</th><th>Status</th><th></th></tr></thead><tbody>
      ${waiting.map((d) => `<tr><td class="mono"><b>${esc(d.serial)}</b></td><td class="mono">${esc(d.mac)}</td><td>${esc(d.firmware)}</td><td>${esc(d.controller)}</td><td class="muted">${ago(d.first_seen)}</td>
        <td>${d.online ? `<span class="badge ok"><span class="dot ok"></span>Online</span>` : `<span class="badge">Seen ${ago(d.last_seen)}</span>`}</td>
        <td style="text-align:right;white-space:nowrap">${isAdmin() ? `<button class="btn sm primary" data-adopt="${esc(d.serial)}">Adopt</button> <button class="btn sm ghost" data-forget="${esc(d.serial)}">Ignore</button>` : ""}</td></tr>`).join("")}
      </tbody></table></div></div>` : "")
    + `<div class="card"><div class="table-wrap"><table><thead><tr><th>Door</th><th>Status</th><th>Credentials</th><th>Device</th><th>Firmware</th><th>Last seen</th></tr></thead><tbody>
      ${doors.map((d) => `<tr class="click" data-id="${d.id}"><td><div class="person"><span class="door-ico">${icon("door")}</span><div class="two"><b>${esc(d.name)}</b><small>Door ${d.id}${d.area ? " · " + esc(d.area) : ""}</small></div></div></td>
        <td>${d.online ? `<span class="badge ok"><span class="dot ok"></span>Online</span>` : `<span class="badge bad"><span class="dot bad"></span>Offline</span>`}${d.rejects ? ` <span class="badge bad">${d.rejects} rejected</span>` : ""}</td>
        <td><span class="badge accent">${MODE_LABEL[d.credential_mode] || "PIN"}</span></td>
        <td class="mono">${d.serial ? esc(d.serial) : `<span class="muted">None</span>`}</td><td>${esc(d.firmware) || `<span class="muted">—</span>`}</td><td class="muted">${ago(d.last_seen)}</td></tr>`).join("")
      || `<tr><td colspan="6">${emptyState("door", "No doors yet", "Plug a keypad into a door controller and adopt it above.")}</td></tr>`}</tbody></table></div></div>`;
  $$("[data-adopt]").forEach((b) => b.addEventListener("click", () => adoptPanel(waiting.find((d) => d.serial === b.dataset.adopt), doors, groups)));
  $$("[data-forget]").forEach((b) => b.addEventListener("click", async () => {
    if (await dialog({ title: "Ignore this device?", text: "It is removed from the list and reappears if it announces itself again." })) { await api(`/api/devices/${b.dataset.forget}`, { method: "DELETE" }); render(); }
  }));
  $$("tr.click", el).forEach((tr) => tr.addEventListener("click", () => doorPanel(Number(tr.dataset.id))));
  $("#add")?.addEventListener("click", () => {
    openPanel(panelShell({ title: "Door without device", sub: "Create the door now and adopt a keypad into it later" }));
    const next = doors.length ? Math.max(...doors.map((x) => x.id)) + 1 : 1;
    $("#panel-content").innerHTML = `<form id="df" class="stack"><div class="row2"><label class="field"><span>Door number</span><input name="id" type="number" min="1" max="31" required value="${next}"></label>
      <label class="field"><span>Unlock time (ms)</span><input name="unlock_ms" type="number" min="1000" max="30000" step="500" value="5000"></label></div>
      <label class="field"><span>Name</span><input name="name" required placeholder="Server room"></label><label class="field"><span>Area</span><input name="area" placeholder="Level 2"></label>
      <div class="actions" style="justify-content:flex-end"><button class="btn primary">Create door</button></div></form>`;
    $("#df").addEventListener("submit", async (e) => {
      e.preventDefault(); const f = new FormData(e.target);
      try { await api("/api/doors", { body: { id: Number(f.get("id")), name: f.get("name"), area: f.get("area"), unlock_ms: Number(f.get("unlock_ms")) } }); closePanel(); render(); toast("Door created"); }
      catch (err) { fail(err); }
    });
  });
};

function adoptPanel(dev, doors, groups) {
  const free = doors.filter((d) => !d.serial);
  const next = doors.length ? Math.max(...doors.map((x) => x.id)) + 1 : 1;
  openPanel(panelShell({ avatar: `<span class="door-ico">${icon("cpu")}</span>`, title: `Adopt ${esc(dev.serial)}`, sub: `${esc(dev.mac)} · firmware ${esc(dev.firmware)} · via ${esc(dev.controller)}` }));
  $("#panel-content").innerHTML = `<form id="af" class="stack">
    <label class="field"><span>Pairing code on the panel's screen</span><input name="code" inputmode="numeric" maxlength="7" required autocomplete="off" placeholder="000 000" style="font-size:22px;height:48px;letter-spacing:.3em;text-align:center">
      <small>Proves you are adopting the panel in front of you, not one announced by someone else on the network.</small></label>
    <label class="field"><span>Assign to</span><select name="target"><option value="new">New door (#${next})</option>${free.map((d) => `<option value="${d.id}">${esc(d.name)} (door ${d.id})</option>`).join("")}</select></label>
    <div id="newdoor" class="row2"><label class="field"><span>Name</span><input name="name" placeholder="Main Entrance"></label><label class="field"><span>Area</span><input name="area" placeholder="Ground floor"></label></div>
    <div class="field"><span>Add to access groups</span><div class="checks">${groups.map((g) => `<label class="chk"><input type="checkbox" name="groups" value="${g.id}">${esc(g.name)}</label>`).join("") || `<span class="muted">None yet</span>`}</div></div>
    <div class="actions" style="justify-content:flex-end"><button class="btn primary">${icon("lock")}Adopt device</button></div></form>`;
  const sel = $("#af [name=target]");
  sel.addEventListener("change", () => $("#newdoor").classList.toggle("hidden", sel.value !== "new"));
  $("#af").addEventListener("submit", async (e) => {
    e.preventDefault(); const f = new FormData(e.target);
    const door_id = sel.value === "new" ? next : Number(sel.value);
    try {
      await api(`/api/devices/${dev.serial}/adopt`, { body: { pairing_code: f.get("code").replace(/\s/g, ""), door_id, name: f.get("name") || "", area: f.get("area") || "", groups: f.getAll("groups").map(Number) } });
      closePanel(); toast(`Adopted as door ${door_id}. The panel restarts with its key in a few seconds.`); render();
    } catch (err) { fail(err); }
  });
}

async function doorPanel(id) {
  const groups = await api("/api/groups");
  let d = await api(`/api/doors/${id}`);
  const ro = !isAdmin();
  openPanel(panelShell({ avatar: `<span class="door-ico" style="width:44px;height:44px">${icon("door", "lg")}</span>`, title: esc(d.name),
    sub: `Door ${d.id}${d.area ? " · " + esc(d.area) : ""} · ${d.online ? "Online" : "Offline"}`, tabs: ["Overview", "Settings", "Diagnostics", "Activity"] }),
    { door: id, tab: 0 });
  const content = () => $("#panel-content");
  const today = (k) => d.today[k] || 0;

  const overview = () => {
    content().innerHTML = `<div class="grid" style="grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:6px">
        <div class="card stat"><div><div class="label">Granted today</div><div class="value">${today("access.granted")}</div></div></div>
        <div class="card stat"><div><div class="label">Denied today</div><div class="value">${today("access.denied")}</div></div></div>
        <div class="card stat"><div><div class="label">Rejected frames</div><div class="value">${d.rejects}</div></div></div></div>
      <div class="section">Device</div>
      ${d.serial ? `<div class="kvs">${kv("Serial", `<span class="mono">${esc(d.serial)}</span>`)}${kv("MAC address", `<span class="mono">${esc(d.mac)}</span>`)}${kv("Firmware", esc(d.firmware))}${kv("Door controller", esc(d.controller))}${kv("Adopted", d.adopted_at ? fmtDate(d.adopted_at) : "—")}${kv("Last seen", ago(d.last_seen))}</div>`
        : emptyState("cpu", "No device", "Adopt a keypad into this door from Doors & devices.")}
      <div class="section">Access</div>
      <div class="kvs">${kv("Credentials accepted", MODE_LABEL[d.credential_mode] || "PIN")}${kv("Unlock time", `${d.unlock_ms / 1000} s`)}</div>
      <p class="muted" style="font-size:12.5px">${d.groups.length ? `Open to: ${d.groups.map((g) => `${esc(g.name)} (${esc(g.schedule)})`).join(", ")}` : "No access group includes this door yet."}</p>`;
  };
  const settings = () => {
    const inGroup = new Set(d.groups.map((g) => g.id));
    content().innerHTML = `<form id="dd" class="stack">
      <div class="row2"><label class="field"><span>Name</span><input name="name" value="${esc(d.name)}" required><small>Shown on the keypad</small></label><label class="field"><span>Area</span><input name="area" value="${esc(d.area)}"></label></div>
      <div class="row2"><label class="field"><span>Unlock time (ms)</span><input name="unlock_ms" type="number" min="1000" max="30000" step="500" value="${d.unlock_ms}"></label>
        <label class="field"><span>Credentials accepted</span><select name="credential_mode">${Object.entries(MODE_LABEL).map(([k, v]) => `<option value="${k}" ${d.credential_mode === k ? "selected" : ""}>${v}</option>`).join("")}</select>
        <small id="mode-hint">${MODE_HINT[d.credential_mode] || ""}</small></label></div>
      <div class="field"><span>Access groups using this door</span><div class="checks">${groups.map((g) => `<label class="chk"><input type="checkbox" name="groups" value="${g.id}" ${inGroup.has(g.id) ? "checked" : ""}>${esc(g.name)}</label>`).join("") || `<span class="muted">None</span>`}</div></div>
      ${ro ? "" : `<div class="actions" style="justify-content:flex-end"><button class="btn primary">Save changes</button></div>
      <div class="section">Maintenance</div>
      <div class="actions"><button type="button" class="btn" id="rekey">${icon("key")}Rotate door key</button>
        ${d.serial ? `<button type="button" class="btn" id="unassign">${icon("arrows-exchange")}Unassign device</button>` : ""}
        <button type="button" class="btn danger" id="remove">${icon("trash")}Remove door</button></div>
      <p class="muted" style="font-size:12.5px">Keys also rotate automatically on schedule. Unassigning returns the panel to “awaiting adoption” and voids its key.</p>`}</form>`;
    if (ro) $$("#dd input, #dd select").forEach((i) => (i.disabled = true));
    $("#dd [name=credential_mode]").addEventListener("change", (e) => ($("#mode-hint").textContent = MODE_HINT[e.target.value] || ""));
    $("#dd").addEventListener("submit", async (e) => {
      e.preventDefault(); const f = new FormData(e.target);
      try {
        await api(`/api/doors/${id}`, { method: "PATCH", body: { name: f.get("name"), area: f.get("area"), unlock_ms: Number(f.get("unlock_ms")), credential_mode: f.get("credential_mode"), groups: f.getAll("groups").map(Number) } });
        toast("Door saved; the keypad updates within 5 s"); d = await api(`/api/doors/${id}`);
      } catch (err) { fail(err); }
    });
    $("#rekey")?.addEventListener("click", async () => {
      if (!await dialog({ title: "Rotate this door's key?", ic: "key", text: "A new key is generated and delivered to the panel encrypted to its own key pair." })) return;
      try { const r = await api(`/api/doors/${id}/rekey`, { method: "POST" }); toast(r.auto ? "New key sent to the panel" : "Key rotated; provision the panel manually"); } catch (err) { fail(err); }
    });
    $("#unassign")?.addEventListener("click", async () => {
      if (!await dialog({ title: `Unassign ${d.serial}?`, tone: "warn", ic: "arrows-exchange", confirm: "Unassign", text: "The door keeps its settings. The panel forgets its key and shows its pairing code again." })) return;
      try { await api(`/api/doors/${id}/unassign`, { method: "POST" }); closePanel(); render(); } catch (err) { fail(err); }
    });
    $("#remove")?.addEventListener("click", async () => {
      if (d.serial) return toast("Unassign the device first", "bad");
      if (await dialog({ title: `Remove ${d.name}?`, tone: "bad", ic: "trash", danger: true, confirm: "Remove", text: "Its history stays in the audit trail." })) { await api(`/api/doors/${id}`, { method: "DELETE" }); closePanel(); render(); }
    });
  };
  const diagnostics = async () => {
    d = await api(`/api/doors/${id}`);
    const g = d.diag;
    const warn = (cond, text) => cond ? `<span style="color:var(--warn)">${text}</span>` : text;
    const shot = (k, title) => d.media[k] ? `<figure class="shot"><img src="/api/doors/${id}/media/${k}.jpg?${Date.now()}" data-cap="${title}" alt=""><figcaption>${title}</figcaption></figure>`
      : `<figure class="shot"><div class="empty" style="padding:30px 10px">${icon(k === "screenshot" ? "device-desktop" : "camera", "xl")}<b>No ${title.toLowerCase()} yet</b></div></figure>`;
    content().innerHTML = `${canOperate() ? `<div class="actions" style="margin-bottom:16px">
        <button class="btn" data-cmd="identify">${icon("broadcast")}Identify</button>
        <button class="btn" data-cmd="screenshot">${icon("device-desktop")}Screenshot</button>
        <button class="btn" data-cmd="test_photo">${icon("camera")}Test photo</button>
        ${isAdmin() ? `<button class="btn danger" data-cmd="reboot">${icon("power")}Reboot panel</button>` : ""}</div>` : ""}
      <div class="section">Health ${d.diag_ts && Date.now() / 1000 - d.diag_ts < 90 ? `<span class="badge ok" style="margin-left:6px">Live</span>` : ""}</div>
      ${g ? `<div class="kvs">${kv("Firmware", esc(g.firmware))}${kv("Uptime", fmtUptime(g.uptime_s))}
        ${kv("Last restart", warn(/crash|watchdog|brownout|glitch/.test(g.reset_reason), esc(g.reset_reason)))}${kv("Chip temperature", g.temp_c == null ? "—" : warn(g.temp_c > 75, `${g.temp_c} °C`))}
        ${kv("Internal RAM free", warn(g.heap_internal < 40000, `${fmtBytes(g.heap_internal)} <span class="muted">(lowest ${fmtBytes(g.heap_internal_min)})</span>`))}${kv("PSRAM free", fmtBytes(g.heap_psram))}
        ${kv("Camera", g.camera ? `<span style="color:var(--ok)">Streaming</span>` : `<span style="color:var(--bad)">Not running</span>`)}${kv("Card reader", g.reader ? `<span style="color:var(--ok)">OK</span>` : "Not fitted")}
        ${kv("Link errors", warn(g.link_errors > 0, g.link_errors))}${kv("Rejected frames", warn(g.rejected > 0, g.rejected))}
        ${kv("Last decision", g.last_decision_ms ? `${g.last_decision_ms} ms` : "—")}${kv("Reported", ago(d.diag_ts))}</div>`
        : emptyState("activity", "No health report yet", "Panels report every 30 seconds once linked.")}
      <div class="section">Latest captures</div><div class="shots">${shot("screenshot", "Panel screen")}${shot("test_photo", "Camera test")}</div>
      <p class="muted" style="font-size:12.5px;margin-top:10px">Commands are sealed with the door key and delivered on the panel's next check-in, within 5 seconds.</p>`;
    $$("[data-cmd]").forEach((b) => b.addEventListener("click", async () => {
      const cmd = b.dataset.cmd;
      if (cmd === "reboot" && !await dialog({ title: `Reboot the panel at ${d.name}?`, tone: "warn", ic: "power", confirm: "Reboot", text: "The door is unavailable for about 10 seconds. This is recorded against your account." })) return;
      try { await api(`/api/doors/${id}/command`, { body: { command: cmd } }); toast(`${b.textContent.trim()} sent`); } catch (err) { fail(err); }
    }));
  };
  const activity = async () => {
    content().innerHTML = `<div class="card">${eventTable(await api(`/api/events?door=${id}&limit=50`), "door-act")}</div>`;
  };
  const tabs = [overview, settings, diagnostics, activity];
  bindTabs((t) => { panelState.tab = t; panelState.refresh = t === 2 ? diagnostics : null; tabs[t](); });
}

// ---------- operators ----------
PAGES.operators = async (el) => {
  const ops = await api("/api/operators");
  el.innerHTML = head("Operators", "Viewers watch; operators also handle alarms and site mode; admins configure everything",
    `<button id="add" class="btn primary">${icon("plus")}New operator</button>`)
    + `<div class="card"><div class="table-wrap"><table><thead><tr><th>Operator</th><th>Role</th><th>Two-factor</th><th>Last sign-in</th><th>Created</th><th></th></tr></thead><tbody>
    ${ops.map((o) => `<tr><td><div class="person"><span class="avatar">${initials(o.username)}</span><b>${esc(o.username)}</b></div></td>
      <td><span class="badge ${o.role === "admin" ? "violet" : o.role === "operator" ? "accent" : ""}">${o.role}</span></td>
      <td>${o.mfa ? `<span class="badge ok">${icon("shield-check")}On</span>` : `<span class="badge warn">Off</span>`}</td>
      <td class="muted">${ago(o.last_login)}</td><td class="muted">${fmtDay(o.created)}</td>
      <td style="text-align:right">${o.username === ME.username ? `<span class="muted">You</span>` : `<button class="btn sm danger" data-del="${o.id}">Remove</button>`}</td></tr>`).join("")}</tbody></table></div></div>`;
  $("#add").addEventListener("click", () => {
    openPanel(panelShell({ title: "New operator", sub: "Ask them to turn on two-factor sign-in at first login" }));
    $("#panel-content").innerHTML = `<form id="of" class="stack"><label class="field"><span>Username</span><input name="username" required minlength="3" autocomplete="off"></label>
      <label class="field"><span>Temporary password</span><input name="password" type="password" required minlength="12" autocomplete="new-password"><small>At least 12 characters</small></label>
      <label class="field"><span>Role</span><select name="role"><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option></select></label>
      <div class="actions" style="justify-content:flex-end"><button class="btn primary">Create operator</button></div></form>`;
    $("#of").addEventListener("submit", async (e) => {
      e.preventDefault();
      try { await api("/api/operators", { body: Object.fromEntries(new FormData(e.target)) }); closePanel(); render(); } catch (err) { fail(err); }
    });
  });
  $$("[data-del]").forEach((b) => b.addEventListener("click", async () => {
    if (await dialog({ title: "Remove this operator?", tone: "bad", ic: "trash", danger: true, confirm: "Remove", text: "They are signed out and can no longer use the console." })) { await api(`/api/operators/${b.dataset.del}`, { method: "DELETE" }); render(); }
  }));
};

// ---------- settings ----------
PAGES.settings = async (el) => {
  const s = await api("/api/settings");
  const ro = !isAdmin();
  el.innerHTML = head("Settings", "Site-wide policy")
    + `<div class="grid" style="grid-template-columns:minmax(0,1fr) minmax(0,1fr);align-items:start">
      <div class="card"><div class="card-head"><h2>Site</h2></div><div class="card-body"><form id="sf" class="stack">
        <label class="field"><span>Site name</span><input name="site_name" value="${esc(s.site_name)}"></label>
        <label class="field"><span>Keep entry photos for (days)</span><input name="photo_retention_days" type="number" min="1" max="3650" value="${s.photo_retention_days}">
          <small>Photos are personal information. Older photos are deleted hourly; their hashes stay in the audit trail.</small></label>
        <label class="field"><span>Rotate door keys every (days)</span><input name="rekey_days" type="number" min="1" max="365" value="${s.rekey_days}">
          <small>New keys are delivered to adopted panels automatically.</small></label>
        <label class="chk" style="align-self:flex-start"><input type="checkbox" name="require_admin_mfa" ${s.require_admin_mfa ? "checked" : ""}>Require two-factor sign-in for admins</label>
        ${ro ? "" : `<div class="actions" style="justify-content:flex-end"><button class="btn primary">Save settings</button></div>`}</form></div></div>
      <div class="card"><div class="card-head"><h2>Trust</h2></div><div class="card-body stack">
        <div class="kvs">${kv("Server certificate (SHA-256)", s.tls_fingerprint ? `<span class="mono">${s.tls_fingerprint.match(/.{1,16}/g).join(" ")}</span>` : "HTTPS not active")}
          ${kv("Door controller token", `<span class="mono">${esc(s.controller_token_hint)}</span>`)}</div>
        <p class="muted" style="margin:0;font-size:12.5px">Door controllers pin this certificate and present the controller token on every call. Both are written to <span class="mono">controller.env</span> in the server's data folder for installing on a controller.</p>
      </div></div></div>`;
  if (ro) $$("#sf input").forEach((i) => (i.disabled = true));
  $("#sf").addEventListener("submit", async (e) => {
    e.preventDefault(); const f = new FormData(e.target);
    try {
      await api("/api/settings", { method: "PATCH", body: { site_name: f.get("site_name"), photo_retention_days: Number(f.get("photo_retention_days")), rekey_days: Number(f.get("rekey_days")), require_admin_mfa: f.has("require_admin_mfa") } });
      toast("Settings saved"); setSys();
    } catch (err) { fail(err); }
  });
};

// ---------- account security ----------
async function securityPanel(nudge = false) {
  ME = await api("/api/me");
  openPanel(panelShell({ avatar: `<span class="avatar lg">${initials(ME.username)}</span>`, title: esc(ME.username), sub: `${ME.role} · account security` }));
  const c = $("#panel-content");
  c.innerHTML = `${nudge ? `<div class="callout">${icon("shield-lock", "lg")}<div class="grow"><b>Two-factor sign-in is required for admins on this site</b><span class="muted">Set it up now to keep your access.</span></div></div>` : ""}
    <div class="section">Two-factor sign-in</div>
    <div class="cred-row"><span class="cred ${ME.mfa ? "on" : ""}">${icon("shield-check")}</span><div class="grow"><b>Authenticator app</b><small>${ME.mfa ? "On: a 6-digit code is required at every sign-in" : "Off"}</small></div>
      <button class="btn sm ${ME.mfa ? "" : "primary"}" id="mfa">${ME.mfa ? "Turn off" : "Set up"}</button></div>
    <div id="mfa-setup"></div>
    <div class="section">Password</div>
    <form id="pw" class="stack"><label class="field"><span>Current password</span><input name="current" type="password" required autocomplete="current-password"></label>
      <label class="field"><span>New password</span><input name="new" type="password" required minlength="12" autocomplete="new-password"><small>At least 12 characters. Other sessions are signed out.</small></label>
      <div class="actions" style="justify-content:flex-end"><button class="btn">Change password</button></div></form>`;
  $("#mfa").addEventListener("click", async () => {
    try {
      if (ME.mfa) {
        const code = await dialog({ title: "Turn off two-factor sign-in?", tone: "warn", ic: "shield-lock", confirm: "Turn off", text: "Enter a current code from your authenticator app.", input: { label: "Code", placeholder: "6 digits" } });
        if (code === null) return;
        await api("/api/me/mfa/disable", { body: { code } }); toast("Two-factor sign-in turned off"); return securityPanel();
      }
      const s = await api("/api/me/mfa/setup", { method: "POST" });
      $("#mfa-setup").innerHTML = `<div class="card card-body" style="margin-bottom:10px"><p style="margin:0 0 6px">Scan with Google Authenticator, Microsoft Authenticator, 1Password or similar, then enter the code it shows.</p>
        <div class="qr">${s.qr_svg}</div><p class="muted" style="font-size:12px;margin:0 0 12px">Or enter the key manually: <span class="mono">${esc(s.secret.match(/.{1,4}/g).join(" "))}</span></p>
        <form id="mfa-confirm" class="row2" style="align-items:end"><label class="field"><span>Code</span><input name="code" inputmode="numeric" maxlength="6" required></label><button class="btn primary">Turn on</button></form></div>`;
      $("#mfa-confirm").addEventListener("submit", async (e) => {
        e.preventDefault();
        try { await api("/api/me/mfa/confirm", { body: { code: new FormData(e.target).get("code") } }); toast("Two-factor sign-in is on"); securityPanel(); } catch (err) { fail(err); }
      });
    } catch (err) { fail(err); }
  });
  $("#pw").addEventListener("submit", async (e) => {
    e.preventDefault();
    try { await api("/api/me/password", { body: Object.fromEntries(new FormData(e.target)) }); toast("Password changed"); e.target.reset(); } catch (err) { fail(err); }
  });
}

// ---------- audit ----------
PAGES.audit = async (el) => {
  el.innerHTML = head("Audit trail", "Tamper-evident record of every decision, alarm, change and photo",
    `<button id="run" class="btn primary">${icon("shield-check")}Verify integrity</button>`)
    + `<div class="card" style="margin-bottom:16px"><div id="result" class="verify"><div class="big" style="background:var(--sunken)">${icon("shield-lock", "lg")}</div>
      <div><b>HMAC-SHA256 hash chain</b><div class="muted">Each record is chained to the one before it with a key the database does not hold. Any edit, deletion or reordering breaks the chain at that record.</div></div></div></div>
    <div class="card"><div class="card-head"><h2>Operator actions</h2></div><div id="ops"></div></div>`;
  $("#run").addEventListener("click", async () => {
    const v = await api("/api/journal/verify");
    $("#result").innerHTML = v.ok
      ? `<div class="big" style="background:var(--ok-soft);color:var(--ok)">${icon("circle-check", "lg")}</div><div><b>Chain intact</b><div class="muted">${v.checked} records verified · head <span class="mono">${v.head.slice(0, 24)}…</span></div></div>`
      : `<div class="big" style="background:var(--bad-soft);color:var(--bad)">${icon("circle-x", "lg")}</div><div><b>Chain broken at record #${v.broken_at}</b><div class="muted">${esc(v.why)} · ${v.checked} records before it verified</div></div>`;
  });
  $("#ops").innerHTML = eventTable(await api("/api/events?kind=operator.*&limit=50"), "ops-body");
};

// =====================================================================
// boot
// =====================================================================
async function boot() {
  try { ME = await api("/api/me"); } catch { return; }
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#user-name").textContent = ME.username;
  $("#avatar").textContent = initials(ME.username);
  $("#menu-user").textContent = ME.username;
  $("#menu-role").textContent = `${ME.role}${ME.mfa ? " · two-factor on" : ""}`;
  $$("[data-admin]").forEach((a) => a.classList.toggle("hidden", !isAdmin()));
  connectWs(); setSys(); refreshBadges(); render();
}
fetch("/api/me", { credentials: "same-origin" }).then((r) => (r.ok ? boot() : showLogin()));
