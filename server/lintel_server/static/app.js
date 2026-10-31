"use strict";

// ---------- helpers ----------
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MODES = ["Normal", "Lockdown", "Free access"];
let ME = null;
let DOORS = [];

async function api(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || (opts.body ? "POST" : "GET"),
    headers: opts.body ? { "Content-Type": "application/json" } : {},
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    credentials: "same-origin",
  });
  if (res.status === 401 && path !== "/api/login") { showLogin(); throw new Error("signed out"); }
  const data = res.headers.get("content-type")?.includes("json") ? await res.json() : null;
  if (!res.ok) {
    const msg = Array.isArray(data?.detail) ? data.detail.map((d) => d.msg).join("; ") : data?.detail || res.statusText;
    throw new Error(msg);
  }
  return data;
}

function toast(msg, bad = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (bad ? " bad" : "");
  clearTimeout(toast.t);
  toast.t = setTimeout(() => t.classList.add("hidden"), 3200);
}

const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const fmtDate = (ts) => new Date(ts * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "medium" });
const ago = (ts) => {
  if (!ts) return "never";
  const s = Date.now() / 1000 - ts;
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return fmtDate(ts);
};
const hhmm = (m) => `${String(Math.floor(m / 60)).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;
const parseHHMM = (s) => { const [h, m] = s.split(":").map(Number); return h * 60 + m; };
const daysText = (mask) => mask === 127 ? "Every day" : mask === 31 ? "Mon–Fri" : mask === 96 ? "Sat–Sun" : DAYS.filter((_, i) => mask & (1 << i)).join(", ");
const isAdmin = () => ME?.role === "admin";
const canOperate = () => ME && ME.role !== "viewer";

function eventStyle(e) {
  if (e.kind === "access.granted") return ["green", "&#10003;", "Access granted"];
  if (e.kind === "access.denied") return ["red", "&#10005;", "Access denied"];
  if (e.kind === "door.online") return ["green", "&#9679;", "Door online"];
  if (e.kind === "door.offline") return ["amber", "&#9675;", "Door offline"];
  if (e.kind === "link.rejected") return ["red", "&#9888;", "Rejected traffic"];
  if (e.kind === "site.mode") return ["violet", "&#9670;", "Site mode"];
  if (e.kind === "photo.attached") return ["blue", "&#9635;", "Entry photo"];
  if (e.kind.startsWith("alarm.")) return ["amber", "&#9888;", "Alarm " + e.kind.split(".")[1]];
  if (e.kind.startsWith("operator.")) return ["blue", "&#9786;", "Operator"];
  return ["blue", "&#8226;", e.kind];
}

function eventRow(e, fresh = false) {
  const [tone, icon, label] = eventStyle(e);
  const who = [e.cardholder_name, e.door_name].filter(Boolean).join(" · ");
  const thumb = e.photo
    ? `<img src="/api/photos/${e.seq}.jpg" data-seq="${e.seq}" data-cap="${esc(label + " — " + (who || "") + " — " + fmtDate(e.ts))}">`
    : `<span class="pill ${tone}" style="border:0;background:none">${icon}</span>`;
  return `<div class="ev${fresh ? " fresh" : ""}" data-seq="${e.seq}">
    <div class="ev-thumb">${thumb}</div>
    <div><div class="ev-title"><span class="pill ${tone}">${label}</span> ${esc(who)}</div>
      <div class="ev-sub">${esc(e.detail)}${e.operator ? ` · by ${esc(e.operator)}` : ""}</div></div>
    <div class="ev-time">${fmtTime(e.ts)}<br><span class="mono">#${e.seq}</span></div></div>`;
}

document.addEventListener("click", (ev) => {
  const img = ev.target.closest(".ev-thumb img, .shot img");
  if (img) {
    const lb = $("#lightbox");
    $("img", lb).src = img.src;
    $(".lightbox-cap", lb).textContent = img.dataset.cap || "";
    lb.classList.remove("hidden");
  } else if (ev.target.closest("#lightbox")) {
    $("#lightbox").classList.add("hidden");
  } else if (ev.target.id === "drawer") {
    closeDrawer();
  }
});

function openDrawer(html) { $("#drawer-body").innerHTML = html; $("#drawer").classList.remove("hidden"); }
function closeDrawer() { $("#drawer").classList.add("hidden"); openDoorId = null; }

// ---------- auth ----------
function showLogin() { $("#app").classList.add("hidden"); $("#login").classList.remove("hidden"); }

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    await api("/api/login", { body: { username: f.get("username"), password: f.get("password") } });
    $("#login-error").textContent = "";
    boot();
  } catch (err) { $("#login-error").textContent = err.message; }
});
$("#logout").addEventListener("click", async () => { await api("/api/logout", { method: "POST" }); location.reload(); });

// ---------- live updates ----------
let socket;
function connectWs() {
  socket = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
  socket.onopen = () => { $("#ws-dot").className = "dot green"; $("#ws-text").textContent = "live"; };
  socket.onclose = () => { $("#ws-dot").className = "dot amber"; $("#ws-text").textContent = "reconnecting"; setTimeout(connectWs, 2000); };
  socket.onmessage = (m) => onLive(JSON.parse(m.data));
}

function onLive(msg) {
  if (msg.type === "event") {
    const feed = $("#feed");
    if (feed) { $(".empty", feed)?.remove(); feed.insertAdjacentHTML("afterbegin", eventRow(msg.event, true)); }
    if (msg.event.kind.startsWith("access.")) refreshKpis();
  }
  if (msg.type === "photo") updatePhoto(msg.seq);
  if (msg.type === "alarm") {
    refreshAlarmBadge();
    if (msg.alarm.priority === 1) { toast("CRITICAL: " + msg.alarm.title, true); beep(); }
  }
  if (msg.type === "alarm" || msg.type === "alarms") { refreshAlarmBadge(); if ($("#alarm-list")) loadAlarms(); }
  if (msg.type === "doors" || msg.type === "devices") { refreshKpis(); if (current === "doors" && $("#drawer").classList.contains("hidden")) render(); }
  if (msg.type === "devices" && current !== "doors" && isAdmin()) api("/api/devices").then((ds) => { const n = ds.filter((d) => d.door_id == null).length; if (n) toast(`${n} unassigned device${n > 1 ? "s" : ""} waiting — see Doors`); });
  if (msg.type === "mode") setModeUi(msg.mode);
  if ((msg.type === "media" || msg.type === "diag") && openDoorId === msg.door) refreshDoorDiag(msg.door);
}

async function updatePhoto(seq) {
  const row = $(`.ev[data-seq="${seq}"] .ev-thumb`);
  if (row) row.innerHTML = `<img src="/api/photos/${seq}.jpg?${Date.now()}" data-cap="Entry photo #${seq}">`;
}

function beep() {
  try {
    const ctx = new AudioContext(), o = ctx.createOscillator(), g = ctx.createGain();
    o.frequency.value = 880; o.connect(g); g.connect(ctx.destination); g.gain.value = 0.08;
    o.start(); setTimeout(() => { o.frequency.value = 660; }, 180); setTimeout(() => o.stop(), 420);
  } catch { /* audio blocked */ }
}

async function refreshDoorDiag(id) {
  const d = await api(`/api/doors/${id}`);
  const shots = $("#shots");
  if (!shots) return;
  const tmp = document.createElement("div");
  tmp.innerHTML = diagSection(d);
  const kvs = tmp.querySelector(".kvs, .empty");
  const cur = shots.parentElement.querySelector(".section + .kvs, .section + .empty");
  if (kvs && cur) cur.replaceWith(kvs);
  shots.replaceWith(tmp.querySelector("#shots"));
}

// ---------- chrome ----------
function setModeUi(mode) {
  $$("#mode-switch button").forEach((b) => b.classList.toggle("on", Number(b.dataset.mode) === mode));
  $("#lockdown-strip").classList.toggle("hidden", mode !== 1);
  $("#free-strip").classList.toggle("hidden", mode !== 2);
}

$$("#mode-switch button").forEach((b) => b.addEventListener("click", async () => {
  const mode = Number(b.dataset.mode);
  if (!canOperate()) return toast("Viewer accounts cannot change the site mode", true);
  if (mode !== 0 && !confirm(`Switch the whole site to ${MODES[mode].toUpperCase()}?`)) return;
  try { await api("/api/mode", { body: { mode } }); setModeUi(mode); } catch (e) { toast(e.message, true); }
}));

async function refreshAlarmBadge() {
  const al = await api("/api/alarms");
  const active = al.filter((a) => a.state === "active").length;
  const b = $("#nav-alarms");
  b.textContent = active;
  b.classList.toggle("hidden", active === 0);
}

// ---------- pages ----------
let current = "monitor";
const PAGES = {};

async function render() {
  current = (location.hash || "#monitor").slice(1);
  if (!PAGES[current]) current = "monitor";
  $$("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.page === current));
  $("#page-title").textContent = $(`#nav a[data-page="${current}"]`).textContent.replace(/\d+$/, "").trim();
  try { await PAGES[current]($("#page")); } catch (e) { if (e.message !== "signed out") toast(e.message, true); }
}
window.addEventListener("hashchange", render);

async function refreshKpis() {
  if (current !== "monitor") return;
  const o = await api("/api/overview");
  DOORS = o.doors;
  const online = o.doors.filter((d) => d.online).length;
  const k = $("#kpis");
  if (!k) return;
  k.innerHTML = `
    <div class="card kpi"><div class="label">Doors online</div><div class="value">${online}<small> / ${o.doors.length}</small></div></div>
    <div class="card kpi"><div class="label">Active alarms</div><div class="value" style="color:${o.active_alarms ? "var(--red)" : "inherit"}">${o.active_alarms}</div></div>
    <div class="card kpi"><div class="label">Granted today</div><div class="value" style="color:var(--green)">${o.granted_today}</div></div>
    <div class="card kpi"><div class="label">Denied today</div><div class="value" style="color:${o.denied_today ? "var(--amber)" : "inherit"}">${o.denied_today}</div></div>`;
  $("#door-tiles").innerHTML = o.doors.length ? o.doors.map(doorTile).join("") : `<div class="empty">No doors yet. Add one under Doors.</div>`;
  setModeUi(o.mode);
}

function doorTile(d) {
  return `<div class="card door">
    <div class="door-top"><div class="door-name">${esc(d.name)}</div>
      <span class="pill ${d.online ? "green" : "red"}"><span class="dot ${d.online ? "green" : "red"}"></span>${d.online ? "Online" : "Offline"}</span></div>
    <div class="door-meta"><span>Door ${d.id}${d.area ? " · " + esc(d.area) : ""}</span><span>Seen ${ago(d.last_seen)}</span></div>
    <div class="door-meta"><span>${d.last_ip ? esc(d.last_ip) : "—"}</span><span>${d.rssi ? d.rssi + " dBm" : ""}</span>
      ${d.rejects ? `<span style="color:var(--red)">${d.rejects} rejected frames</span>` : ""}</div></div>`;
}

PAGES.monitor = async (el) => {
  el.innerHTML = `
    <div id="kpis" class="grid kpis"></div>
    <div class="grid two" style="margin-top:16px">
      <div class="card"><div class="card-head"><h2>Live activity</h2><span class="muted">newest first</span></div><div id="feed" class="feed"></div></div>
      <div class="grid" style="gap:16px">
        <div class="card"><div class="card-head"><h2>Open alarms</h2><a href="#alarms" class="btn small ghost">All alarms</a></div><div id="alarm-list"></div></div>
        <div class="card"><div class="card-head"><h2>Doors</h2></div><div class="card-body"><div id="door-tiles" class="grid doors"></div></div></div>
      </div>
    </div>`;
  await refreshKpis();
  const evs = await api("/api/events?limit=60");
  $("#feed").innerHTML = evs.length ? evs.map((e) => eventRow(e)).join("") : `<div class="empty">No activity yet</div>`;
  await loadAlarms(true);
};

async function loadAlarms(compact = false) {
  const list = $("#alarm-list");
  if (!list) return;
  const al = await api("/api/alarms" + (compact || current === "monitor" ? "" : "?state=all"));
  list.innerHTML = al.length ? al.slice(0, compact ? 6 : 200).map(alarmRow).join("") : `<div class="empty">No open alarms</div>`;
  $$("[data-ack]", list).forEach((b) => b.addEventListener("click", () => alarmAction(b.dataset.ack, "ack")));
  $$("[data-clear]", list).forEach((b) => b.addEventListener("click", () => alarmAction(b.dataset.clear, "clear")));
}

function alarmRow(a) {
  const st = a.state === "active" ? `<span class="pill red">Active</span>` : a.state === "acknowledged" ? `<span class="pill amber">Acknowledged</span>` : `<span class="pill">Cleared</span>`;
  const actions = !canOperate() || a.state === "cleared" ? "" :
    `${a.state === "active" ? `<button class="btn small" data-ack="${a.id}">Acknowledge</button>` : ""}<button class="btn small ghost" data-clear="${a.id}">Clear</button>`;
  return `<div class="alarm p${a.priority} ${a.state}"><div class="bar"></div>
    <div><div class="alarm-title">${esc(a.title)}</div>
      <div class="alarm-sub">P${a.priority} · ${fmtDate(a.ts)} ${st}${a.ack_by ? ` · ${esc(a.ack_by)}` : ""}${a.note ? ` · “${esc(a.note)}”` : ""}</div></div>
    <div class="alarm-actions">${actions}</div></div>`;
}

async function alarmAction(id, what) {
  const note = prompt(what === "ack" ? "Acknowledge — response note (optional):" : "Clear — resolution note (optional):") ?? null;
  if (note === null) return;
  try { await api(`/api/alarms/${id}/${what}`, { body: { note } }); await loadAlarms(current === "monitor"); refreshAlarmBadge(); }
  catch (e) { toast(e.message, true); }
}

PAGES.alarms = async (el) => {
  el.innerHTML = `<div class="card"><div class="card-head"><h2>Alarm history</h2><span class="muted">active first, by priority</span></div><div id="alarm-list"></div></div>`;
  await loadAlarms(false);
};

PAGES.events = async (el) => {
  const doorOpts = (await api("/api/doors")).map((d) => `<option value="${d.id}">${esc(d.name)}</option>`).join("");
  el.innerHTML = `
    <div class="toolbar">
      <select id="f-kind"><option value="">All events</option><option value="access.*">Access</option><option value="access.granted">Granted only</option>
        <option value="access.denied">Denied only</option><option value="door.*">Door status</option><option value="alarm.*">Alarm handling</option>
        <option value="operator.*">Operator actions</option><option value="cardholder.*">Cardholder changes</option><option value="photo.*">Photos</option></select>
      <select id="f-door"><option value="">All doors</option>${doorOpts}</select>
      <label class="muted">From <input id="f-from" type="date"></label><label class="muted">To <input id="f-to" type="date"></label>
      <span class="grow"></span><button id="f-csv" class="btn">Export CSV</button></div>
    <div class="card"><div id="feed" class="feed" style="max-height:none"></div><div class="card-body"><button id="more" class="btn small">Load more</button></div></div>`;
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
    if (reset) $("#feed").innerHTML = "";
    $("#feed").insertAdjacentHTML("beforeend", evs.map((e) => eventRow(e)).join("") || (reset ? `<div class="empty">No matching events</div>` : ""));
    if (evs.length) oldest = evs[evs.length - 1].seq;
    $("#more").classList.toggle("hidden", evs.length < 100);
  };
  $$("#f-kind, #f-door, #f-from, #f-to").forEach((i) => i.addEventListener("change", () => { oldest = null; load(true); }));
  $("#more").addEventListener("click", () => load(false));
  $("#f-csv").addEventListener("click", () => { location.href = "/api/events.csv?" + params(); });
  await load(true);
};

// --- cardholders
PAGES.cardholders = async (el) => {
  el.innerHTML = `<div class="toolbar"><input id="q" class="grow" placeholder="Search name, department or email">
    ${isAdmin() ? `<button id="add" class="btn primary">+ New cardholder</button>` : ""}</div>
    <div class="card"><table><thead><tr><th>Name</th><th>Department</th><th>Credentials</th><th>Access groups</th><th>Status</th><th>Last access</th></tr></thead><tbody id="rows"></tbody></table></div>`;
  const groups = await api("/api/groups");
  const gname = Object.fromEntries(groups.map((g) => [g.id, g.name]));
  const load = async () => {
    const list = await api("/api/cardholders?q=" + encodeURIComponent($("#q").value));
    $("#rows").innerHTML = list.map((c) => `<tr class="click" data-id="${c.id}">
      <td><b>${esc(c.first_name)} ${esc(c.last_name)}</b><div class="muted">${esc(c.email)}</div></td>
      <td>${esc(c.department)}</td>
      <td>${c.has_pin ? `<span class="pill blue">PIN</span>` : `<span class="pill">none</span>`} ${c.has_duress ? `<span class="pill violet">Duress</span>` : ""} ${c.override ? `<span class="pill amber">Override</span>` : ""}</td>
      <td>${c.groups.map((g) => `<span class="pill">${esc(gname[g] || g)}</span>`).join(" ") || `<span class="muted">none</span>`}</td>
      <td>${c.active ? `<span class="pill green">Active</span>` : `<span class="pill red">Disabled</span>`}</td>
      <td class="muted">${c.last_access ? ago(c.last_access.ts) : "never"}</td></tr>`).join("") || `<tr><td colspan="6" class="empty">No cardholders</td></tr>`;
    $$("#rows tr.click").forEach((tr) => tr.addEventListener("click", () => cardholderForm(list.find((c) => c.id == tr.dataset.id), groups, load)));
  };
  $("#q").addEventListener("input", () => { clearTimeout(load.t); load.t = setTimeout(load, 200); });
  $("#add")?.addEventListener("click", () => cardholderForm(null, groups, load));
  await load();
};

const toDateInput = (ts) => ts ? new Date(ts * 1000).toISOString().slice(0, 10) : "";
const fromDateInput = (s, end) => s ? new Date(s + (end ? "T23:59:59" : "T00:00")).getTime() / 1000 : null;

function cardholderForm(c, groups, reload) {
  const ro = !isAdmin();
  openDrawer(`<h2>${c ? esc(c.first_name + " " + c.last_name) : "New cardholder"}</h2>
    <form class="form" id="chf">
      <div class="row"><label>First name<input name="first_name" required value="${esc(c?.first_name)}"></label>
        <label>Last name<input name="last_name" value="${esc(c?.last_name)}"></label></div>
      <div class="row"><label>Department<input name="department" value="${esc(c?.department)}"></label>
        <label>Email<input name="email" type="email" value="${esc(c?.email)}"></label></div>
      <div class="row"><label>${c?.has_pin ? "New PIN (leave blank to keep)" : "PIN (4–6 digits)"}<input name="pin" inputmode="numeric" pattern="\\d{4,6}" autocomplete="off"></label>
        <label>${c?.has_duress ? "New duress PIN (blank keeps)" : "Duress PIN (optional)"}<input name="duress_pin" inputmode="numeric" pattern="\\d{4,6}" autocomplete="off"></label></div>
      <p class="hint">PINs are stored only as keyed hashes; nobody can read them back. A duress PIN opens the door normally but raises a silent critical alarm.</p>
      <label>Access groups<div class="checks">${groups.map((g) => `<label><input type="checkbox" name="groups" value="${g.id}" ${c?.groups.includes(g.id) ? "checked" : ""}>${esc(g.name)}</label>`).join("") || `<span class="hint">Create an access group first</span>`}</div></label>
      <div class="row"><label>Valid from<input name="valid_from" type="date" value="${toDateInput(c?.valid_from)}"></label>
        <label>Valid until<input name="valid_until" type="date" value="${toDateInput(c?.valid_until)}"></label></div>
      <div class="checks"><label><input type="checkbox" name="active" ${!c || c.active ? "checked" : ""}>Active</label>
        <label><input type="checkbox" name="override" ${c?.override ? "checked" : ""}>Lockdown override (security staff)</label></div>
      <label>Notes<textarea name="notes" rows="3">${esc(c?.notes)}</textarea></label>
      <div class="form-actions">${c && !ro ? `<button type="button" id="del" class="btn danger">Delete</button>` : "<span></span>"}
        <div><button type="button" class="btn ghost" onclick="closeDrawer()">Cancel</button> ${ro ? "" : `<button class="btn primary">Save</button>`}</div></div>
    </form>`);
  if (ro) $$("#chf input, #chf textarea").forEach((i) => (i.disabled = true));
  $("#chf").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const body = {
      first_name: f.get("first_name"), last_name: f.get("last_name"), department: f.get("department"), email: f.get("email"),
      groups: f.getAll("groups").map(Number), active: f.has("active"), override: f.has("override"), notes: f.get("notes"),
      valid_from: fromDateInput(f.get("valid_from"), false), valid_until: fromDateInput(f.get("valid_until"), true),
    };
    if (f.get("pin")) body.pin = f.get("pin");
    if (f.get("duress_pin")) body.duress_pin = f.get("duress_pin");
    try {
      await api(c ? `/api/cardholders/${c.id}` : "/api/cardholders", { method: c ? "PATCH" : "POST", body });
      closeDrawer(); toast("Cardholder saved"); reload();
    } catch (err) { toast(err.message, true); }
  });
  $("#del")?.addEventListener("click", async () => {
    if (!confirm(`Delete ${c.first_name} ${c.last_name}? Their history stays in the journal.`)) return;
    await api(`/api/cardholders/${c.id}`, { method: "DELETE" }); closeDrawer(); reload();
  });
}

// --- access groups
PAGES.groups = async (el) => {
  const [groups, schedules, doors] = await Promise.all([api("/api/groups"), api("/api/schedules"), api("/api/doors")]);
  const dname = Object.fromEntries(doors.map((d) => [d.id, d.name]));
  el.innerHTML = `<div class="toolbar"><span class="grow muted">An access group is a set of doors plus the schedule they open on.</span>
    ${isAdmin() ? `<button id="add" class="btn primary">+ New access group</button>` : ""}</div>
    <div class="card"><table><thead><tr><th>Group</th><th>Doors</th><th>Schedule</th><th>Members</th></tr></thead><tbody>
    ${groups.map((g) => `<tr class="click" data-id="${g.id}"><td><b>${esc(g.name)}</b></td><td>${g.doors.map((d) => `<span class="pill">${esc(dname[d] || d)}</span>`).join(" ") || `<span class="muted">none</span>`}</td>
      <td>${esc(g.schedule)}</td><td>${g.members}</td></tr>`).join("") || `<tr><td colspan="4" class="empty">No access groups</td></tr>`}</tbody></table></div>`;
  const form = (g) => {
    if (!isAdmin()) return;
    openDrawer(`<h2>${g ? esc(g.name) : "New access group"}</h2><form class="form" id="gf">
      <label>Name<input name="name" required value="${esc(g?.name)}"></label>
      <label>Schedule<select name="schedule_id">${schedules.map((s) => `<option value="${s.id}" ${g?.schedule_id === s.id ? "selected" : ""}>${esc(s.name)}</option>`).join("")}</select></label>
      <label>Doors<div class="checks">${doors.map((d) => `<label><input type="checkbox" name="doors" value="${d.id}" ${g?.doors.includes(d.id) ? "checked" : ""}>${esc(d.name)}</label>`).join("") || `<span class="hint">No doors yet</span>`}</div></label>
      <div class="form-actions">${g ? `<button type="button" id="del" class="btn danger">Delete</button>` : "<span></span>"}<div><button type="button" class="btn ghost" onclick="closeDrawer()">Cancel</button> <button class="btn primary">Save</button></div></div></form>`);
    $("#gf").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      const body = { name: f.get("name"), schedule_id: Number(f.get("schedule_id")), doors: f.getAll("doors").map(Number) };
      try { await api(g ? `/api/groups/${g.id}` : "/api/groups", { method: g ? "PUT" : "POST", body }); closeDrawer(); render(); }
      catch (err) { toast(err.message, true); }
    });
    $("#del")?.addEventListener("click", async () => { if (confirm("Delete this access group?")) { await api(`/api/groups/${g.id}`, { method: "DELETE" }); closeDrawer(); render(); } });
  };
  $("#add")?.addEventListener("click", () => form(null));
  $$("tr.click", el).forEach((tr) => tr.addEventListener("click", () => form(groups.find((g) => g.id == tr.dataset.id))));
};

// --- schedules
PAGES.schedules = async (el) => {
  const schedules = await api("/api/schedules");
  el.innerHTML = `<div class="toolbar"><span class="grow muted">Time windows in site local time. A window ending before it starts runs past midnight.</span>
    ${isAdmin() ? `<button id="add" class="btn primary">+ New schedule</button>` : ""}</div>
    <div class="card"><table><thead><tr><th>Schedule</th><th>Windows</th></tr></thead><tbody>
    ${schedules.map((s) => `<tr class="click" data-id="${s.id}"><td><b>${esc(s.name)}</b></td><td>${s.windows.map((w) => `<span class="pill">${daysText(w.days)} ${hhmm(w.start_min)}–${hhmm(w.end_min === 1440 ? 1440 : w.end_min)}</span>`).join(" ")}</td></tr>`).join("")}</tbody></table></div>`;
  const winRow = (w) => `<div class="win card" style="padding:12px;display:flex;flex-direction:column;gap:10px">
    <div class="checks">${DAYS.map((d, i) => `<label><input type="checkbox" value="${i}" ${w.days & (1 << i) ? "checked" : ""}>${d}</label>`).join("")}</div>
    <div class="row"><label>From<input type="time" class="ws" value="${hhmm(w.start_min)}"></label><label>Until<input type="time" class="we" value="${hhmm(w.end_min % 1440)}"></label></div>
    <button type="button" class="btn small ghost rm">Remove window</button></div>`;
  const form = (s) => {
    if (!isAdmin()) return;
    openDrawer(`<h2>${s ? esc(s.name) : "New schedule"}</h2><form class="form" id="sf">
      <label>Name<input name="name" required value="${esc(s?.name)}"></label>
      <div id="wins">${(s?.windows || [{ days: 31, start_min: 480, end_min: 1020 }]).map(winRow).join("")}</div>
      <button type="button" id="addw" class="btn small">+ Add window</button>
      <p class="hint">00:00 → 00:00 means all day.</p>
      <div class="form-actions">${s ? `<button type="button" id="del" class="btn danger">Delete</button>` : "<span></span>"}<div><button type="button" class="btn ghost" onclick="closeDrawer()">Cancel</button> <button class="btn primary">Save</button></div></div></form>`);
    const bindRm = () => $$(".rm").forEach((b) => (b.onclick = () => b.closest(".win").remove()));
    bindRm();
    $("#addw").onclick = () => { $("#wins").insertAdjacentHTML("beforeend", winRow({ days: 31, start_min: 480, end_min: 1020 })); bindRm(); };
    $("#sf").addEventListener("submit", async (e) => {
      e.preventDefault();
      const windows = $$(".win").map((w) => {
        const days = $$("input[type=checkbox]:checked", w).reduce((m, c) => m | (1 << Number(c.value)), 0);
        const start = parseHHMM($(".ws", w).value), end = parseHHMM($(".we", w).value);
        return { days, start_min: start, end_min: start === 0 && end === 0 ? 1440 : end };
      });
      try { await api(s ? `/api/schedules/${s.id}` : "/api/schedules", { method: s ? "PUT" : "POST", body: { name: new FormData(e.target).get("name"), windows } }); closeDrawer(); render(); }
      catch (err) { toast(err.message, true); }
    });
    $("#del")?.addEventListener("click", async () => { try { await api(`/api/schedules/${s.id}`, { method: "DELETE" }); closeDrawer(); render(); } catch (err) { toast(err.message, true); } });
  };
  $("#add")?.addEventListener("click", () => form(null));
  $$("tr.click", el).forEach((tr) => tr.addEventListener("click", () => form(schedules.find((s) => s.id == tr.dataset.id))));
};

// --- doors & devices
const MODE_LABEL = { pin: "PIN only", card: "Card only", card_or_pin: "Card or PIN", card_and_pin: "Card + PIN",
  face: "Face only (convenience)", face_and_pin: "Face + PIN" };

const fmtBytes = (n) => n == null ? "—" : n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.round(n / 1024)} KB`;
const fmtUptime = (s) => { if (s == null) return "—"; const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m ${s % 60}s`; };

function diagSection(d) {
  const g = d.diag;
  const fresh = d.diag_ts && Date.now() / 1000 - d.diag_ts < 90;
  const warn = (cond, text) => cond ? `<span style="color:var(--amber)">${text}</span>` : text;
  const health = g ? `<div class="kvs">
      ${kv("Firmware", esc(g.firmware))}${kv("Uptime", fmtUptime(g.uptime_s))}
      ${kv("Last restart", warn(/crash|watchdog|brownout|glitch/.test(g.reset_reason), esc(g.reset_reason)))}
      ${kv("Chip temperature", g.temp_c == null ? "—" : warn(g.temp_c > 75, `${g.temp_c} °C`))}
      ${kv("Internal RAM free", warn(g.heap_internal < 40000, `${fmtBytes(g.heap_internal)} <span class="muted">(low ${fmtBytes(g.heap_internal_min)})</span>`))}
      ${kv("PSRAM free", fmtBytes(g.heap_psram))}
      ${kv("Camera", g.camera ? `<span style="color:var(--green)">Streaming</span>` : `<span style="color:var(--red)">Not running</span>`)}
      ${kv("Card reader", g.reader ? `<span style="color:var(--green)">OK</span>` : "Not fitted")}
      ${kv("Link errors", warn(g.link_errors > 0, g.link_errors))}${kv("Rejected frames", warn(g.rejected > 0, g.rejected))}
      ${kv("Last decision", g.last_decision_ms ? `${g.last_decision_ms} ms` : "—")}
      ${kv("Reported", d.diag_ts ? ago(d.diag_ts) : "—")}</div>`
    : `<div class="empty" style="padding:16px">No health report yet. Panels report every 30 seconds once linked.</div>`;
  const shot = (k, title) => d.media[k]
    ? `<figure class="shot"><img src="/api/doors/${d.id}/media/${k}.jpg?${Date.now()}" data-cap="${title}"><figcaption>${title}</figcaption></figure>` : "";
  return `<h3 class="section">Diagnostics ${fresh ? `<span class="pill green" style="margin-left:6px">live</span>` : ""}</h3>
    ${health}
    ${canOperate() ? `<div class="checks" style="margin-top:12px">
      <button class="btn" data-cmd="identify">Identify</button>
      <button class="btn" data-cmd="screenshot">Screenshot</button>
      <button class="btn" data-cmd="test_photo">Test photo</button>
      ${isAdmin() ? `<button class="btn danger" data-cmd="reboot">Reboot panel</button>` : ""}</div>
      <p class="hint">Commands are sealed with the door key and delivered on the panel's next check-in (within 5 s).</p>` : ""}
    <div class="shots" id="shots">${shot("screenshot", "Panel screen")}${shot("test_photo", "Camera test")}</div>`;
}

function kv(label, value, mono = false) {
  return `<div class="kv"><span>${label}</span><b class="${mono ? "mono" : ""}">${value ?? "—"}</b></div>`;
}

function provisionPanel(r, name) {
  openDrawer(`<h2>Manual provisioning — ${esc(name)}</h2>
    <p class="muted">This door has no adopted device, so the key is shown once for manual setup on the panel's USB console.
    Panels connected through a door controller are adopted instead and never need this.</p>
    <div class="secret mono">prov ${r.id} ${r.net_id} ${r.key}</div>
    <div class="form-actions"><span></span><button class="btn primary" onclick="closeDrawer()">Done</button></div>`);
}

PAGES.doors = async (el) => {
  const [doors, devices, groups] = await Promise.all([api("/api/doors"), api("/api/devices"), api("/api/groups")]);
  const unassigned = devices.filter((d) => d.door_id == null);
  el.innerHTML = `
    <div class="card" style="margin-bottom:18px">
      <div class="card-head"><h2>Unassigned devices</h2><span class="muted">panels announced by door controllers, waiting to be adopted</span></div>
      ${unassigned.length ? `<table><thead><tr><th>Serial</th><th>MAC</th><th>Firmware</th><th>Controller</th><th>First seen</th><th>Status</th><th></th></tr></thead><tbody>
        ${unassigned.map((d) => `<tr><td class="mono"><b>${esc(d.serial)}</b></td><td class="mono">${esc(d.mac)}</td><td>${esc(d.firmware)}</td>
          <td>${esc(d.controller)}</td><td class="muted">${ago(d.first_seen)}</td>
          <td>${d.online ? `<span class="pill green"><span class="dot green"></span>Online</span>` : `<span class="pill">Last seen ${ago(d.last_seen)}</span>`}</td>
          <td style="text-align:right">${isAdmin() ? `<button class="btn primary small" data-adopt="${esc(d.serial)}">Adopt</button> <button class="btn small ghost" data-forget="${esc(d.serial)}">Ignore</button>` : ""}</td></tr>`).join("")}
        </tbody></table>` : `<div class="empty">No unassigned devices. Plug a new keypad into a door controller and it appears here within seconds.</div>`}
    </div>
    <div class="toolbar"><span class="grow muted">Each door has its own AES-128 key, delivered to its panel sealed to the panel's own X25519 key.</span>
      ${isAdmin() ? `<button id="add" class="btn">+ Door without device</button>` : ""}</div>
    <div class="grid doors">${doors.map((d) => `<div class="card door click-card" data-door="${d.id}">
      <div class="door-top"><div class="door-name">${esc(d.name)}</div>
        <span class="pill ${d.online ? "green" : "red"}"><span class="dot ${d.online ? "green" : "red"}"></span>${d.online ? "Online" : "Offline"}</span></div>
      <div class="door-meta"><span>Door ${d.id}${d.area ? " · " + esc(d.area) : ""}</span><span>${MODE_LABEL[d.credential_mode] || "PIN only"}</span></div>
      <div class="door-meta"><span class="mono">${d.serial ? esc(d.serial) : "no device"}</span><span>Seen ${ago(d.last_seen)}</span></div>
      ${d.rejects ? `<div class="door-meta" style="color:var(--red)">${d.rejects} rejected frames</div>` : ""}</div>`).join("") || `<div class="empty">No doors yet — adopt a device above.</div>`}</div>`;

  $$("[data-adopt]").forEach((b) => b.addEventListener("click", () => adoptForm(unassigned.find((d) => d.serial === b.dataset.adopt), doors, groups)));
  $$("[data-forget]").forEach((b) => b.addEventListener("click", async () => {
    if (confirm("Ignore this device? It reappears if it announces again.")) { await api(`/api/devices/${b.dataset.forget}`, { method: "DELETE" }); render(); }
  }));
  $$("[data-door]").forEach((c) => c.addEventListener("click", () => doorDetail(Number(c.dataset.door), groups)));
  $("#add")?.addEventListener("click", () => {
    openDrawer(`<h2>Door without device</h2><p class="muted">Create the door now and adopt a panel into it later, or provision a panel by hand.</p>
      <form class="form" id="df">
      <div class="row"><label>Door number (1–31)<input name="id" type="number" min="1" max="31" required value="${doors.length ? Math.max(...doors.map((x) => x.id)) + 1 : 1}"></label>
        <label>Unlock time (ms)<input name="unlock_ms" type="number" min="1000" max="30000" step="500" value="5000"></label></div>
      <label>Name<input name="name" required placeholder="Server room"></label>
      <label>Area / zone<input name="area" placeholder="Level 2"></label>
      <div class="form-actions"><span></span><div><button type="button" class="btn ghost" onclick="closeDrawer()">Cancel</button> <button class="btn primary">Create</button></div></div></form>`);
    $("#df").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      try {
        const r = await api("/api/doors", { body: { id: Number(f.get("id")), name: f.get("name"), area: f.get("area"), unlock_ms: Number(f.get("unlock_ms")) } });
        provisionPanel(r, f.get("name")); render();
      } catch (err) { toast(err.message, true); }
    });
  });
};

function adoptForm(dev, doors, groups) {
  const free = doors.filter((d) => !d.serial);
  const next = doors.length ? Math.max(...doors.map((x) => x.id)) + 1 : 1;
  openDrawer(`<h2>Adopt ${esc(dev.serial)}</h2>
    <div class="kvs">${kv("MAC", esc(dev.mac), true)}${kv("Firmware", esc(dev.firmware))}${kv("Controller", esc(dev.controller))}${kv("First seen", fmtDate(dev.first_seen))}</div>
    <form class="form" id="af" style="margin-top:16px">
      <label>Pairing code shown on the panel's screen<input name="code" inputmode="numeric" pattern="\\d{3} ?\\d{3}" maxlength="7" required autocomplete="off" placeholder="123 456" style="font-size:22px;letter-spacing:6px"></label>
      <p class="hint">The code proves you are adopting the device in front of you, not one announced by someone else on the network.</p>
      <label>Assign to<select name="target">
        <option value="new">New door #${next}</option>
        ${free.map((d) => `<option value="${d.id}">Existing: ${esc(d.name)} (door ${d.id})</option>`).join("")}</select></label>
      <div id="newdoor" class="form">
        <div class="row"><label>Name<input name="name" placeholder="Main Entrance"></label><label>Area / zone<input name="area" placeholder="Ground floor"></label></div>
        <label>Unlock time (ms)<input name="unlock_ms" type="number" min="1000" max="30000" step="500" value="5000"></label>
      </div>
      <label>Add to access groups<div class="checks">${groups.map((g) => `<label><input type="checkbox" name="groups" value="${g.id}">${esc(g.name)}</label>`).join("") || `<span class="hint">No access groups yet</span>`}</div></label>
      <div class="form-actions"><span></span><div><button type="button" class="btn ghost" onclick="closeDrawer()">Cancel</button> <button class="btn primary">Adopt device</button></div></div>
    </form>`);
  const sel = $("#af select[name=target]");
  sel.addEventListener("change", () => $("#newdoor").classList.toggle("hidden", sel.value !== "new"));
  $("#af").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const body = {
      pairing_code: f.get("code").replace(/\s/g, ""),
      door_id: sel.value === "new" ? next : Number(sel.value),
      name: f.get("name") || "", area: f.get("area") || "", unlock_ms: Number(f.get("unlock_ms") || 5000),
      groups: f.getAll("groups").map(Number),
    };
    try {
      await api(`/api/devices/${dev.serial}/adopt`, { body });
      closeDrawer(); toast(`Adopted as door ${body.door_id}. The panel restarts with its key in a few seconds.`); render();
    } catch (err) { toast(err.message, true); }
  });
}

let openDoorId = null;

async function doorDetail(id, groups) {
  const d = await api(`/api/doors/${id}`);
  const ro = !isAdmin();
  const inGroup = new Set(d.groups.map((g) => g.id));
  const today = (k) => d.today[k] || 0;
  openDrawer(`
    <div class="detail-head"><div><h2 style="margin:0">${esc(d.name)}</h2><div class="muted">Door ${d.id}${d.area ? " · " + esc(d.area) : ""}</div></div>
      <span class="pill ${d.online ? "green" : "red"}"><span class="dot ${d.online ? "green" : "red"}"></span>${d.online ? "Online" : "Offline"}</span></div>

    <div class="stats3"><div><b style="color:var(--green)">${today("access.granted")}</b><span>granted today</span></div>
      <div><b style="color:${today("access.denied") ? "var(--amber)" : "inherit"}">${today("access.denied")}</b><span>denied today</span></div>
      <div><b style="color:${d.rejects ? "var(--red)" : "inherit"}">${d.rejects}</b><span>rejected frames</span></div></div>

    <h3 class="section">Device</h3>
    ${d.serial ? `<div class="kvs">${kv("Serial", esc(d.serial), true)}${kv("MAC", esc(d.mac), true)}${kv("Firmware", esc(d.firmware))}
      ${kv("Door controller", esc(d.controller))}${kv("Adopted", d.adopted_at ? fmtDate(d.adopted_at) : "—")}${kv("Last seen", ago(d.last_seen))}</div>`
      : `<div class="empty" style="padding:16px">No device adopted to this door. Adopt one from Unassigned devices.</div>`}

    ${diagSection(d)}

    <h3 class="section">Settings</h3>
    <form class="form" id="dd">
      <div class="row"><label>Name<input name="name" value="${esc(d.name)}" required></label><label>Area / zone<input name="area" value="${esc(d.area)}"></label></div>
      <div class="row"><label>Unlock time (ms)<input name="unlock_ms" type="number" min="1000" max="30000" step="500" value="${d.unlock_ms}"></label>
        <label>Credentials accepted<select name="credential_mode">${Object.entries(MODE_LABEL).map(([k, v]) => `<option value="${k}" ${d.credential_mode === k ? "selected" : ""}>${v}</option>`).join("")}</select></label></div>
      <label>Access groups using this door<div class="checks">${groups.map((g) => `<label><input type="checkbox" name="groups" value="${g.id}" ${inGroup.has(g.id) ? "checked" : ""}>${esc(g.name)}</label>`).join("") || `<span class="hint">No access groups</span>`}</div></label>
      ${ro ? "" : `<div class="form-actions"><span></span><button class="btn primary">Save changes</button></div>`}
    </form>

    <h3 class="section">Recent activity</h3>
    <div class="card" style="margin-bottom:18px">${d.recent.length ? d.recent.map((e) => eventRow(e)).join("") : `<div class="empty">No activity yet</div>`}</div>

    ${ro ? "" : `<h3 class="section">Maintenance</h3><div class="checks">
      <button class="btn" id="rekey">Rotate door key</button>
      ${d.serial ? `<button class="btn" id="unassign">Unassign device</button>` : ""}
      <button class="btn danger" id="remove">Remove door</button></div>
      <p class="hint">Rotating the key re-delivers it to the panel automatically. Unassigning sends the panel back to "awaiting adoption" and voids its key.</p>`}`);
  if (ro) $$("#dd input, #dd select").forEach((i) => (i.disabled = true));
  $$("[data-cmd]").forEach((b) => b.addEventListener("click", async () => {
    const cmd = b.dataset.cmd;
    if (cmd === "reboot" && !confirm(`Reboot the panel at ${d.name}? The door is unavailable for about 10 seconds.`)) return;
    try { await api(`/api/doors/${id}/command`, { body: { command: cmd } }); toast(`${b.textContent} sent to ${d.name}`); }
    catch (err) { toast(err.message, true); }
  }));
  openDoorId = id;
  $("#dd").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try {
      await api(`/api/doors/${id}`, { method: "PATCH", body: { name: f.get("name"), area: f.get("area"), unlock_ms: Number(f.get("unlock_ms")),
        credential_mode: f.get("credential_mode"), groups: f.getAll("groups").map(Number) } });
      toast("Door saved"); closeDrawer(); render();
    } catch (err) { toast(err.message, true); }
  });
  $("#rekey")?.addEventListener("click", async () => {
    if (!confirm("Rotate this door's key?")) return;
    const r = await api(`/api/doors/${id}/rekey`, { method: "POST" });
    if (r.auto) { toast("New key sealed to the panel; it switches over on its next check-in"); closeDrawer(); }
    else provisionPanel(r, d.name);
  });
  $("#unassign")?.addEventListener("click", async () => {
    if (!confirm(`Unassign ${d.serial} from ${d.name}? The door keeps its settings.`)) return;
    await api(`/api/doors/${id}/unassign`, { method: "POST" }); closeDrawer(); render();
  });
  $("#remove")?.addEventListener("click", async () => {
    if (d.serial) return toast("Unassign the device first", true);
    if (confirm("Remove this door? Its history stays in the journal.")) { await api(`/api/doors/${id}`, { method: "DELETE" }); closeDrawer(); render(); }
  });
}

// --- operators
PAGES.operators = async (el) => {
  const ops = await api("/api/operators");
  el.innerHTML = `<div class="toolbar"><span class="grow muted">Viewers can watch; operators can also handle alarms and change the site mode; admins configure everything.</span>
    <button id="add" class="btn primary">+ New operator</button></div>
    <div class="card"><table><thead><tr><th>Username</th><th>Role</th><th>Created</th><th></th></tr></thead><tbody>
    ${ops.map((o) => `<tr><td><b>${esc(o.username)}</b></td><td><span class="pill ${o.role === "admin" ? "violet" : o.role === "operator" ? "blue" : ""}">${o.role}</span></td>
      <td class="muted">${fmtDate(o.created)}</td><td>${o.username === ME.username ? "" : `<button class="btn small danger" data-del="${o.id}">Remove</button>`}</td></tr>`).join("")}</tbody></table></div>`;
  $("#add").addEventListener("click", () => {
    openDrawer(`<h2>New operator</h2><form class="form" id="of">
      <label>Username<input name="username" required minlength="3"></label>
      <label>Password (10+ characters)<input name="password" type="password" required minlength="10" autocomplete="new-password"></label>
      <label>Role<select name="role"><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option></select></label>
      <div class="form-actions"><span></span><div><button type="button" class="btn ghost" onclick="closeDrawer()">Cancel</button> <button class="btn primary">Create</button></div></div></form>`);
    $("#of").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      try { await api("/api/operators", { body: Object.fromEntries(f) }); closeDrawer(); render(); } catch (err) { toast(err.message, true); }
    });
  });
  $$("[data-del]").forEach((b) => b.addEventListener("click", async () => { if (confirm("Remove this operator?")) { await api(`/api/operators/${b.dataset.del}`, { method: "DELETE" }); render(); } }));
};

// --- audit
PAGES.audit = async (el) => {
  el.innerHTML = `<div class="card"><div class="card-head"><h2>Journal integrity</h2><button id="run" class="btn primary">Verify now</button></div>
    <div id="result" class="verify muted">Every access decision, alarm action, configuration change and photo hash is chained with HMAC-SHA256.
    Verification recomputes the chain from the first record; any edit, deletion or reordering breaks it at that record.</div></div>`;
  $("#run").addEventListener("click", async () => {
    const v = await api("/api/journal/verify");
    $("#result").innerHTML = v.ok
      ? `<span class="big" style="color:var(--green)">&#10003;</span><div><b>Chain intact</b><div class="muted">${v.checked} records verified · head <span class="mono">${v.head.slice(0, 24)}…</span></div></div>`
      : `<span class="big" style="color:var(--red)">&#10005;</span><div><b>Chain broken at record #${v.broken_at}</b><div class="muted">${esc(v.why)} · ${v.checked} records before it verified</div></div>`;
  });
};

// ---------- boot ----------
async function boot() {
  try { ME = await api("/api/me"); } catch { return; }
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#user-name").textContent = ME.username;
  $("#user-role").textContent = ME.role;
  $("#site-name").textContent = ME.site_name;
  $$("[data-role=admin]").forEach((a) => a.classList.toggle("hidden", !isAdmin()));
  connectWs();
  refreshAlarmBadge();
  render();
}

window.closeDrawer = closeDrawer;
fetch("/api/me", { credentials: "same-origin" }).then((r) => (r.ok ? boot() : showLogin()));
