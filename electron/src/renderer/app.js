'use strict';
/* =========================================================================
   Valkyrie renderer — splash cinematic + live multi-page dashboard.
   Talks to the shell only through window.valkyrie (preload). No Node, no
   direct HTTP, no localhost surface. All data arrives pre-parsed over IPC.
   ========================================================================= */

const V = window.valkyrie || null;
const $ = (id) => document.getElementById(id);
const el = (tag, cls, html) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (html != null) n.innerHTML = html;
  return n;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function safe(fn, fallback) { try { return await fn(); } catch { return fallback; } }

const LOGO = `
<svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M32 4 54 13v14c0 14-9.5 23-22 30C19.5 50 10 41 10 27V13L32 4z"
        stroke="#f6f6f7" stroke-width="2.2" fill="rgba(255,255,255,0.05)"/>
  <path d="M32 16v28M32 20l9 5M32 20l-9 5M32 30l9 5M32 30l-9 5"
        stroke="#f6f6f7" stroke-width="2.2" stroke-linecap="round"/>
</svg>`;

const state = { engineUp: false, protected: false, busy: false, route: 'dashboard', tele: null, pageTimer: null };

/* ============================ Utilities ============================== */
function fmt(n) { return (n == null || isNaN(n)) ? '0' : Number(n).toLocaleString('en-US'); }
function fmtUptime(s) {
  if (!s || s < 0) return '—';
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  const sec = Math.floor(s % 60);
  return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
}
function privacyScore(stats, up) {
  if (!up || !stats) return 0;
  const blocked = (stats.dns_blocked || 0) + (stats.fw_blocked || 0);
  return Math.min(100, Math.round(72 + 28 * (1 - 1 / (1 + blocked / 200))));
}
function animateNumber(node, to) {
  if (!node) return;
  const from = Number(node.dataset.v || 0);
  if (from === to) { node.textContent = fmt(to); return; }
  node.dataset.v = to;
  const t0 = performance.now(), dur = 650;
  const step = (t) => {
    const p = Math.min(1, (t - t0) / dur);
    const e = 1 - Math.pow(1 - p, 3);
    node.textContent = fmt(Math.round(from + (to - from) * e));
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* Component builders -------------------------------------------------- */
function statCard(id, label, icon, cls) {
  return `<div class="card ${cls || ''}"><div class="label">${ICON[icon] || ''}${label}</div>
    <div class="value"><span class="num" id="card-${id}" data-v="0">0</span></div></div>`;
}
function sectionHead(title, hint) {
  return `<div class="section-head"><h2>${title}</h2>${hint ? `<span class="hint">${hint}</span>` : ''}</div>`;
}
function rowsPanel(pairs) {
  return `<div class="panel"><div class="rows">${pairs.map(([k, v, icon, color]) =>
    `<div class="row"><span class="rk">${icon ? ICON[icon] : ''}${k}</span>
      <span class="rv" ${color ? `style="color:${color}"` : ''}>${v}</span></div>`).join('')}</div></div>`;
}
function badge(text, kind) {
  return `<span class="badge ${kind || ''}"><span class="bdot"></span>${text}</span>`;
}

/* ============================ Particles ============================== */
function startParticles() {
  const c = $('particles'); if (!c) return () => {};
  const ctx = c.getContext('2d');
  let raf, w, h, pts;
  const resize = () => { w = c.width = c.offsetWidth * devicePixelRatio; h = c.height = c.offsetHeight * devicePixelRatio; };
  resize(); window.addEventListener('resize', resize);
  pts = Array.from({ length: 46 }, () => ({
    x: Math.random() * w, y: Math.random() * h, r: (Math.random() * 1.6 + 0.4) * devicePixelRatio,
    vy: (-0.15 - Math.random() * 0.35) * devicePixelRatio, vx: (Math.random() - 0.5) * 0.15 * devicePixelRatio,
    a: Math.random() * 0.5 + 0.1,
  }));
  const draw = () => {
    ctx.clearRect(0, 0, w, h);
    for (const p of pts) {
      p.x += p.vx; p.y += p.vy;
      if (p.y < -10) { p.y = h + 10; p.x = Math.random() * w; }
      ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(235,235,240,${p.a})`; ctx.fill();
    }
    raf = requestAnimationFrame(draw);
  };
  draw();
  return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', resize); };
}

/* ============================ Splash ================================ */
const CHECKS = [
  'Loading Configuration', 'Starting DNS Engine', 'Initializing Firewall',
  'Loading Intelligence Engine', 'Loading Behavioral Engine', 'Loading Threat Detection',
  'Loading AI Engine', 'Verifying Rules', 'Loading Threat Intelligence',
  'Starting Local Services', 'Connecting Internal Components', 'Protection Ready',
];
async function typeLine(text) {
  const line = $('splashLine'); line.classList.remove('show'); await sleep(280);
  line.textContent = text; line.classList.add('show');
}
async function runIntro() {
  await sleep(1500);
  await typeLine('Hi.'); await sleep(1150);
  await typeLine("I'm Valkyrie."); await sleep(1250);
  await typeLine("I'll protect your privacy."); await sleep(1350);
  await typeLine('Initializing protection…'); await sleep(700);
}
async function runChecks(bootPromise) {
  const wrap = $('checks');
  const nodes = CHECKS.map((label) => {
    const row = el('div', 'check', `<span class="box">${ICON.check}</span><span class="spin" hidden></span><span>${label}</span>`);
    wrap.appendChild(row); return row;
  });
  let engineReady = false;
  bootPromise.then((r) => { engineReady = !!(r && r.ready); }).catch(() => {});
  for (let i = 0; i < nodes.length; i++) {
    const row = nodes[i], spin = row.querySelector('.spin'), box = row.querySelector('.box');
    row.classList.add('show'); box.style.display = 'none'; spin.hidden = false;
    await sleep(230 + Math.random() * 160);
    if (i === nodes.length - 1) {
      const t0 = performance.now();
      while (!engineReady && performance.now() - t0 < 18000) await sleep(200);
    }
    spin.hidden = true; box.style.display = 'grid'; row.classList.add('done'); await sleep(90);
  }
  return engineReady;
}
function makeCheckRow(label) {
  const el2 = el('div', 'check show',
    `<span class="box">${ICON.check}</span><span class="spin" hidden></span><span class="clabel">${label}</span>`);
  return { el: el2, box: el2.querySelector('.box'), spin: el2.querySelector('.spin'), lbl: el2.querySelector('.clabel') };
}

function finishSplash(stopParticles) {
  const splash = $('splash');
  splash.classList.add('hide');
  $('app').classList.add('ready');
  setTimeout(() => { splash.remove(); if (stopParticles) stopParticles(); }, 950);
}

// Normal launch — the quick cinematic ("Hi. I'm Valkyrie…").
async function runSplashNormal() {
  $('splashLogo').innerHTML = LOGO;
  const stopParticles = startParticles();
  const boot = V ? V.boot() : Promise.resolve({ ready: false });
  await runIntro();
  const ready = await runChecks(boot);
  state.engineUp = ready;
  await sleep(500);
  finishSplash(stopParticles);
}

// First install / upgrade / repair — a deliberate "Preparing Valkyrie" sequence
// whose checklist is driven by REAL boot:step events from the main process.
async function runSetupSplash(scenario) {
  const titles = {
    fresh:   ['Preparing Valkyrie',  'Setting up your protection for the first time'],
    upgrade: ['Updating Valkyrie',   'Applying the latest version — your data is preserved'],
    repair:  ['Repairing Valkyrie',  'Restoring your installation'],
  };
  const [title, subtitle] = titles[scenario] || titles.fresh;
  $('splashLogo').innerHTML = LOGO;
  const stopParticles = startParticles();

  await sleep(1300);
  await typeLine(title);
  const sub = $('splashSub'); if (sub) { sub.textContent = subtitle; sub.classList.add('show'); }

  const wrap = $('checks');
  const rows = {};
  const off = V ? V.onBootStep(({ key, label, status }) => {
    let r = rows[key];
    if (!r) { r = makeCheckRow(label); wrap.appendChild(r.el); rows[key] = r; }
    if (label) r.lbl.textContent = label;
    if (status === 'run') { r.spin.hidden = false; r.box.style.display = 'none'; r.el.classList.remove('done', 'warnrow'); }
    else { r.spin.hidden = true; r.box.style.display = 'grid'; r.el.classList.add(status === 'warn' ? 'warnrow' : 'done'); }
  }) : null;

  const res = V ? await V.boot() : { ready: false };
  if (off) off();
  state.engineUp = !!res.ready;
  await sleep(900);
  finishSplash(stopParticles);
}

/* ============================ Chrome / nav ========================== */
const NAV = [
  ['dashboard', 'Dashboard', 'dashboard'], ['protection', 'Protection', 'shield'],
  ['privacy', 'Privacy', 'lock'], ['firewall', 'Firewall', 'flame'],
  ['threats', 'Threats', 'alert'], ['intelligence', 'Intelligence', 'brain'],
  ['applications', 'Applications', 'apps'], ['network', 'Network', 'network'],
  ['dns', 'DNS', 'dns'], ['devices', 'Devices', 'devices'],
  ['updates', 'Updates', 'download'], ['settings', 'Settings', 'settings'],
  ['about', 'About', 'info'],
];
function buildChrome() {
  $('brandMark').innerHTML = ICON.shieldCheck;
  $('minBtn').innerHTML = ICON.min; $('maxBtn').innerHTML = ICON.max;
  $('closeBtn').innerHTML = ICON.x; $('notifBtn').innerHTML = ICON.bell;
  const sb = $('sidebar');
  sb.appendChild(el('div', 'section-label', 'Protection'));
  NAV.forEach(([id, label, icon], idx) => {
    if (idx === 7) sb.appendChild(el('div', 'section-label', 'System'));
    const item = el('div', 'nav-item' + (id === 'dashboard' ? ' active' : ''), `${ICON[icon]}<span>${label}</span>`);
    item.dataset.route = id; item.onclick = () => route(id); sb.appendChild(item);
  });
  if (V) {
    $('minBtn').onclick = () => V.minimize();
    $('maxBtn').onclick = () => V.maximize();
    $('closeBtn').onclick = () => V.close();
    $('notifBtn').onclick = () => V.openLogs();
  }
}
function route(id) {
  if (state.pageTimer) { clearInterval(state.pageTimer); state.pageTimer = null; }
  state.route = id;
  document.querySelectorAll('.nav-item').forEach((n) => n.classList.toggle('active', n.dataset.route === id));
  const meta = NAV.find((n) => n[0] === id);
  $('pageTitle').textContent = meta ? meta[1] : 'Valkyrie';
  const page = PAGES[id] || PAGES.dashboard;
  page.render();
  if (state.tele && page.onTele) page.onTele(state.tele);
  if (page.poll) { page.poll(); state.pageTimer = setInterval(page.poll, page.interval || 3000); }
}

/* ============================ PAGES ================================= */
const PAGES = {};

/* ---- Dashboard ---- */
PAGES.dashboard = {
  render() {
    $('page').innerHTML = `
      <div class="hero">
        <div class="status-pill" id="statusPill"><span class="dot"></span><span id="statusText">Checking…</span></div>
        <div class="orb-wrap" id="orbWrap">
          <div class="ring r1"></div><div class="ring r2"></div><div class="ring r3"></div>
          <button class="orb" id="orb"><span class="orb-icon">${ICON.power}</span><span class="orb-label" id="orbLabel">—</span></button>
        </div>
        <div class="sub">Valkyrie guards your DNS, firewall and privacy in real time.</div>
      </div>
      ${sectionHead('Live Activity', 'Updating every 1.5s')}
      <div class="grid">
        ${statCard('dns_blocked', 'DNS Requests Blocked', 'shield', 'accent-green')}
        ${statCard('fw_blocked', 'Firewall Blocks', 'flame')}
        ${statCard('flagged', 'Threats Flagged', 'alert')}
        ${statCard('total_24h', 'DNS Requests (24h)', 'dns', 'accent-blue')}
        ${statCard('allowed', 'Connections Allowed', 'network')}
        ${statCard('elements_cleaned', 'Trackers Cleaned', 'lock')}
        ${statCard('scanner_decisions', 'Scanner Decisions', 'activity')}
        ${statCard('privacy', 'Privacy Score', 'brain', 'accent-green')}
      </div>
      ${sectionHead('Recent Events', '')}
      <div class="feed" id="feed"><div class="empty">Waiting for live events…</div></div>`;
    const orb = $('orb'); if (orb) orb.onclick = toggleProtection;
  },
  onTele(data) {
    const stats = (data && data.stats) || {}, up = !!(data && data.ok);
    setProtectionUI(!!(data && data.protected));
    const ps = privacyScore(stats, up);
    const vals = {
      dns_blocked: stats.dns_blocked || 0, fw_blocked: stats.fw_blocked || 0,
      flagged: stats.flagged || 0, total_24h: stats.total_24h || 0, allowed: stats.allowed || 0,
      elements_cleaned: stats.elements_cleaned || 0, scanner_decisions: stats.scanner_decisions || 0, privacy: ps,
    };
    for (const [k, v] of Object.entries(vals)) animateNumber($('card-' + k), v);
    renderFeed((data && data.events) || []);
  },
};
function renderFeed(events) {
  const feed = $('feed'); if (!feed) return;
  if (!events.length) { feed.innerHTML = '<div class="empty">No events yet — activity appears here live.</div>'; return; }
  feed.innerHTML = '';
  events.slice(0, 40).forEach((e) => {
    const verdict = (e.action || e.verdict || e.decision || '').toString().toLowerCase();
    const kind = /block|deny|sinkhole/.test(verdict) ? 'block' : /flag|suspic|warn/.test(verdict) ? 'flag' : 'allow';
    const name = e.domain || e.query || e.name || e.host || e.target || '—';
    const meta = [e.process, e.type, e.reason].filter(Boolean).join(' · ');
    const t = e.time || e.timestamp || '';
    feed.appendChild(el('div', 'feed-row',
      `<span class="fdot ${kind}"></span><span class="fname">${escapeHtml(name)}</span>
       <span class="fmeta">${escapeHtml(meta || t)}</span>`));
  });
}

/* ---- Protection ---- */
PAGES.protection = {
  render() {
    $('page').innerHTML = `
      <div class="page-intro">Core protection status. Valkyrie intercepts DNS, enforces firewall policy and
      keeps a health heartbeat on every subsystem.</div>
      <div id="protRows"></div>
      <div class="btn-row">
        <button class="btn primary" id="protToggle">${ICON.power}<span>Toggle Protection</span></button>
        <button class="btn" id="protMeeting">${ICON.lock}<span>Meeting Mode</span></button>
        <button class="btn" id="protLogs">${ICON.activity}<span>Open Logs</span></button>
      </div>`;
    $('protToggle').onclick = toggleProtection;
    $('protLogs').onclick = () => V && V.openLogs();
    $('protMeeting').onclick = async () => {
      const m = await safe(() => V.api.get('/api/meeting/status'), {});
      await safe(() => V.api.post(m && m.active ? '/api/meeting/stop' : '/api/meeting/start'), null);
    };
  },
  onTele(data) {
    const s = (data && data.stats) || {}, up = !!(data && data.ok), prot = !!(data && data.protected);
    $('protRows').innerHTML = rowsPanel([
      ['Protection', prot ? badge('Active', 'ok') : badge('Standby', 'off'), 'shield'],
      ['Engine service', up ? badge('Running', 'ok') : badge('Stopped', 'off'), 'cpu'],
      ['Engine health', s.protection_healthy ? badge('Healthy', 'ok') : (up ? badge('Degraded', 'warn') : '—'), 'activity'],
      ['DNS interception', up ? `port ${s.dns_port || 53}` : '—', 'dns'],
      ['Firewall rules', fmt(s.fw_blocked || 0) + ' blocks', 'flame'],
      ['Meeting mode', s.meeting_active ? badge('On', 'warn') : badge('Off', 'off'), 'lock'],
      ['Running as service', s.running_as_service ? badge('Yes', 'ok') : badge('No', 'off'), 'cpu'],
      ['Uptime', up ? fmtUptime(s.uptime_seconds) : '—', 'activity'],
    ]);
  },
};

/* ---- Privacy ---- */
PAGES.privacy = {
  render() {
    $('page').innerHTML = `
      <div class="page-intro">Telemetry suppression, MAC identity, encrypted transport and zero-log status.</div>
      <div class="grid">
        ${statCard('cleaned', 'Trackers Cleaned', 'lock', 'accent-green')}
        ${statCard('pblocked', 'Requests Blocked', 'shield')}
      </div>
      ${sectionHead('Privacy Subsystems')}
      <div id="privRows"><div class="empty">Loading…</div></div>
      <div class="btn-row">
        <button class="btn" id="pvKill">${ICON.shield}<span>Kill Telemetry</span></button>
        <button class="btn" id="pvMac">${ICON.network}<span>Randomize MAC</span></button>
      </div>`;
    $('pvKill').onclick = async () => { await safe(() => V.api.post('/api/telemetry/kill'), null); this.poll(); };
    $('pvMac').onclick = async () => { await safe(() => V.api.post('/api/mac/randomize'), null); this.poll(); };
  },
  onTele(data) {
    const s = (data && data.stats) || {};
    animateNumber($('card-cleaned'), s.elements_cleaned || 0);
    animateNumber($('card-pblocked'), (s.dns_blocked || 0) + (s.fw_blocked || 0));
  },
  async poll() {
    const [tel, vpn, zero] = await Promise.all([
      safe(() => V.api.get('/api/telemetry/status'), {}),
      safe(() => V.api.get('/api/vpn/status'), {}),
      safe(() => V.api.get('/api/zero-log/status'), {}),
    ]);
    const box = $('privRows'); if (!box) return;
    const telStatus = tel.status === 'KILLED' ? badge('Killed', 'ok')
      : tel.status === 'ACTIVE' ? badge('Telemetry active', 'warn')
      : tel.status === 'PARTIAL' ? badge('Partial', 'warn') : badge('Unknown', 'off');
    box.innerHTML = rowsPanel([
      ['Windows telemetry', telStatus, 'shield'],
      ['Telemetry settings tracked', fmt((tel.settings || []).length), 'activity'],
      ['Encrypted transport (VPN)', vpn.hop1_conf_exists ? badge('Configured', 'ok') : badge('Not configured', 'off'), 'globe'],
      ['Zero-log mode', zero.active ? badge('Active', 'ok') : badge('Disk logging', 'off'), 'lock'],
      ['Log integrity', zero.integrity === 'verified' ? badge('Verified', 'ok') : (zero.integrity || '—'), 'check'],
    ]);
  },
};

/* ---- Firewall ---- */
PAGES.firewall = {
  render() {
    $('page').innerHTML = `
      <div class="page-intro">Outbound connection control. Blocked destinations and the busiest offenders.</div>
      <div class="grid">
        ${statCard('fw', 'Firewall Blocks', 'flame', 'accent-green')}
        ${statCard('fwallowed', 'Allowed', 'network')}
      </div>
      ${sectionHead('Top Blocked Destinations')}
      <div class="bars" id="fwBars"><div class="empty">No blocks recorded yet.</div></div>`;
  },
  onTele(data) {
    const s = (data && data.stats) || {};
    animateNumber($('card-fw'), s.fw_blocked || 0);
    animateNumber($('card-fwallowed'), s.allowed || 0);
    renderTopBlocked($('fwBars'), s.top_blocked || []);
  },
};
function renderTopBlocked(box, top) {
  if (!box) return;
  if (!top.length) { box.innerHTML = '<div class="empty">No blocks recorded yet.</div>'; return; }
  const max = Math.max(...top.map((t) => t[1] || t.count || 0), 1);
  box.innerHTML = top.slice(0, 8).map((t) => {
    const name = Array.isArray(t) ? t[0] : (t.domain || t.name);
    const n = Array.isArray(t) ? t[1] : (t.count || 0);
    return `<div class="bar-row"><span class="bn">${escapeHtml(name)}</span>
      <span class="bar-track"><span class="bar-fill" style="width:${Math.max(4, (n / max) * 100)}%"></span></span>
      <span class="bv">${fmt(n)}</span></div>`;
  }).join('');
}

/* ---- Threats (EDR) ---- */
PAGES.threats = {
  render() {
    $('page').innerHTML = `
      <div class="page-intro">Endpoint detection &amp; response — incidents raised by the behavioral engine.</div>
      <div class="grid" id="edrCards"><div class="empty">Loading EDR…</div></div>
      ${sectionHead('Recent Incidents')}
      <div class="list" id="edrList"><div class="empty">Loading…</div></div>`;
  },
  async poll() {
    const [stats, incidents] = await Promise.all([
      safe(() => V.api.get('/api/edr/stats'), {}),
      safe(() => V.api.get('/api/edr/incidents'), []),
    ]);
    const cards = $('edrCards');
    if (cards) cards.innerHTML = `
      <div class="card accent-green"><div class="label">${ICON.alert}Open Incidents</div><div class="value">${fmt(stats.open || stats.open_incidents || 0)}</div></div>
      <div class="card"><div class="label">${ICON.shield}Total Incidents</div><div class="value">${fmt(stats.total || stats.total_incidents || (Array.isArray(incidents) ? incidents.length : 0))}</div></div>
      <div class="card"><div class="label">${ICON.activity}Telemetry Events</div><div class="value">${fmt(stats.events || stats.event_count || 0)}</div></div>`;
    const list = $('edrList'); if (!list) return;
    const arr = Array.isArray(incidents) ? incidents : (incidents.incidents || []);
    if (!arr.length) { list.innerHTML = '<div class="empty">No incidents — endpoint is clean.</div>'; return; }
    list.innerHTML = arr.slice(0, 20).map((i) => `
      <div class="list-row"><div class="lr-main">
        <span class="lr-title">${escapeHtml(i.title || i.name || i.rule || 'Incident')}</span>
        <span class="lr-sub">${escapeHtml((i.severity || i.status || '') + (i.host ? ' · ' + i.host : ''))}</span>
      </div><span class="lr-val">${escapeHtml(i.status || i.severity || '')}</span></div>`).join('');
  },
};

/* ---- Intelligence ---- */
PAGES.intelligence = {
  render() { $('page').innerHTML = `
    <div class="page-intro">List-free threat intelligence: seed blocklist, live feeds and self-healing.</div>
    <div id="intelCards" class="grid"><div class="empty">Loading…</div></div>
    <div id="intelRows"></div>`; },
  async poll() {
    const info = await safe(() => V.api.get('/api/intelligence'), { enabled: false });
    const cards = $('intelCards');
    if (cards) cards.innerHTML = `
      <div class="card accent-blue"><div class="label">${ICON.brain}Blocklist Domains</div><div class="value">${fmt(info.blocklist_domains || 0)}</div></div>
      <div class="card"><div class="label">${ICON.shield}Seed Domains</div><div class="value">${fmt(info.seed_domains || 0)}</div></div>`;
    $('intelRows').innerHTML = rowsPanel([
      ['Intelligence engine', info.enabled ? badge('Enabled', 'ok') : badge('Disabled', 'off'), 'brain'],
      ['External feeds', info.external_lists ? badge('On', 'ok') : badge('Off (list-free)', 'off'), 'globe'],
      ['Self-heal', info.self_heal ? badge('Active', 'ok') : badge('Idle', 'off'), 'activity'],
    ]);
  },
};

/* ---- Applications ---- */
PAGES.applications = {
  render() { $('page').innerHTML = `
    <div class="page-intro">Processes generating network activity, ranked by request volume.</div>
    ${sectionHead('Top Process')}
    <div id="appTop"></div>
    ${sectionHead('Active Processes')}
    <div class="list" id="appList"><div class="empty">Watching for process activity…</div></div>`; },
  onTele(data) {
    const s = (data && data.stats) || {}, events = (data && data.events) || [];
    $('appTop').innerHTML = rowsPanel([
      ['Busiest process', escapeHtml(s.top_process || '—'), 'apps'],
      ['Top destination', escapeHtml(s.top_domain || '—'), 'globe'],
    ]);
    const byProc = {};
    events.forEach((e) => { const p = e.process; if (p) byProc[p] = (byProc[p] || 0) + 1; });
    const rows = Object.entries(byProc).sort((a, b) => b[1] - a[1]).slice(0, 15);
    const list = $('appList'); if (!list) return;
    if (!rows.length) { list.innerHTML = '<div class="empty">Watching for process activity…</div>'; return; }
    list.innerHTML = rows.map(([p, n]) =>
      `<div class="list-row"><div class="lr-main"><span class="lr-title">${escapeHtml(p)}</span>
        <span class="lr-sub">network events</span></div><span class="lr-val">${fmt(n)}</span></div>`).join('');
  },
};

/* ---- Network ---- */
PAGES.network = {
  render() { $('page').innerHTML = `
    <div class="page-intro">Live connection flow through the gateway.</div>
    <div class="grid">
      ${statCard('nTotal', 'DNS Requests (24h)', 'dns', 'accent-blue')}
      ${statCard('nAllowed', 'Allowed', 'network', 'accent-green')}
      ${statCard('nBlocked', 'Blocked', 'shield')}
      ${statCard('nFlagged', 'Flagged', 'alert')}
    </div>
    ${sectionHead('Gateway')}
    <div id="netRows"></div>`; },
  onTele(data) {
    const s = (data && data.stats) || {}, up = !!(data && data.ok);
    animateNumber($('card-nTotal'), s.total_24h || 0);
    animateNumber($('card-nAllowed'), s.allowed || 0);
    animateNumber($('card-nBlocked'), s.dns_blocked || 0);
    animateNumber($('card-nFlagged'), s.flagged || 0);
    $('netRows').innerHTML = rowsPanel([
      ['DNS port', up ? String(s.dns_port || 53) : '—', 'dns'],
      ['Web / API port', up ? String(s.web_port || 8090) : '—', 'globe'],
      ['Multi-hop VPN', s.multihop_hop1_ready ? badge('Ready', 'ok') : badge('Off', 'off'), 'network'],
    ]);
  },
};

/* ---- DNS ---- */
PAGES.dns = {
  render() { $('page').innerHTML = `
    <div class="page-intro">DNS sinkhole activity — the heart of Valkyrie's privacy protection.</div>
    <div class="grid">
      ${statCard('dTotal', 'Total Requests (24h)', 'dns', 'accent-blue')}
      ${statCard('dBlocked', 'Blocked', 'shield', 'accent-green')}
      ${statCard('dAllowed', 'Resolved', 'network')}
    </div>
    ${sectionHead('Top Blocked Domains')}
    <div class="bars" id="dnsBars"><div class="empty">No blocks yet.</div></div>`; },
  onTele(data) {
    const s = (data && data.stats) || {};
    animateNumber($('card-dTotal'), s.total_24h || 0);
    animateNumber($('card-dBlocked'), s.dns_blocked || 0);
    animateNumber($('card-dAllowed'), s.allowed || 0);
    renderTopBlocked($('dnsBars'), s.top_blocked || []);
  },
};

/* ---- Devices ---- */
PAGES.devices = {
  render() { $('page').innerHTML = `
    <div class="page-intro">This protected endpoint. Fleet devices appear here when a fleet server is connected.</div>
    <div id="devRows"></div>`; },
  onTele(data) {
    const s = (data && data.stats) || {}, up = !!(data && data.ok), prot = !!(data && data.protected);
    $('devRows').innerHTML = rowsPanel([
      ['This device', badge(prot ? 'Protected' : (up ? 'Standby' : 'Offline'), prot ? 'ok' : 'off'), 'devices'],
      ['Engine uptime', up ? fmtUptime(s.uptime_seconds) : '—', 'activity'],
      ['Running as service', s.running_as_service ? badge('Yes', 'ok') : badge('No', 'off'), 'cpu'],
      ['Scanner decisions', fmt(s.scanner_decisions || 0), 'shield'],
    ]);
  },
};

/* ---- Updates ---- */
PAGES.updates = {
  async render() {
    const info = await safe(() => V.appInfo(), { version: '—' });
    $('page').innerHTML = `
      <div class="page-intro">Valkyrie updates locally — rebuild the installer with one command, no app store.</div>
      ${rowsPanel([
        ['Installed version', escapeHtml('v' + (info.version || '—')), 'download'],
        ['Channel', badge('Stable', 'ok'), 'activity'],
        ['Status', badge('Up to date', 'ok'), 'check'],
      ])}
      <div class="btn-row"><button class="btn" id="upLogs">${ICON.activity}<span>Open Logs</span></button></div>`;
    const b = $('upLogs'); if (b) b.onclick = () => V && V.openLogs();
  },
};

/* ---- Settings ---- */
PAGES.settings = {
  async render() {
    const info = await safe(() => V.appInfo(), {});
    $('page').innerHTML = `
      <div class="page-intro">Application and engine configuration.</div>
      ${rowsPanel([
        ['App version', escapeHtml('v' + (info.version || '—')), 'info'],
        ['Engine location', `<span style="font-size:11.5px;color:var(--text-2)">${escapeHtml(info.engineRoot || '—')}</span>`, 'settings'],
        ['Dashboard port', '8090', 'globe'],
        ['Launch at startup', badge('Managed by installer', 'ok'), 'download'],
      ])}
      <div class="btn-row">
        <button class="btn" id="setLogs">${ICON.activity}<span>Open Logs</span></button>
        <button class="btn danger" id="setStop">${ICON.power}<span>Stop Protection</span></button>
      </div>`;
    $('setLogs').onclick = () => V && V.openLogs();
    $('setStop').onclick = () => V && V.stopEngine();
  },
};

/* ---- About ---- */
PAGES.about = {
  async render() {
    const info = await safe(() => V.appInfo(), { version: '—' });
    $('page').innerHTML = `
      <div class="placeholder" style="gap:18px">
        <div style="width:84px;height:84px">${LOGO}</div>
        <h3 style="font-size:22px;color:var(--text-0)">Valkyrie</h3>
        <div style="color:var(--text-1)">Premium privacy &amp; security for Windows</div>
        <div style="color:var(--text-2);font-size:12.5px">Version ${escapeHtml(info.version || '—')} · Local-first · No cloud accounts</div>
        <div style="color:var(--text-2);font-size:12px;max-width:440px;line-height:1.6">
          DNS sinkhole, firewall, behavioral EDR, threat intelligence and telemetry
          suppression — running entirely on your machine.</div>
      </div>`;
  },
};

/* ============================ Protection toggle ===================== */
async function toggleProtection() {
  if (!V || state.busy) return;
  state.busy = true;
  const wantOn = !state.protected;
  const label = $('orbLabel'); if (label) label.textContent = wantOn ? 'STARTING…' : 'STOPPING…';
  try {
    const r = wantOn ? await V.startEngine() : await V.stopEngine();
    if (wantOn && r && r.ready === false) {
      await V.errorDialog('Unable to start protection',
        'Valkyrie could not confirm the engine came online. Open logs to see why.');
    }
  } catch {
    await V.errorDialog('Protection error', 'An unexpected error occurred while changing protection state.');
  } finally { state.busy = false; }
}

/* ============================ Live topbar =========================== */
function setProtectionUI(on) {
  const wrap = $('orbWrap'), label = $('orbLabel'), pill = $('statusPill'), txt = $('statusText');
  if (wrap) wrap.classList.toggle('on', on);
  if (label && !state.busy) label.textContent = on ? 'STOP PROTECTION' : 'START PROTECTION';
  if (pill) pill.classList.toggle('on', on);
  if (txt) txt.textContent = on ? 'Protected' : 'Not protected';
}
function updateTopbar(data) {
  const s = (data && data.stats) || {}, up = !!(data && data.ok), prot = !!(data && data.protected);
  state.engineUp = up; state.protected = prot;
  $('tbStatus').textContent = prot ? 'Protected' : (up ? 'Standby' : 'Off');
  $('tbStatus').style.color = prot ? 'var(--text-0)' : 'var(--text-1)';
  $('tbBlocked').textContent = fmt((s.dns_blocked || 0) + (s.fw_blocked || 0));
  $('tbPrivacy').textContent = up ? privacyScore(s, up) : '—';
  $('tbUptime').textContent = up ? fmtUptime(s.uptime_seconds) : '—';
}

/* ============================ Boot ================================== */
async function init() {
  buildChrome();
  PAGES.dashboard.render();
  if (V) {
    V.onTelemetry((data) => {
      state.tele = data;
      updateTopbar(data);
      const page = PAGES[state.route];
      if (page && page.onTele) page.onTele(data);
    });
    V.appInfo().then((info) => { if (info && info.startPage) route(info.startPage); }).catch(() => {});
  }

  // Pick the boot experience: a deliberate setup sequence for a fresh install /
  // upgrade / repair, or the quick cinematic on a normal launch.
  let info = { scenario: 'normal' };
  if (V) { try { info = await V.lifecycleInfo(); } catch {} }
  if (info.scenario && info.scenario !== 'normal') await runSetupSplash(info.scenario);
  else await runSplashNormal();
}
document.addEventListener('DOMContentLoaded', init);
