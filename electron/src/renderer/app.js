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

// Shared modal focus trap — used by every full-screen overlay (Replay,
// Command Palette) so Tab/Shift+Tab cycle within the dialog instead of
// leaking focus back to the page behind it. Returns a disposer.
const FOCUSABLE_SEL = 'a[href], button:not([disabled]), input:not([disabled]), ' +
  'select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
function trapFocus(container) {
  const handler = (e) => {
    if (e.key !== 'Tab') return;
    const nodes = Array.from(container.querySelectorAll(FOCUSABLE_SEL))
      .filter((n) => n.offsetParent !== null);
    if (!nodes.length) return;
    const first = nodes[0], last = nodes[nodes.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  container.addEventListener('keydown', handler);
  return () => container.removeEventListener('keydown', handler);
}

// Twin-wing "V" mark — angular, faceted (two fill tones per blade to read as
// folded metal), converging on a center spike. Monochrome, matches the
// design system's black/white/grey rule; no color.
const LOGO = `
<svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
  <polygon points="29,4 2,14 9,19" fill="#f6f6f7" opacity="0.72"/>
  <polygon points="35,4 62,14 55,19" fill="#f6f6f7" opacity="0.72"/>
  <polygon points="18,12 2,22 7.5,25.5" fill="#f6f6f7" opacity="0.72"/>
  <polygon points="46,12 62,22 56.5,25.5" fill="#f6f6f7" opacity="0.72"/>
  <polygon points="29,4 25.5,8.5 2,14" fill="#f6f6f7"/>
  <polygon points="35,4 38.5,8.5 62,14" fill="#f6f6f7"/>
  <polygon points="18,12 15.5,16 2,22" fill="#f6f6f7"/>
  <polygon points="46,12 48.5,16 62,22" fill="#f6f6f7"/>
  <polygon points="30,19 32,31 34,19" fill="#f6f6f7"/>
</svg>`;

const state = { engineUp: false, protected: false, busy: false, route: 'dashboard', tele: null, pageTimer: null };

/* ============================ Utilities ============================== */
function fmt(n) { return (n == null || isNaN(n)) ? '0' : Number(n).toLocaleString('en-US'); }
// Formats a duration in SECONDS (fractional — MTTD/MTTR are often
// sub-second) into the shortest reasonable human string. Used only for
// valkyrie/edr/metrics.py's median_seconds/p95_seconds — null means "not
// enough data", handled by the caller before this is reached.
function fmtDuration(s) {
  if (s == null || isNaN(s)) return '—';
  if (s < 1) return `${Math.round(s * 1000)}ms`;
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)}s`;
  const m = Math.floor(s / 60), rem = Math.round(s % 60);
  if (m < 60) return rem ? `${m}m ${rem}s` : `${m}m`;
  const h = Math.floor(m / 60), remM = m % 60;
  return remM ? `${h}h ${remM}m` : `${h}h`;
}
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
// Sentinel for "this poll did not reach the engine", which is NOT the same as
// null ("this layer is switched off") and NOT the same as 0 ("we looked and
// found none"). Three distinct truths that all used to render as "0".
const NO_DATA = '—';
// Map a telemetry number for display: only trust it when the poll succeeded.
// Every counter these cards show is cumulative, so a 0 arriving on a failed
// poll is never real data -- it is the {} fallback in each onTele().
function statVal(up, v) { return up ? (v || 0) : NO_DATA; }

function animateNumber(node, to) {
  if (!node) return;
  if (to === NO_DATA) {
    // Deliberately does NOT clear dataset.v: the last known value is kept so
    // the number animates back from where it was once the engine returns,
    // rather than counting up from zero and looking like fresh activity.
    node.textContent = NO_DATA;
    node.classList.add('stat-off');
    node.title = 'No data — could not reach the engine on this poll';
    return;
  }
  // null/undefined means "the subsystem that produces this number is not
  // running" — distinct from a real zero. Rendering it as 0 reads as
  // "running, nothing found", which is false reassurance about a layer that
  // is switched off entirely. The API sends null deliberately for this.
  if (to == null) {
    node.dataset.v = 0;
    node.textContent = 'Off';
    node.classList.add('stat-off');
    node.title = 'This protection layer is not currently running';
    return;
  }
  node.classList.remove('stat-off');
  node.removeAttribute('title');
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
function truncate(s, n) {
  const str = String(s || '');
  return str.length > n ? str.slice(0, n - 1) + '…' : str;
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
/* Reusable empty / offline / error state — the one component every page uses so
   an absence of data is always communicated honestly and consistently.
   kind: 'offline' (engine not monitoring) | 'empty' (monitoring, nothing found)
       | 'error' (couldn't load). */
function stateBlock(kind, title, sub) {
  const ic = { offline: ICON.power, empty: ICON.shieldCheck || ICON.shield, error: ICON.alert }[kind] || ICON.shield;
  return `<div class="state-block ${kind}"><div class="sb-ic">${ic || ''}</div>
    <div class="sb-t">${escapeHtml(title)}</div>${sub ? `<div class="sb-s">${escapeHtml(sub)}</div>` : ''}</div>`;
}
// Plain-language incident impact (valkyrie/edr/impact.py, NIST SP 800-30
// harm-to-individuals vocabulary): what was exposed, to whom, is it
// reversible, what to do. Supplements severity — never replaces the .sev
// chip already shown alongside it — and is deliberately never a color or a
// score: harm_level is named in the caption, not painted. Missing/older-
// build incidents (no `impact` key) render nothing, not a placeholder.
function renderImpactLine(impact) {
  if (!impact || !impact.line) return '';
  return `<div class="impact-line"><span class="il-cap">Impact (${escapeHtml(impact.harm_level || 'unknown')}${impact.confirmed ? ', confirmed' : ''})</span>
    <span class="il-text">${escapeHtml(impact.line)}</span></div>`;
}

/* ============================ Particles ============================== */
function startParticles() {
  const c = $('particles'); if (!c) return () => {};
  const ctx = c.getContext('2d');
  let raf, w = 1, h = 1;
  // Keep the canvas BUFFER matched to its on-screen size at all times. Measuring
  // the element (with a viewport fallback) means we never seed into a partial
  // layout — the bug that bunched every particle into the top-left corner.
  const resize = () => {
    const dpr = window.devicePixelRatio || 1;
    const cssW = c.offsetWidth || c.clientWidth || window.innerWidth || 1;
    const cssH = c.offsetHeight || c.clientHeight || window.innerHeight || 1;
    w = c.width = Math.max(1, Math.round(cssW * dpr));
    h = c.height = Math.max(1, Math.round(cssH * dpr));
  };
  resize();
  window.addEventListener('resize', resize);
  // Density from the viewport (always known), not a maybe-unlaid-out canvas.
  const area = (window.innerWidth || 1440) * (window.innerHeight || 900);
  const count = Math.max(150, Math.min(340, Math.round(area / 9000)));
  // Positions are stored as FRACTIONS of the canvas (0..1). Multiplying by the
  // live width/height at draw time guarantees the field ALWAYS fills the whole
  // screen — independent of size, DPR, or when a resize lands.
  const pts = Array.from({ length: count }, () => ({
    fx: Math.random(), fy: Math.random(),
    r: Math.random() * 1.7 + 0.4,            // css px; scaled by dpr at draw
    vx: (Math.random() - 0.5) * 0.00022,     // fraction of width  / frame
    vy: -(0.00022 + Math.random() * 0.00060),// fraction of height / frame (up)
    a: Math.random() * 0.5 + 0.12,
  }));
  const draw = () => {
    const dpr = window.devicePixelRatio || 1;
    ctx.clearRect(0, 0, w, h);
    for (const p of pts) {
      p.fx += p.vx; p.fy += p.vy;
      if (p.fy < -0.02) { p.fy = 1.02; p.fx = Math.random(); }   // wrap top→bottom
      if (p.fx < -0.02) p.fx = 1.02; else if (p.fx > 1.02) p.fx = -0.02;
      ctx.beginPath();
      ctx.arc(p.fx * w, p.fy * h, p.r * dpr, 0, Math.PI * 2);
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
  ['dashboard', 'Dashboard', 'dashboard'], ['nyx', 'Nyx', 'brain'],
  ['protection', 'Protection', 'shield'],
  ['privacy', 'Privacy', 'lock'], ['firewall', 'Firewall', 'flame'],
  ['threats', 'Threats', 'alert'], ['hunting', 'Threat Hunting', 'search'],
  ['intelligence', 'Intelligence', 'brain'],
  ['applications', 'Applications', 'apps'], ['network', 'Network', 'network'],
  ['dns', 'DNS', 'dns'], ['devices', 'Devices', 'devices'],
  ['updates', 'Updates', 'download'], ['components', 'Components', 'cpu'],
  ['compliance', 'Compliance', 'shieldCheck'],
  ['settings', 'Settings', 'settings'], ['about', 'About', 'info'],
];
const NAV_SYSTEM_START = 'network';   // first item of the "System" sidebar section
function buildChrome() {
  $('brandMark').innerHTML = ICON.mark;
  $('minBtn').innerHTML = ICON.min; $('maxBtn').innerHTML = ICON.max;
  $('closeBtn').innerHTML = ICON.x; $('notifBtn').innerHTML = ICON.bell;
  $('searchBtn').innerHTML = ICON.search;
  $('searchBtn').onclick = () => CommandPalette.open();
  const sb = $('sidebar');
  sb.appendChild(el('div', 'section-label', 'Protection'));
  NAV.forEach(([id, label, icon]) => {
    if (id === NAV_SYSTEM_START) sb.appendChild(el('div', 'section-label', 'System'));
    const item = el('div', 'nav-item' + (id === 'dashboard' ? ' active' : ''), `${ICON[icon]}<span>${label}</span>`);
    item.dataset.route = id;
    item.tabIndex = 0;
    item.setAttribute('role', 'button');
    item.setAttribute('aria-current', id === 'dashboard' ? 'page' : 'false');
    item.onclick = () => route(id);
    item.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); route(id); } };
    sb.appendChild(item);
  });
  if (V) {
    $('minBtn').onclick = () => V.minimize();
    $('maxBtn').onclick = () => V.maximize();
    $('closeBtn').onclick = () => V.close();
    $('notifBtn').onclick = () => V.openLogs();
  }
}
// Reopen where the analyst left off — persisted locally only, never synced.
const LAST_ROUTE_KEY = 'valkyrie:lastRoute';
function saveLastRoute(id) { try { localStorage.setItem(LAST_ROUTE_KEY, id); } catch {} }
function loadLastRoute() {
  try {
    const id = localStorage.getItem(LAST_ROUTE_KEY);
    return NAV.some((n) => n[0] === id) ? id : null;   // only trust a route that still exists
  } catch { return null; }
}

function route(id) {
  if (state.pageTimer) { clearInterval(state.pageTimer); state.pageTimer = null; }
  state.route = id;
  document.querySelectorAll('.nav-item').forEach((n) => {
    const on = n.dataset.route === id;
    n.classList.toggle('active', on);
    n.setAttribute('aria-current', on ? 'page' : 'false');
  });
  const meta = NAV.find((n) => n[0] === id);
  $('pageTitle').textContent = meta ? meta[1] : 'Valkyrie';
  if (meta) saveLastRoute(id);
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
    setProtectionUI(!!(data && data.protected), up);
    const ps = privacyScore(stats, up);
    const vals = {
      dns_blocked: statVal(up, stats.dns_blocked), fw_blocked: statVal(up, stats.fw_blocked),
      flagged: statVal(up, stats.flagged), total_24h: statVal(up, stats.total_24h),
      allowed: statVal(up, stats.allowed),
      // elements_cleaned is intentionally NOT `|| 0`: the API sends null when
      // TLS inspection isn't running, and that must render as "Off", not 0.
      // On a failed poll we don't even know that much, so it is NO_DATA, not Off.
      elements_cleaned: up ? (stats.elements_cleaned ?? null) : NO_DATA,
      scanner_decisions: statVal(up, stats.scanner_decisions),
      privacy: up ? ps : NO_DATA,
    };
    for (const [k, v] of Object.entries(vals)) animateNumber($('card-' + k), v);
    renderFeed((data && data.events) || [], up);
  },
};
function renderFeed(events, up) {
  const feed = $('feed'); if (!feed) return;
  const vs = ViewState.feedState(up, events);
  if (vs.kind !== 'list') { feed.innerHTML = stateBlock(vs.kind, vs.title, vs.sub); return; }
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

/* ---- Nyx (the data guard) ---- */
// Nyx is Valkyrie's data brain: it reads each outbound request in the raw and,
// by the SHAPE of what's inside, spots a piece of the user crossing to a third
// party. This slice is SEE & REPORT — observe-only — so the page says so plainly
// and never implies Nyx is blocking those leaks (it isn't, yet). The "defended"
// tiles below are the OTHER, already-acting defenses (blocks, fake beacons),
// kept visually distinct from the observe-only leak feed so the honesty holds.
PAGES.nyx = {
  render() {
    $('page').innerHTML = `
      <div class="page-intro">Nyx is Valkyrie's data guard. It watches every request leaving your machine and,
      reading the raw data itself, catches when a piece of <em>you</em> — a device ID, your location,
      your contact details, a browser fingerprint — is being handed to a third party you didn't mean to talk to.
      <b>Right now Nyx is in watch-and-report mode: it tells you what it sees and never blocks or changes your
      traffic</b>, so it can't break a page or an app.</div>
      ${sectionHead('What Nyx saw', 'Live · updates every 3s')}
      <div class="grid">
        ${statCard('nyx_watched', 'Requests Watched (24h)', 'network', 'accent-blue')}
        ${statCard('nyx_leaks', 'Data Leaks Caught', 'alert')}
        ${statCard('nyx_lied', 'Beacons Fed Fake Data', 'lock', 'accent-green')}
        ${statCard('nyx_blocked', 'Trackers Stopped', 'shield', 'accent-green')}
      </div>
      ${sectionHead('Your data caught leaving to third parties', 'Each line is one thing Nyx watched leave — observed, not blocked')}
      <div class="feed" id="nyxFeed"><div class="empty">Waiting for Nyx…</div></div>`;
  },
  interval: 3000,
  async poll() {
    const feed = $('nyxFeed'); if (!feed) return;
    const data = await safe(() => V.api.get('/api/nyx'), null);
    const up = !!data && !data.error;
    const d = data || {}, def = d.defended || {};
    animateNumber($('card-nyx_watched'), statVal(up, d.watched_24h));
    animateNumber($('card-nyx_leaks'),   statVal(up, d.leak_count));
    animateNumber($('card-nyx_lied'),    statVal(up, def.fake_data_served));
    animateNumber($('card-nyx_blocked'), statVal(up, def.trackers_blocked));

    if (!up) {
      feed.innerHTML = stateBlock('offline', 'Nyx is offline',
        'Turn protection on and Nyx will start watching your data.');
      return;
    }
    const leaks = d.leaks || [];
    if (!leaks.length) {
      feed.innerHTML = stateBlock('empty', 'No data leaks caught',
        'Nyx is watching. Nothing has tried to take your data yet.');
      return;
    }
    feed.innerHTML = '';
    leaks.forEach((l) => {
      feed.appendChild(el('div', 'feed-row',
        `<span class="fdot flag"></span><span class="fname">${escapeHtml(l.sentence)}</span>
         <span class="fmeta">${escapeHtml(l.host || '')}</span>`));
    });
  },
};

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
      </div>
      ${sectionHead('Defense Coverage', 'What fraction of Valkyrie\'s defenses are actually running, right now')}
      <div id="tamperBanner"></div>
      <div id="covHead"><div class="empty">Loading…</div></div>
      <div id="covGaps"></div>
      ${sectionHead('Sensor Health', 'Detection sensors this engine depends on')}
      <div id="sensorRows"><div class="empty">Loading…</div></div>`;
    $('protToggle').onclick = toggleProtection;
    $('protLogs').onclick = () => V && V.openLogs();
    $('protMeeting').onclick = toggleMeetingMode;
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
  interval: 5000,
  async poll() {
    const tamperBanner = $('tamperBanner'), covHead = $('covHead'), covGaps = $('covGaps'),
      sensorBox = $('sensorRows');
    if (!sensorBox) return;
    const [sysmon, coverage, incidents] = await Promise.all([
      safe(() => V.api.get('/api/sysmon/status'), null),
      safe(() => V.api.get('/api/controls/coverage'), null),
      safe(() => V.api.get('/api/edr/incidents'), []),
    ]);
    const arr = Array.isArray(incidents) ? incidents : (incidents.incidents || []);
    // Sensor tamper (T1562.001): a security tool's OWN sensor going dark is
    // itself an attack technique (Impair Defenses). This is DIFFERENT
    // information from the coverage gap list below — an active-tampering
    // signal, not just "something isn't running" — so it keeps its own
    // banner rather than being folded into coverage. The old binary
    // "DEGRADED" banner (sysmon.degraded alone) is retired: the coverage
    // section below already reports that, with the effective/degraded/
    // absent nuance a boolean can't carry.
    const tamper = arr.filter((i) => (i.technique || '').includes('T1562.001'));
    const openTamper = tamper.find((i) => i.status === 'open') || tamper[0];
    if (tamperBanner) {
      tamperBanner.innerHTML = openTamper
        ? stateBlock('error', 'Sensor tamper detected (T1562.001)',
            openTamper.explanation || openTamper.title)
        : '';
    }

    renderCoverage(covHead, covGaps, coverage);

    sensorBox.innerHTML = rowsPanel([
      ['Sysmon', !sysmon ? badge('—', 'off')
        : !sysmon.monitored ? badge('Not monitored', 'off')
        : sysmon.sysmon_healthy == null ? badge('Checking…', 'off')
        : sysmon.sysmon_healthy ? badge('Healthy', 'ok') : badge('Degraded', 'warn'),
        'shield'],
      ['Coverage detail', sysmon && sysmon.monitored ? (sysmon.detail || '—') : '—', 'activity'],
      ['Sensor tamper alerts', tamper.length ? badge(`${tamper.length} (T1562.001)`, 'warn') : badge('None', 'ok'), 'alert'],
    ]);
  },
};

// Defense coverage (valkyrie/coverage.py): the headline fraction plus the
// NAMED gaps — "which parts of my defense are not running" is the actual
// deliverable, not the percentage alone. Three states, encoded by
// fill/opacity only (no color): effective = solid, degraded = mid-opacity,
// absent = hairline outline on empty track. A present-but-STOPPED sensor
// (e.g. Sysmon installed but not delivering events) lands in absent, never
// effective — see coverage.py's own module docstring for why that
// distinction is the entire point of this metric.
function renderCoverage(headBox, gapsBox, cov) {
  if (!headBox || !gapsBox) return;
  if (!cov) {
    headBox.innerHTML = rowsPanel([['Defense coverage', '—', 'shieldCheck']]);
    gapsBox.innerHTML = '';
    return;
  }
  const counts = cov.counts || {}, total = cov.total || 0;
  const eff = counts.effective || 0, deg = counts.degraded || 0, abs = counts.absent || 0;
  const pct = total ? Math.round((eff / total) * 100) : 0;
  const segPct = (n) => total ? Math.max(n > 0 ? 1.5 : 0, (n / total) * 100) : 0;
  headBox.innerHTML = `
    <div class="cov-head">
      <div class="cov-frac">${fmt(eff)} / ${fmt(total)}<span class="unit">controls effective · ${pct}%</span></div>
      <div class="cov-legend">
        <span class="lg"><span class="sw effective"></span>Effective (${fmt(eff)})</span>
        <span class="lg"><span class="sw degraded"></span>Degraded (${fmt(deg)})</span>
        <span class="lg"><span class="sw absent"></span>Absent (${fmt(abs)})</span>
      </div>
    </div>
    <div class="cov-track">
      <span class="cov-seg effective" style="width:${segPct(eff)}%"></span>
      <span class="cov-seg degraded" style="width:${segPct(deg)}%"></span>
      <span class="cov-seg absent" style="width:${segPct(abs)}%"></span>
    </div>`;

  const gaps = (cov.gaps || []).slice()
    // Absent first — the most actionable state — then degraded.
    .sort((a, b) => (a.state === b.state ? 0 : a.state === 'absent' ? -1 : 1));
  if (!gaps.length) {
    gapsBox.innerHTML = stateBlock('empty', 'Every control is effective', 'No named gaps right now.');
    return;
  }
  gapsBox.innerHTML = `<div class="list">${gaps.slice(0, 25).map((g) => {
    const stateBadge = g.state === 'absent' ? badge('Absent', 'err')
      : g.state === 'degraded' ? badge('Degraded', 'warn') : badge(g.state, 'off');
    return `<div class="list-row"><div class="lr-main">
        <span class="lr-title">${escapeHtml(g.name)}</span>
        <span class="lr-sub">${escapeHtml(g.category || '')} · ${escapeHtml(truncate(g.detail || '', 130))}</span>
      </div>${stateBadge}</div>`;
  }).join('')}</div>`;
}

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
      </div>
      ${sectionHead('Deception Engine', 'Fake replies fed to trackers instead of a dead end')}
      <div id="decRows"><div class="empty">Loading…</div></div>
      ${sectionHead('DoH Bypass Detection', 'Apps trying to route DNS around Valkyrie entirely')}
      <div id="dohRows"><div class="empty">Loading…</div></div>`;
    $('pvKill').onclick = killTelemetry;
    $('pvMac').onclick = randomizeMac;
  },
  onTele(data) {
    const s = (data && data.stats) || {}, up = !!(data && data.ok);
    animateNumber($('card-cleaned'), up ? (s.elements_cleaned ?? null) : NO_DATA);
    animateNumber($('card-pblocked'), statVal(up, (s.dns_blocked || 0) + (s.fw_blocked || 0)));
  },
  async poll() {
    const box = $('privRows'); if (!box) return;
    const vs = ViewState.privacyRowsState(state.engineUp);
    if (vs.kind !== 'list') {
      box.innerHTML = stateBlock(vs.kind, vs.title, vs.sub);
      const decBox = $('decRows'); if (decBox) decBox.innerHTML = stateBlock(vs.kind, vs.title, vs.sub);
      const dohBox = $('dohRows'); if (dohBox) dohBox.innerHTML = stateBlock(vs.kind, vs.title, vs.sub);
      return;
    }
    const [tel, vpn, zero, mac, fp, dec, doh] = await Promise.all([
      safe(() => V.api.get('/api/telemetry/status'), {}),
      safe(() => V.api.get('/api/vpn/status'), {}),
      safe(() => V.api.get('/api/zero-log/status'), {}),
      safe(() => V.api.get('/api/mac/status'), {}),
      safe(() => V.api.get('/api/fingerprint/status'), {}),
      safe(() => V.api.get('/api/deception/status'), null),
      safe(() => V.api.get('/api/doh/status'), null),
    ]);
    renderDeceptionRows($('decRows'), dec);
    renderDohRows($('dohRows'), doh);
    const telStatus = tel.status === 'KILLED' ? badge('Killed', 'ok')
      : tel.status === 'ACTIVE' ? badge('Telemetry active', 'warn')
      : tel.status === 'PARTIAL' ? badge('Partial', 'warn') : badge('Unknown', 'off');
    // MAC identity — show original → current (spoofed) for the adapter that changed.
    const ifaces = (mac && mac.interfaces) || {};
    let m = null, mName = '';
    for (const [name, v] of Object.entries(ifaces)) {
      if (v && v.changed) { m = v; mName = name; break; }
      if (!m && v && v.current) { m = v; mName = name; }
    }
    const monoOld = 'font-family:ui-monospace,monospace;opacity:.55';
    const monoNew = 'font-family:ui-monospace,monospace';
    const macCell = m && m.changed
      ? `<span style="${monoOld}">${m.original}</span> <span style="opacity:.5">→</span> <span style="${monoNew}">${m.current}</span>`
      : (m ? `<span style="${monoNew}">${m.current || '—'}</span> ${badge('original', 'off')}` : badge('—', 'off'));
    const fpCell = (fp && fp.normalized) ? badge('Spoofed (generic · TTL 64)', 'ok')
      : (fp && fp.supported ? badge('Real (Windows stack)', 'off') : badge('—', 'off'));
    box.innerHTML = rowsPanel([
      ['MAC identity' + (mName ? ' (' + mName + ')' : ''), macCell, 'network'],
      ['TCP/IP fingerprint', fpCell, 'activity'],
      ['Windows telemetry', telStatus, 'shield'],
      ['Telemetry settings tracked', fmt((tel.settings || []).length), 'activity'],
      ['Encrypted transport (VPN)', vpn.hop1_conf_exists ? badge('Configured', 'ok') : badge('Not configured', 'off'), 'globe'],
      ['Zero-log mode', zero.active ? badge('Active', 'ok') : badge('Disk logging', 'off'), 'lock'],
      ['Log integrity', zero.integrity === 'verified' ? badge('Verified', 'ok') : (zero.integrity || '—'), 'check'],
    ]);
  },
};

// Deception engine rows — how many trackers got a fabricated persona instead
// of a dead end, and what that persona currently looks like. A NULL `dec`
// means the endpoint call failed (engine off, or an older build without it);
// rendered as '—' rather than 0, since 0 would falsely read as "deception is
// active and simply has nothing to report yet".
function renderDeceptionRows(box, dec) {
  if (!box) return;
  const p = (dec && dec.persona) || null;
  box.innerHTML = rowsPanel([
    ['Trackers deceived (24h)', dec ? fmt(dec.trackers_deceived_24h) : '—', 'shield'],
    ['Beacons answered (24h)', dec ? fmt(dec.beacons_deceived_24h) : '—', 'activity'],
    ['Trackers deceived (all time)', dec ? fmt(dec.trackers_deceived_total) : '—', 'shield'],
    ['Current persona', p ? `${escapeHtml(p.city)}, ${escapeHtml(p.region)} · ${escapeHtml(p.locale)}` : '—', 'target'],
    ['Persona device', p ? `${escapeHtml(p.os)} · ${escapeHtml(p.browser)}` : '—', 'cpu'],
    ['Persona display', p ? `${escapeHtml(p.screen)} · ${p.cores}-core · ${p.memory_gb}GB` : '—', 'network'],
  ]);
}

// DoH-bypass rows — a process resolving DNS-over-HTTPS straight to a public
// resolver's IP is routing DNS around Valkyrie entirely, so it never reaches
// the deception/block decision at all. A NULL `doh` (endpoint call failed)
// renders as '—'; a wired-but-unavailable detector (no psutil) renders as
// its own distinct badge rather than looking identical to "nothing found".
function renderDohRows(box, doh) {
  if (!box) return;
  if (!doh) { box.innerHTML = rowsPanel([['DoH bypass detection', '—', 'globe']]); return; }
  const statusBadge = !doh.available ? badge('Unavailable', 'off')
    : doh.running ? badge('Monitoring', 'ok') : badge('Not running', 'warn');
  const r = doh.most_recent;
  const recent = r ? `${escapeHtml(r.process_name || 'unknown')} → ${escapeHtml(r.resolver_ip || '?')} · ${rpTime(r.timestamp)}`
    : badge('None seen', 'ok');
  box.innerHTML = rowsPanel([
    ['Detector', statusBadge, 'globe'],
    ['Bypass attempts (24h)', fmt(doh.bypass_attempts_24h), 'alert'],
    ['Distinct processes (24h)', fmt(doh.bypass_processes_24h), 'apps'],
    ['Bypass attempts (all time)', fmt(doh.bypass_attempts_total), 'alert'],
    ['Most recent attempt', recent, 'activity'],
  ]);
}

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
    const s = (data && data.stats) || {}, up = !!(data && data.ok);
    animateNumber($('card-fw'), statVal(up, s.fw_blocked));
    animateNumber($('card-fwallowed'), statVal(up, s.allowed));
    renderTopBlocked($('fwBars'), s.top_blocked || [], up);
  },
};
function renderTopBlocked(box, top, up) {
  if (!box) return;
  const vs = ViewState.topBlockedState(up, top);
  if (vs.kind !== 'list') { box.innerHTML = stateBlock(vs.kind, vs.title, vs.sub); return; }
  const max = Math.max(...top.map((t) => t[1] || t.count || 0), 1);
  box.innerHTML = top.slice(0, 8).map((t) => {
    const name = Array.isArray(t) ? t[0] : (t.domain || t.name);
    const n = Array.isArray(t) ? t[1] : (t.count || 0);
    return `<div class="bar-row"><span class="bn">${escapeHtml(name)}</span>
      <span class="bar-track"><span class="bar-fill" style="width:${Math.max(4, (n / max) * 100)}%"></span></span>
      <span class="bv">${fmt(n)}</span></div>`;
  }).join('');
}

// MTTD/MTTR (valkyrie/edr/metrics.py) — labeled in plain words, not
// acronyms alone, per the task: "time to detect" / "time to respond".
// median/p95 side by side (never a single average — see metrics.py's own
// docstring on why). n==0 renders as "not enough data yet", never a
// fabricated 0s, since a metric with no samples is not the same claim as
// an instant one.
function renderMttdMttr(box, m) {
  if (!box) return;
  if (!m) { box.innerHTML = rowsPanel([['Response speed', '—', 'activity']]); return; }
  const cell = (metric) => metric.n > 0
    ? `${fmtDuration(metric.median_seconds)} median · ${fmtDuration(metric.p95_seconds)} p95 <span class="lr-sub" style="display:inline">(${fmt(metric.n)} of ${fmt(metric.total)} incidents)</span>`
    : badge(`Not enough data yet (0 of ${fmt(metric.total)} incidents)`, 'off');
  box.innerHTML = rowsPanel([
    ['Time to detect', cell(m.mttd), 'search'],
    ['Time to respond', cell(m.mttr), 'shield'],
  ]);
}

/* ---- Threats (EDR) ---- */
PAGES.threats = {
  render() {
    $('page').innerHTML = `
      <div class="page-intro">Endpoint detection &amp; response — incidents raised by the behavioral engine.</div>
      <div class="grid" id="edrCards"><div class="empty">Loading EDR…</div></div>
      ${sectionHead('Response Speed', 'Time to detect a threat, and time to respond to it — the headline security metrics')}
      <div id="mttdRows"><div class="empty">Loading…</div></div>
      ${sectionHead('Recent Incidents')}
      <div class="list" id="edrList"><div class="empty">Loading…</div></div>`;
    // Delegated: click or keyboard-activate an incident to replay it
    // step-by-step. Survives the poll's innerHTML refresh because the
    // listener lives on the parent, not the (replaced) rows.
    const list = $('edrList');
    if (list) {
      list.onclick = (e) => {
        const row = e.target.closest('.inc-row');
        if (row && row.dataset.id) openReplay(row.dataset.id);
      };
      list.onkeydown = (e) => {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        const row = e.target.closest('.inc-row');
        if (row && row.dataset.id) { e.preventDefault(); openReplay(row.dataset.id); }
      };
    }
  },
  async poll() {
    const cards = $('edrCards');
    const list = $('edrList'); if (!list) return;
    // Honesty first: never imply "clean" when the engine isn't monitoring. A
    // security product that shows reassurance while protection is off is worse
    // than one that shows nothing. state.engineUp is driven by live telemetry.
    const mttdBox = $('mttdRows');
    if (!state.engineUp) {
      if (cards) cards.innerHTML = '';
      if (mttdBox) mttdBox.innerHTML = '';
      list.innerHTML = stateBlock('offline', 'Protection is off',
        'Valkyrie is not monitoring this endpoint right now. Start protection to see incidents and live detections.');
      return;
    }
    const [stats, incidents, mttdMttr] = await Promise.all([
      safe(() => V.api.get('/api/edr/stats'), {}),
      safe(() => V.api.get('/api/edr/incidents'), []),
      safe(() => V.api.get('/api/edr/metrics/mttd-mttr'), null),
    ]);
    renderMttdMttr(mttdBox, mttdMttr);
    if (cards) cards.innerHTML = `
      <div class="card accent-green"><div class="label">${ICON.alert}Open Incidents</div><div class="value">${fmt(stats.open || stats.open_incidents || 0)}</div></div>
      <div class="card"><div class="label">${ICON.shield}Total Incidents</div><div class="value">${fmt(stats.total || stats.total_incidents || (Array.isArray(incidents) ? incidents.length : 0))}</div></div>
      <div class="card"><div class="label">${ICON.activity}Telemetry Events</div><div class="value">${fmt(stats.events || stats.event_count || 0)}</div></div>`;
    const arr = Array.isArray(incidents) ? incidents : (incidents.incidents || []);
    if (!arr.length) {
      list.innerHTML = stateBlock('empty', 'No incidents detected',
        'The behavioral engine is monitoring this endpoint — no threats found.');
      return;
    }
    list.innerHTML = arr.slice(0, 20).map((i) => {
      const sev = String(i.severity || '').toLowerCase();
      const sevClass = /crit/.test(sev) ? 'critical' : /high/.test(sev) ? 'high'
        : /med/.test(sev) ? 'medium' : /low/.test(sev) ? 'low' : '';
      const sevText = sevClass || (i.status || 'incident');
      // MITRE id from a "technique" field, tolerating "T1003.001 — LSASS" strings.
      const tech = (i.technique || '').toString().match(/T\d{4}(?:\.\d{3})?/);
      const entity = i.entity || i.host || '';
      const sub = [i.status, i.host].filter(Boolean).join(' · ');
      const title = i.title || i.name || i.rule || 'Incident';
      // Plain-language "why" — the decision engine's own reasoning where
      // available (see edr/engine.py's _incident_explanation), so a user can
      // see why an incident exists without opening the replay view. Omitted
      // when it would just repeat the title verbatim.
      const explain = (i.explanation && i.explanation !== title) ? i.explanation : '';
      return `<div class="list-row inc-row" data-sev="${sevClass}" data-id="${escapeHtml(i.id || '')}"
        tabindex="0" role="button" aria-label="Replay incident: ${escapeHtml(title)}, ${escapeHtml(sevText)}">
        <span class="inc-rail"></span>
        <span class="sev ${sevClass}">${escapeHtml(sevText)}</span>
        <div class="lr-main">
          <span class="lr-title">${escapeHtml(title)}</span>
          <span class="lr-sub">${entity ? `<span class="mono-tag">${escapeHtml(entity)}</span> ` : ''}${escapeHtml(sub)}</span>
          ${explain ? `<span class="lr-sub lr-explain">${escapeHtml(truncate(explain, 160))}</span>` : ''}
          ${i.impact && i.impact.line ? `<span class="lr-sub lr-impact">${escapeHtml(truncate(i.impact.line, 170))}</span>` : ''}
        </div>
        ${tech ? `<span class="mono-tag">${escapeHtml(tech[0])}</span>` : ''}
        <span class="rp-open">▶ Replay</span>
      </div>`;
    }).join('');
  },
};

function fmtCell(v) {
  if (v == null || v === '') return '—';
  if (typeof v === 'number') return Number.isInteger(v) ? fmt(v) : v.toFixed(2);
  return String(v);
}

/* ---- Threat Hunting ---- */
// A real, safe, read-only query surface (edr/hunt.py): a small validated
// filter spec compiled to a parameterised query — never arbitrary SQL — plus
// six canned "saved hunts" for the questions defenders ask most. No query
// language, autocomplete-from-history, or saved/pinned queries beyond that
// exist server-side, so none of that is invented client-side either.
PAGES.hunting = {
  async render() {
    $('page').innerHTML = `
      <div class="page-intro">Structured, read-only queries over Valkyrie's event history — pivot by process,
      domain, category, decision or suspicion score. Six saved hunts cover the questions defenders ask most.</div>
      ${sectionHead('Saved Hunts')}
      <div class="hunt-saved" id="huntSaved"><div class="empty">Loading…</div></div>
      ${sectionHead('Quick Pivots', 'last 24h')}
      <div id="huntFacets"><div class="empty">Loading…</div></div>
      ${sectionHead('Ad-hoc Query')}
      <div class="hunt-filters">
        <input class="rp-input" id="hfDomain" placeholder="Domain contains…" aria-label="Domain contains" />
        <input class="rp-input" id="hfProcess" placeholder="Process name (exact)" aria-label="Process name, exact match" />
        <select class="rp-select" id="hfDecision" aria-label="Decision">
          <option value="">Any decision</option>
          <option value="blocked">Blocked</option><option value="allowed">Allowed</option>
          <option value="flagged">Flagged</option><option value="behavioral">Behavioral</option>
        </select>
        <input class="rp-input" id="hfCategory" placeholder="Category" list="huntCatList" aria-label="Category" />
        <datalist id="huntCatList"></datalist>
        <select class="rp-select" id="hfSince" aria-label="Time window">
          <option value="0">Any time</option><option value="1">Last hour</option>
          <option value="24" selected>Last 24h</option><option value="168">Last 7 days</option>
        </select>
        <input class="rp-input" id="hfSuspicion" type="number" min="0" max="1" step="0.05" placeholder="Min suspicion" aria-label="Minimum suspicion score, 0 to 1" />
        <button class="btn primary" id="hfRun">${ICON.search}<span>Run</span></button>
      </div>
      ${sectionHead('Results')}
      <div id="huntResults">${stateBlock('empty', 'No query run yet', 'Pick a saved hunt above or run an ad-hoc query.')}</div>`;
    $('hfRun').onclick = () => this.runAdhoc();
    ['hfDomain', 'hfProcess', 'hfCategory', 'hfSuspicion'].forEach((id) => {
      $(id).addEventListener('keydown', (e) => { if (e.key === 'Enter') this.runAdhoc(); });
    });

    if (!state.engineUp) {
      $('huntSaved').innerHTML = stateBlock('offline', 'Protection is off',
        'Hunting queries the live event history — start protection to use it.');
      $('huntFacets').innerHTML = '';
      return;
    }
    const data = await safe(() => V.api.get('/api/edr/hunt/saved'), null);
    this.renderSaved((data && data.hunts) || []);
    this.renderFacets((data && data.facets) || {});
  },
  renderSaved(hunts) {
    const box = $('huntSaved'); if (!box) return;
    if (!hunts.length) { box.innerHTML = stateBlock('empty', 'No saved hunts available', ''); return; }
    box.innerHTML = hunts.map((h) =>
      `<button class="hunt-chip" data-saved="${escapeHtml(h.id)}" title="${escapeHtml(h.description || '')}">${escapeHtml(h.name)}</button>`).join('');
    box.querySelectorAll('[data-saved]').forEach((b) => { b.onclick = () => this.runSaved(b.dataset.saved, b); });
  },
  renderFacets(f) {
    const box = $('huntFacets'); if (!box) return;
    const procs = f.top_processes || [], cats = f.top_categories || [], dec = f.decisions || {};
    if (!procs.length && !cats.length && !Object.keys(dec).length) {
      box.innerHTML = stateBlock('empty', 'No activity in the last 24h', '');
    } else {
      const row = (label, chips) => chips
        ? `<div class="hunt-facet"><span class="hunt-facet-l">${escapeHtml(label)}</span><div class="hunt-facet-chips">${chips}</div></div>` : '';
      box.innerHTML =
        row('Top processes', procs.map((p) => `<span class="mono-tag">${escapeHtml(p.process_name || '—')} · ${fmt(p.c)}</span>`).join('')) +
        row('Top categories', cats.map((c) => `<span class="mono-tag">${escapeHtml(c.raw_category || '—')} · ${fmt(c.c)}</span>`).join('')) +
        row('Decisions', Object.entries(dec).map(([k, v]) => `<span class="mono-tag">${escapeHtml(k)} · ${fmt(v)}</span>`).join(''));
    }
    // Feed the category suggestion list from real, observed categories only.
    const dl = $('huntCatList');
    if (dl) dl.innerHTML = cats.map((c) => `<option value="${escapeHtml(c.raw_category)}">`).join('');
  },
  async runSaved(id, btn) {
    document.querySelectorAll('.hunt-chip').forEach((c) => c.classList.remove('active'));
    if (btn) btn.classList.add('active');
    $('huntResults').innerHTML = `<div class="empty">Running "${escapeHtml(btn ? btn.textContent : id)}"…</div>`;
    const res = await safe(() => V.api.post('/api/edr/hunt', { saved: id, limit: 200 }), null);
    this.renderResults(res);
  },
  async runAdhoc() {
    document.querySelectorAll('.hunt-chip').forEach((c) => c.classList.remove('active'));
    const filters = {
      domain_contains: $('hfDomain').value.trim(),
      process: $('hfProcess').value.trim(),
      decision: $('hfDecision').value || undefined,
      category: $('hfCategory').value.trim(),
      since_hours: Number($('hfSince').value) || 0,
      min_suspicion: Number($('hfSuspicion').value) || 0,
    };
    $('huntResults').innerHTML = '<div class="empty">Running query…</div>';
    const res = await safe(() => V.api.post('/api/edr/hunt', { filters, limit: 200 }), null);
    this.renderResults(res);
  },
  renderResults(res) {
    if (!res) { $('huntResults').innerHTML = stateBlock('error', 'Query failed', 'Could not reach the engine.'); return; }
    if (res.error) { $('huntResults').innerHTML = stateBlock('error', 'Query failed', res.error); return; }
    this.resultRows = res.rows || [];
    this.resultCols = this.resultRows.length ? Object.keys(this.resultRows[0]) : [];
    this.sortCol = null; this.sortDir = 'asc';
    this.paintResults();
  },
  // Sort state lives on the page object, not the DOM, so re-sorting never
  // re-fetches — the same "local re-render from cached state" pattern the
  // Components page uses for its restart-arm state.
  paintResults() {
    const box = $('huntResults'); if (!box) return;
    const rows = this.resultRows || [], cols = this.resultCols || [];
    if (!rows.length) { box.innerHTML = stateBlock('empty', 'No matches', 'Nothing in the event history matched this query.'); return; }
    const sorted = DataTable.sortRows(rows, this.sortCol, this.sortDir);
    const arrow = (c) => c !== this.sortCol ? '' : (this.sortDir === 'asc' ? ' ▲' : ' ▼');
    box.innerHTML = `
      <div class="hunt-toolbar">
        <span class="hunt-count">${fmt(rows.length)} row${rows.length === 1 ? '' : 's'}</span>
        <div class="hunt-toolbar-actions">
          <button class="btn" id="huntCopyCsv">${ICON.download}<span>Copy CSV</span></button>
          <button class="btn" id="huntCopyJson">${ICON.download}<span>Copy JSON</span></button>
        </div>
      </div>
      <div class="hunt-table-wrap"><table class="hunt-table">
        <thead><tr>${cols.map((c) => `<th data-col="${escapeHtml(c)}" tabindex="0" role="button"
          aria-label="Sort by ${escapeHtml(c)}" title="Sort by ${escapeHtml(c)}">${escapeHtml(c)}${arrow(c)}</th>`).join('')}</tr></thead>
        <tbody>${sorted.map((r) => `<tr tabindex="0" role="button" title="Click to copy this row">
          ${cols.map((c) => `<td>${escapeHtml(fmtCell(r[c]))}</td>`).join('')}</tr>`).join('')}</tbody>
      </table></div>`;
    box.querySelectorAll('.hunt-table th').forEach((th) => {
      const activate = () => {
        const col = th.dataset.col;
        this.sortDir = (this.sortCol === col && this.sortDir === 'asc') ? 'desc' : 'asc';
        this.sortCol = col;
        this.paintResults();
      };
      th.onclick = activate;
      th.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(); } };
    });
    box.querySelectorAll('.hunt-table tbody tr').forEach((tr, i) => {
      const copy = () => this.copyRow(sorted[i], cols);
      tr.onclick = copy;
      tr.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); copy(); } };
    });
    $('huntCopyCsv').onclick = () => this.copyText(DataTable.toCSV(rows, cols), 'Results copied as CSV.');
    $('huntCopyJson').onclick = () => this.copyText(DataTable.toJSON(rows), 'Results copied as JSON.');
  },
  async copyRow(row, cols) { this.copyText(DataTable.rowToTSV(row, cols), 'Row copied.'); },
  async copyText(text, okMessage) {
    try { await navigator.clipboard.writeText(text); toast(okMessage, 'ok'); }
    catch { toast('Could not access the clipboard.', 'error'); }
  },
};


/* ---- Intelligence ---- */
PAGES.intelligence = {
  render() { $('page').innerHTML = `
    <div class="page-intro">List-free threat intelligence: seed blocklist, live feeds and self-healing.</div>
    <div id="intelCards" class="grid"><div class="empty">Loading…</div></div>
    <div id="intelRows"></div>`; },
  async poll() {
    const vs = ViewState.intelRowsState(state.engineUp);
    if (vs.kind !== 'list') {
      const cards = $('intelCards'); if (cards) cards.innerHTML = '';
      const rows = $('intelRows'); if (rows) rows.innerHTML = stateBlock(vs.kind, vs.title, vs.sub);
      return;
    }
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
    const s = (data && data.stats) || {}, events = (data && data.events) || [], up = !!(data && data.ok);
    $('appTop').innerHTML = rowsPanel([
      ['Busiest process', escapeHtml(s.top_process || '—'), 'apps'],
      ['Top destination', escapeHtml(s.top_domain || '—'), 'globe'],
    ]);
    const byProc = {};
    events.forEach((e) => { const p = e.process; if (p) byProc[p] = (byProc[p] || 0) + 1; });
    const rows = Object.entries(byProc).sort((a, b) => b[1] - a[1]).slice(0, 15);
    const list = $('appList'); if (!list) return;
    const vs = ViewState.processListState(up, rows);
    if (vs.kind !== 'list') { list.innerHTML = stateBlock(vs.kind, vs.title, vs.sub); return; }
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
    animateNumber($('card-nTotal'), statVal(up, s.total_24h));
    animateNumber($('card-nAllowed'), statVal(up, s.allowed));
    animateNumber($('card-nBlocked'), statVal(up, s.dns_blocked));
    animateNumber($('card-nFlagged'), statVal(up, s.flagged));
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
    const s = (data && data.stats) || {}, up = !!(data && data.ok);
    animateNumber($('card-dTotal'), statVal(up, s.total_24h));
    animateNumber($('card-dBlocked'), statVal(up, s.dns_blocked));
    animateNumber($('card-dAllowed'), statVal(up, s.allowed));
    renderTopBlocked($('dnsBars'), s.top_blocked || [], up);
  },
};

/* ---- Devices ---- */
// Asset inventory (CIS Controls #1/#2, valkyrie/asset_inventory.py): what's
// installed, listening and loaded on THIS device. The snapshot counts are
// bookkeeping; "Recent Changes" — the delta since the engine started
// watching — is the actual product surface, so it renders second and gets
// the fuller treatment (per-row detail), not the reverse.
PAGES.devices = {
  render() { $('page').innerHTML = `
    <div class="page-intro">This protected endpoint. Fleet devices appear here when a fleet server is connected.</div>
    <div id="devRows"></div>
    ${sectionHead('Asset Inventory', 'What is installed, listening, and loaded — CIS Controls #1/#2')}
    <div id="assetCounts"><div class="empty">Loading…</div></div>
    ${sectionHead('Recent Changes', 'New since Valkyrie started watching — the delta is the signal')}
    <div class="list" id="assetChanges"><div class="empty">Loading…</div></div>`; },
  onTele(data) {
    const s = (data && data.stats) || {}, up = !!(data && data.ok), prot = !!(data && data.protected);
    $('devRows').innerHTML = rowsPanel([
      ['This device', badge(prot ? 'Protected' : (up ? 'Standby' : 'Offline'), prot ? 'ok' : 'off'), 'devices'],
      ['Engine uptime', up ? fmtUptime(s.uptime_seconds) : '—', 'activity'],
      ['Running as service', s.running_as_service ? badge('Yes', 'ok') : badge('No', 'off'), 'cpu'],
      ['Scanner decisions', fmt(s.scanner_decisions || 0), 'shield'],
    ]);
  },
  // Backed by an hourly server-side poll (AssetInventoryCollector) and now a
  // fast in-memory cache (see valkyrie/asset_inventory.py's last_snapshot())
  // — no need to hit it as often as the 2s telemetry stream.
  interval: 15000,
  async poll() {
    const counts = $('assetCounts'), changes = $('assetChanges');
    if (!counts || !changes) return;
    if (!state.engineUp) {
      counts.innerHTML = '';
      changes.innerHTML = stateBlock('offline', 'Protection is off',
        'Asset inventory is collected by the live engine — start protection to see it.');
      return;
    }
    const inv = await safe(() => V.api.get('/api/asset-inventory'), null);
    renderAssetCounts(counts, inv);
    renderAssetChanges(changes, inv);
  },
};

// A NULL inv means the endpoint call itself failed (engine off, or an older
// build without it) — rendered as '—', never 0, for the same reason
// renderDeceptionRows does: 0 would read as "collected, found nothing",
// which is a different (and false, here) claim than "no data arrived".
function renderAssetCounts(box, inv) {
  if (!box) return;
  if (!inv) { box.innerHTML = rowsPanel([['Asset inventory', '—', 'apps']]); return; }
  const c = inv.counts || {};
  box.innerHTML = rowsPanel([
    ['Installed software', fmt(c.software), 'apps'],
    ['Listening ports', fmt(c.listening_ports), 'network'],
    ['Kernel drivers', fmt(c.kernel_drivers), 'cpu'],
    ['Autostart entries', fmt(c.boot_items), 'activity'],
    ['Snapshot taken', inv.taken_at ? rpTime(inv.taken_at) : '—', 'activity'],
  ]);
}

const ASSET_CHANGE_LABEL = {
  new_installed_software: 'New software installed',
  new_listening_port: 'New listening port',
  new_kernel_driver: 'New kernel driver',
};
const ASSET_CHANGE_ICON = {
  new_installed_software: 'apps',
  new_listening_port: 'network',
  new_kernel_driver: 'cpu',
};
// Recent changes — the actual product surface (see the PAGES.devices
// comment above). Each row states what changed, and — encoded by fill vs.
// outline per the monochrome design language, never color — whether it
// came from a trusted, Microsoft-owned path ('ok', filled) or not
// ('warn', outline), the same badge vocabulary the rest of the app uses
// for effective-vs-degraded state.
function renderAssetChanges(box, inv) {
  if (!box) return;
  if (!inv) { box.innerHTML = stateBlock('error', 'Could not load asset inventory', ''); return; }
  const rows = inv.recent_changes || [];
  if (!rows.length) {
    box.innerHTML = stateBlock('empty', 'No changes observed yet',
      'Valkyrie snapshots this device hourly; a change is reported the poll after it first appears.');
    return;
  }
  box.innerHTML = rows.slice(0, 30).map((r) => {
    const label = ASSET_CHANGE_LABEL[r.activity] || r.activity || 'Change';
    const icon = ASSET_CHANGE_ICON[r.activity] || 'activity';
    const trustBadge = r.trusted_os_path ? badge('Trusted OS path', 'ok') : badge('Unverified path', 'warn');
    const path = r.path ? truncate(r.path, 70) : '';
    return `<div class="list-row"><div class="lr-main">
        <span class="lr-title">${ICON[icon] || ''}${escapeHtml(label)}: ${escapeHtml(r.identity || '')}</span>
        <span class="lr-sub">${path ? `<span class="mono-tag">${escapeHtml(path)}</span> · ` : ''}${rpTime(r.detected_at)}</span>
      </div>${trustBadge}</div>`;
  }).join('');
}

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

/* ---- Components ---- */
// The uniform plugin contract every subsystem already runs through
// (valkyrie/components.py, ADR 0021) — register/health/metrics/config/
// restart, fault-isolated so a broken health probe reports "error" instead
// of crashing anything. GET /api/components + POST /{name}/restart already
// existed with zero UI; this is that UI, not a new backend.
const COMPONENT_ICON = {
  storage: 'devices', network: 'network', intelligence: 'brain', detection: 'shieldCheck',
  sensor: 'activity', response: 'flame', integration: 'apps', privacy: 'lock',
};
function compHealthBadge(st) {
  return {
    up: badge('Healthy', 'ok'), degraded: badge('Degraded', 'warn'),
    down: badge('Down', 'off'), disabled: badge('Not available', 'off'),
    error: badge('Error', 'err'),
  }[st] || badge(st || 'Unknown', 'off');
}
PAGES.components = {
  restartArmed: null, restarting: null, armTimer: null, expanded: {}, lastComps: null,
  render() {
    $('page').innerHTML = `
      <div class="page-intro">Every subsystem Valkyrie runs — DNS, firewall, EDR, sensors, threat intel and more —
      reports through one uniform health contract. A subsystem whose health check itself fails is isolated and
      shown as an error, never silently swallowed.</div>
      <div class="grid" id="compCards"><div class="empty">Loading…</div></div>
      ${sectionHead('Subsystems')}
      <div id="compList"><div class="empty">Loading…</div></div>`;
    this.restartArmed = null; this.restarting = null; this.expanded = {}; this.lastComps = null;
  },
  async poll() {
    const cards = $('compCards'), list = $('compList'); if (!list) return;
    if (!state.engineUp) {
      cards.innerHTML = '';
      list.innerHTML = stateBlock('offline', 'Protection is off',
        'Component health is reported by the engine — start protection to see live subsystem status.');
      return;
    }
    const data = await safe(() => V.api.get('/api/components'), null);
    if (!data || data.enabled === false) {
      cards.innerHTML = '';
      list.innerHTML = stateBlock('error', 'Component registry unavailable',
        'Could not reach the engine for subsystem health.');
      return;
    }
    const comps = data.components || [];
    const counts = (data.overall && data.overall.counts) || {};
    const healthy = counts.up || 0;
    const attention = (counts.degraded || 0) + (counts.down || 0) + (counts.error || 0);
    cards.innerHTML = `
      <div class="card"><div class="label">${ICON.cpu}Total Subsystems</div><div class="value"><span class="num" id="card-compTotal" data-v="0">0</span></div></div>
      <div class="card accent-green"><div class="label">${ICON.shieldCheck}Healthy</div><div class="value"><span class="num" id="card-compHealthy" data-v="0">0</span></div></div>
      <div class="card"><div class="label">${ICON.alert}Needs Attention</div><div class="value"><span class="num" id="card-compAttn" data-v="0">0</span></div></div>`;
    animateNumber($('card-compTotal'), comps.length);
    animateNumber($('card-compHealthy'), healthy);
    animateNumber($('card-compAttn'), attention);
    this.lastComps = comps;   // cached so arm/disarm can re-render without a re-fetch
    this.renderList();
  },
  // Rebuilds the list from the last fetch only — no network call. Used both
  // after a poll and whenever local UI state (armed restart, expanded
  // metrics) changes, so a poll landing mid-confirm can never silently
  // reset a restart the user already armed.
  renderList() {
    const list = $('compList'); if (!list) return;
    const comps = this.lastComps || [];
    if (!comps.length) {
      list.innerHTML = stateBlock('empty', 'No components registered', 'Nothing to show yet.');
      return;
    }
    const expanded = this.expanded || {};
    list.innerHTML = `<div class="comp-list">${comps.map((c) => this.row(c, !!expanded[c.name])).join('')}</div>`;
    list.querySelectorAll('[data-restart]').forEach((b) => { b.onclick = () => this.handleRestart(b.dataset.restart); });
    list.querySelectorAll('.comp-toggle').forEach((b) => {
      b.onclick = () => {
        const name = b.dataset.name;
        this.expanded = this.expanded || {};
        this.expanded[name] = !this.expanded[name];
        this.renderList();
      };
    });
  },
  row(c, isExpanded) {
    const h = c.health || {};
    const metrics = c.metrics || {};
    const keys = Object.keys(metrics).filter((k) => k !== '_error');
    const metricsHtml = keys.length
      ? keys.slice(0, 12).map((k) => `<div class="comp-metric"><span>${escapeHtml(k)}</span><span>${escapeHtml(String(metrics[k]))}</span></div>`).join('')
      : '<div class="comp-metric" style="opacity:.6">No metrics reported.</div>';
    const armed = this.restartArmed === c.name;
    const restarting = this.restarting === c.name;
    return `<div class="comp-item">
      <div class="comp-row">
        <span class="comp-ic">${ICON[COMPONENT_ICON[c.kind]] || ICON.cpu}</span>
        <div class="comp-main">
          <span class="comp-name">${escapeHtml(c.name)}</span>
          <span class="comp-sub"><span class="mono-tag">${escapeHtml(c.kind || 'service')}</span>${h.detail ? ' ' + escapeHtml(h.detail) : ''}</span>
        </div>
        <div class="comp-actions">
          ${compHealthBadge(h.state)}
          <button class="icon-btn comp-toggle" data-name="${escapeHtml(c.name)}" aria-expanded="${isExpanded}" title="Show metrics">${ICON.activity}</button>
          ${c.restartable ? `<button class="btn${armed ? ' danger' : ''}" data-restart="${escapeHtml(c.name)}" title="Briefly restarts this subsystem" ${restarting ? 'disabled' : ''}>
            ${ICON.power}<span>${restarting ? 'Restarting…' : armed ? 'Confirm restart?' : 'Restart'}</span></button>` : ''}
        </div>
      </div>
      <div class="comp-metrics" ${isExpanded ? '' : 'hidden'}>${metricsHtml}</div>
    </div>`;
  },
  async handleRestart(name) {
    // Restarting a live security subsystem has real effect (a brief gap in
    // that subsystem's coverage) — arm-then-confirm instead of firing on the
    // first click. State lives on the page object (not the DOM node), and
    // every render (poll or local) reads it, so a poll landing mid-confirm
    // can never silently reset a restart the user already armed.
    if (this.restartArmed !== name) {
      this.restartArmed = name;
      clearTimeout(this.armTimer);
      this.armTimer = setTimeout(() => {
        if (this.restartArmed === name) { this.restartArmed = null; this.renderList(); }
      }, 4000);
      this.renderList();
      return;
    }
    clearTimeout(this.armTimer); this.restartArmed = null;
    this.restarting = name;
    this.renderList();
    const res = await safe(() => V.api.post('/api/components/' + encodeURIComponent(name) + '/restart'), null);
    this.restarting = null;
    if (res && res.ok) toast(`${name} restarted.`, 'ok');
    else toast(`Could not restart ${name}${res && res.error ? ': ' + res.error : ''}.`, 'error');
    this.poll();
  },
};

function frameworkRefs(refs) { return (refs && refs.length) ? refs.join(' · ') : ''; }
function mttrText(minutes) {
  if (minutes == null) return '—';
  return minutes < 60 ? `${Math.round(minutes)}m` : fmtUptime(minutes * 60);
}

/* ---- Compliance ---- */
// Evidence, not certification — the backend (compliance.py) is explicit that
// it never claims compliance, only reports what actually happened, computed
// live with no hardcoded "OK" fields. The UI's job is to not lose that
// framing: the disclaimer ships from the API and is shown verbatim, first.
PAGES.compliance = {
  report: null,
  render() {
    $('page').innerHTML = `
      <div class="page-intro">Point-in-time operational evidence for auditors (SOC 2, ISO 27001, insurers) —
      generated live from what Valkyrie actually recorded. This is evidence toward the referenced controls,
      never a certification.</div>
      <div class="hunt-filters" style="margin-bottom:20px">
        <select class="rp-select" id="compPeriod" aria-label="Reporting period">
          <option value="24">Last 24 hours</option>
          <option value="168">Last 7 days</option>
          <option value="720" selected>Last 30 days</option>
          <option value="2160">Last 90 days</option>
        </select>
        <button class="btn" id="compCopyMd">${ICON.activity}<span>Copy as Markdown</span></button>
      </div>
      <div id="complianceBody"><div class="empty">Loading…</div></div>`;
    $('compPeriod').onchange = () => this.load();
    $('compCopyMd').onclick = () => this.copyMarkdown();
    this.load();
  },
  async load() {
    const box = $('complianceBody'); if (!box) return;
    if (!state.engineUp) {
      box.innerHTML = stateBlock('offline', 'Protection is off',
        'Compliance evidence is computed from live monitoring data — start protection to generate a report.');
      return;
    }
    box.innerHTML = '<div class="empty">Generating report…</div>';
    const hours = $('compPeriod').value;
    const report = await safe(() => V.api.get(`/api/compliance/report?hours=${hours}&format=json`), null);
    this.report = report;
    this.renderReport(report);
  },
  renderReport(r) {
    const box = $('complianceBody'); if (!box) return;
    if (!r || !r.sections) {
      box.innerHTML = stateBlock('error', 'Could not generate report', 'The compliance engine did not return a report.');
      return;
    }
    const s = r.sections;
    const mon = s.monitoring || {}, det = s.detection_response || {}, intel = s.threat_intel || {}, audit = s.audit_trail || {};
    const wiredRows = Object.entries(mon.components_wired || {})
      .map(([k, v]) => [escapeHtml(k), v ? badge('Wired', 'ok') : badge('Not wired', 'off'), 'cpu']);
    box.innerHTML = `
      <div class="comp-disclaimer">${escapeHtml(r.disclaimer || '')}</div>
      <div class="grid">
        <div class="card"><div class="label">${ICON.cpu}Components Wired</div>
          <div class="value">${fmt(mon.wired_count || 0)}<span class="unit">/ ${fmt(mon.component_total || 0)}</span></div></div>
        <div class="card"><div class="label">${ICON.alert}Incidents in Period</div><div class="value">${fmt(det.incidents_in_period || 0)}</div></div>
        <div class="card"><div class="label">${ICON.flame}Open High/Critical</div><div class="value">${fmt(det.open_high_or_critical || 0)}</div></div>
        <div class="card accent-green"><div class="label">${ICON.check}Median Time to Resolve</div><div class="value">${mttrText(det.median_time_to_resolve_minutes)}</div></div>
      </div>
      ${sectionHead('Detection &amp; Response', frameworkRefs(det.framework_refs))}
      ${det.available === false ? stateBlock('empty', 'EDR not available', '') : rowsPanel([
        ['Incidents in period', fmt(det.incidents_in_period || 0), 'alert'],
        ['Resolved', fmt(det.resolved_count || 0), 'check'],
        ['Open (high/critical)', fmt(det.open_high_or_critical || 0), 'flame'],
        ['Mean time to resolve', mttrText(det.mean_time_to_resolve_minutes), 'activity'],
      ])}
      ${sectionHead('Monitoring', frameworkRefs(mon.framework_refs))}
      ${wiredRows.length ? rowsPanel(wiredRows) : stateBlock('empty', 'No components reporting', '')}
      ${sectionHead('Threat Intelligence', frameworkRefs(intel.framework_refs))}
      ${intel.available === false ? stateBlock('empty', 'Threat intelligence not available', intel.error || '') : rowsPanel([
        ['Feeds tracked', fmt(Object.keys(intel.feeds || {}).length), 'globe'],
        ['Stale feeds', fmt((intel.stale_feeds || []).length), 'alert'],
      ])}
      ${sectionHead('Audit Trail', frameworkRefs(audit.framework_refs))}
      ${rowsPanel([
        ['Response actions audited', audit.response_audit_available ? badge('Yes', 'ok') : badge('No', 'off'), 'shield'],
      ])}`;
  },
  async copyMarkdown() {
    const btn = $('compCopyMd'); if (!btn) return;
    const span = btn.querySelector('span'); const original = span ? span.textContent : '';
    if (span) span.textContent = 'Copying…';
    btn.disabled = true;
    const hours = $('compPeriod').value;
    const md = await safe(() => V.api.getText(`/api/compliance/report?hours=${hours}&format=md`), null);
    btn.disabled = false;
    if (span) span.textContent = original;
    if (!md) { toast('Could not generate the report.', 'error'); return; }
    try {
      await navigator.clipboard.writeText(md);
      toast('Compliance report copied as Markdown.', 'ok');
    } catch {
      toast('Could not access the clipboard.', 'error');
    }
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

/* ============================ Toasts =================================
   One reusable, honest feedback surface for actions that don't already have
   somewhere to show their result (a button on the current page updates its
   own panel; an action run from the command palette has no visible panel at
   all). Stacked, auto-dismiss, screen-reader announced via aria-live.
   ========================================================================= */
function toastHost() {
  let host = $('toastHost');
  if (!host) {
    host = el('div', 'toast-host');
    host.id = 'toastHost'; host.setAttribute('aria-live', 'polite'); host.setAttribute('role', 'status');
    document.body.appendChild(host);
  }
  return host;
}
function toast(message, kind) {
  const host = toastHost();
  const node = el('div', 'toast ' + (kind || 'ok'),
    `<span class="toast-ic">${kind === 'error' ? ICON.alert : ICON.check}</span><span class="toast-msg"></span>`);
  node.querySelector('.toast-msg').textContent = message;
  host.appendChild(node);
  requestAnimationFrame(() => node.classList.add('show'));
  const kill = () => { node.classList.remove('show'); setTimeout(() => node.remove(), 220); };
  setTimeout(kill, 3600);
  node.onclick = kill;
}

/* ============================ Shared quick actions ====================
   Named, reusable functions (not per-page closures) so the exact same logic
   runs whether triggered from a page's button or from the command palette —
   no duplicated action logic, one source of truth per action.
   ========================================================================= */
async function toggleMeetingMode() {
  if (!V) return;
  const m = await safe(() => V.api.get('/api/meeting/status'), {});
  const turningOn = !(m && m.active);
  await safe(() => V.api.post(turningOn ? '/api/meeting/start' : '/api/meeting/stop'), null);
  toast(turningOn ? 'Meeting mode on — alerts stay quiet while you present.' : 'Meeting mode off.', 'ok');
}
async function killTelemetry() {
  if (!V) return;
  await safe(() => V.api.post('/api/telemetry/kill'), null);
  toast('Windows telemetry settings locked down.', 'ok');
  if (PAGES.privacy.poll) PAGES.privacy.poll();
}
async function randomizeMac() {
  if (!V) return;
  await safe(() => V.api.post('/api/mac/randomize'), null);
  toast('Network adapter MAC address randomized.', 'ok');
  if (PAGES.privacy.poll) PAGES.privacy.poll();
}

/* ============================ Live topbar =========================== */
// `on` (armed/disarmed) and `up` (did the engine actually answer this poll)
// are independent facts — armed is a filesystem marker, up is live telemetry.
// The toggle affordance (orb glow, START/STOP label) tracks the real armed
// state either way, since that's true regardless of whether stats loaded.
// The status TEXT must not claim "Protected" on a poll that has no data to
// back it — that reads as reassurance the app cannot support.
function setProtectionUI(on, up) {
  const wrap = $('orbWrap'), label = $('orbLabel'), pill = $('statusPill'), txt = $('statusText');
  if (wrap) wrap.classList.toggle('on', on);
  if (label && !state.busy) label.textContent = on ? 'STOP PROTECTION' : 'START PROTECTION';
  if (pill) pill.classList.toggle('on', on);
  if (txt) txt.textContent = !up ? 'No data' : (on ? 'Protected' : 'Not protected');
}
function updateTopbar(data) {
  const s = (data && data.stats) || {}, up = !!(data && data.ok), prot = !!(data && data.protected);
  state.engineUp = up; state.protected = prot;
  $('tbStatus').textContent = !up ? 'No data' : (prot ? 'Protected' : 'Standby');
  $('tbStatus').style.color = (up && prot) ? 'var(--text-0)' : 'var(--text-1)';
  // A failed poll leaves data.stats null, so `s` falls back to {} and every
  // lookup below yields 0. Rendering that as "0" is a lie: it reads as "we
  // checked and nothing was blocked", when the truth is "we could not reach
  // the engine this tick". The counter is cumulative and never legitimately
  // returns to 0 once it has moved, so a 0 here is ALWAYS a failed poll --
  // that is the "numbers drop to zero and come back" flicker. Guard it with
  // `up` exactly like its two siblings already were.
  $('tbBlocked').textContent = up ? fmt((s.dns_blocked || 0) + (s.fw_blocked || 0)) : '—';
  $('tbPrivacy').textContent = up ? privacyScore(s, up) : '—';
  $('tbUptime').textContent = up ? fmtUptime(s.uptime_seconds) : '—';
}

/* ============================ Replay Mode ===========================
   Opens an incident and replays its correlated telemetry step-by-step —
   the attack chain, MITRE techniques, and evidence unfolding in sequence.
   Driven by the REAL /api/edr/incidents/{id} timeline; no synthetic data.
   =================================================================== */
const RP_ICON = {
  play: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M8 5.14v13.72L19 12 8 5.14z"/></svg>',
  pause: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M7 5h3v14H7zM14 5h3v14h-3z"/></svg>',
  prev: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M7 5h2v14H7zM19 5 9 12l10 7V5z"/></svg>',
  next: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M15 5h2v14h-2zM5 5l10 7L5 19V5z"/></svg>',
  restart: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/></svg>',
  x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>',
};

function rpTime(v) {
  if (v == null || v === '') return '';
  let d;
  if (typeof v === 'number' || /^\d+(\.\d+)?$/.test(v)) {
    let ms = Number(v); if (ms < 1e12) ms *= 1000; d = new Date(ms);
  } else { d = new Date(v); }
  return isNaN(d.getTime()) ? String(v) : d.toTimeString().slice(0, 8);
}
function rpSevClass(s) {
  s = String(s || '').toLowerCase();
  return /crit/.test(s) ? 'critical' : /high/.test(s) ? 'high'
    : /med/.test(s) ? 'medium' : /low/.test(s) ? 'low' : '';
}
function rpTech(t) { const m = String(t || '').match(/T\d{4}(?:\.\d{3})?/); return m ? m[0] : ''; }

function normalizeSteps(inc) {
  let tl = (inc && (inc.timeline || inc.events)) || [];
  if (!Array.isArray(tl)) tl = [];
  const steps = tl.map((t) => ({
    t: t.timestamp != null ? t.timestamp : (t.ts != null ? t.ts : t.time),
    sev: rpSevClass(t.severity),
    title: t.title || t.reason || t.activity || t.source || 'Event',
    entity: t.entity || t.target || '',
    tech: rpTech(t.technique),
    techLabel: t.technique || '',
    source: t.source || '',
  }));
  // Ascending by time when timestamps are present.
  if (steps.every((s) => s.t != null)) {
    steps.sort((a, b) => rpTime(a.t) < rpTime(b.t) ? -1 : 1);
  }
  if (!steps.length && inc) {
    steps.push({ t: inc.created || inc.timestamp, sev: rpSevClass(inc.severity),
      title: inc.title || 'Incident', entity: inc.entity || '',
      tech: rpTech(inc.technique), techLabel: inc.technique || '', source: '' });
  }
  return steps;
}

// The incident lifecycle the engine actually models (valkyrie/edr/schema.py
// INCIDENT_STATES) — a fixed, documented enum, not invented UI vocabulary.
const INCIDENT_STATES = ['open', 'investigating', 'contained', 'resolved', 'dismissed'];

const Replay = {
  steps: [], idx: 0, playing: false, speed: 1, timer: null, root: null, keyHandler: null,
  report: null, releaseFocusTrap: null, opener: null, BASE: 1150,

  async open(id) {
    this.close();
    this.opener = document.activeElement;
    const scrim = el('div', 'rp-scrim');
    scrim.innerHTML = `<div class="rp"><div class="rp-body" style="grid-template-columns:1fr">
      <div class="rp-stage"><div class="empty" style="padding:40px 0">Loading replay…</div></div></div></div>`;
    scrim.addEventListener('click', (e) => { if (e.target === scrim) this.close(); });
    document.body.appendChild(scrim);
    this.root = scrim;
    const inc = await safe(() => V.api.get('/api/edr/incidents/' + id), null);
    if (this.root !== scrim) return;               // closed while loading
    this.mount(inc || { id, title: 'Incident' }, normalizeSteps(inc));
  },

  mount(inc, steps) {
    this.inc = inc; this.steps = steps; this.idx = 0; this.playing = false; this.speed = 1;
    this.report = null;
    const sev = rpSevClass(inc.severity);
    const chain = steps.map((s, i) => `
      <div class="rp-ev" data-sev="${s.sev}" data-i="${i}">
        <span class="rp-node"></span>
        <div class="rp-row1"><span class="rp-time">${escapeHtml(rpTime(s.t) || ('step ' + (i + 1)))}</span>
          <span class="rp-ttl">${escapeHtml(s.title)}</span>
          ${s.tech ? `<span class="rp-chip">${escapeHtml(s.tech)}</span>` : ''}</div>
        <div class="rp-desc">${s.entity ? `<span class="m">${escapeHtml(s.entity)}</span>` : ''}${s.source ? `${s.entity ? ' · ' : ''}${escapeHtml(s.source)}` : ''}</div>
      </div>`).join('');
    // Ordered unique techniques and the step each first appears.
    const seen = {}; this.techList = [];
    steps.forEach((s, i) => { if (s.tech && !(s.tech in seen)) { seen[s.tech] = i; this.techList.push({ id: s.tech, label: s.techLabel, at: i }); } });
    const techHtml = this.techList.length ? this.techList.map((t) =>
      `<div class="rp-tech" data-at="${t.at}"><span class="rp-tid off">${escapeHtml(t.id)}</span><span>${escapeHtml((t.label || '').replace(/^T\d{4}(?:\.\d{3})?\s*[—-]?\s*/, '') || t.id)}</span></div>`).join('')
      : '<div class="rp-desc" style="opacity:.6">No MITRE techniques mapped.</div>';

    this.root.innerHTML = `<div class="rp">
      <div class="rp-head">
        <div class="rp-tt"><h3>${escapeHtml(inc.title || 'Incident')}</h3>
          <div class="rp-meta"><span class="sev ${sev}">${escapeHtml(sev || (inc.status || 'incident'))}</span>
            <span>${escapeHtml(String(inc.id || ''))}</span><span>·</span><span>${steps.length} steps replayed</span></div>
          ${renderImpactLine(inc.impact)}</div>
        <button class="rp-x" data-a="close">${RP_ICON.x}</button>
      </div>
      <div class="rp-body">
        <div class="rp-stage"><div class="rp-chain">${chain}</div></div>
        <div class="rp-side">
          <div class="rp-tabs" role="tablist">
            <button class="rp-tab active" id="rptab-playback" role="tab" aria-selected="true" data-tab="playback">Playback</button>
            <button class="rp-tab" id="rptab-investigate" role="tab" aria-selected="false" data-tab="investigate">Investigation</button>
          </div>
          <div class="rp-tabpane" data-pane="playback" role="tabpanel" aria-labelledby="rptab-playback">
            <div class="rp-sec">Current step</div>
            <div class="rp-now"><div class="rp-now-t"></div><div class="rp-now-h"></div><div class="rp-now-d"></div></div>
            <div class="rp-sec">MITRE ATT&amp;CK — observed</div>
            <div class="rp-techs">${techHtml}</div>
          </div>
          <div class="rp-tabpane" data-pane="investigate" role="tabpanel" aria-labelledby="rptab-investigate" hidden>
            <div id="rpInv"></div>
          </div>
        </div>
      </div>
      <div class="rp-ctrl">
        <div class="rp-btns">
          <button class="rp-b" data-a="restart" title="Restart">${RP_ICON.restart}</button>
          <button class="rp-b" data-a="prev" title="Step back">${RP_ICON.prev}</button>
          <button class="rp-b play" data-a="toggle" title="Play / pause (space)">${RP_ICON.play}</button>
          <button class="rp-b" data-a="next" title="Step forward">${RP_ICON.next}</button>
        </div>
        <div class="rp-track"><div class="rp-fill"></div></div>
        <span class="rp-count"></span>
        <div class="rp-speed">
          <button class="rp-sp on" data-s="1">1×</button>
          <button class="rp-sp" data-s="2">2×</button>
          <button class="rp-sp" data-s="4">4×</button>
        </div>
      </div></div>`;

    this.root.querySelectorAll('[data-a]').forEach((b) => b.onclick = () => {
      const a = b.dataset.a;
      if (a === 'close') this.close();
      else if (a === 'toggle') this.toggle();
      else if (a === 'next') { this.pause(); this.seek(this.idx + 1); }
      else if (a === 'prev') { this.pause(); this.seek(this.idx - 1); }
      else if (a === 'restart') { this.pause(); this.seek(0); }
    });
    this.root.querySelectorAll('.rp-sp').forEach((b) => b.onclick = () => this.setSpeed(Number(b.dataset.s)));
    this.root.querySelectorAll('.rp-tab').forEach((b) => b.onclick = () => this.switchTab(b.dataset.tab));
    const track = this.root.querySelector('.rp-track');
    track.onclick = (e) => {
      const r = track.getBoundingClientRect();
      const frac = Math.max(0, Math.min(1, (e.clientX - r.left) / r.width));
      this.pause(); this.seek(Math.round(frac * (this.steps.length - 1)));
    };
    this.keyHandler = (e) => {
      if (e.key === 'Escape') { this.close(); return; }
      // The Investigation tab has real text fields (assignee, notes) — space
      // and the arrow keys must behave like normal text editing there, not
      // hijack playback. Transport shortcuts only apply when nothing is
      // being typed into.
      const t = e.target;
      const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
      if (typing) return;
      if (e.key === ' ') { e.preventDefault(); this.toggle(); }
      else if (e.key === 'ArrowRight') { this.pause(); this.seek(this.idx + 1); }
      else if (e.key === 'ArrowLeft') { this.pause(); this.seek(this.idx - 1); }
    };
    document.addEventListener('keydown', this.keyHandler);
    this.releaseFocusTrap = trapFocus(this.root);
    const closeBtn = this.root.querySelector('.rp-x');
    if (closeBtn) closeBtn.focus();

    this.update();
    if (this.steps.length > 1) this.timer = setTimeout(() => this.play(), 400);
  },

  update() {
    const n = this.steps.length, s = this.steps[this.idx] || {};
    this.root.querySelectorAll('.rp-ev').forEach((ev) => {
      const i = Number(ev.dataset.i);
      ev.classList.toggle('shown', i <= this.idx);
      ev.classList.toggle('active', i === this.idx);
      if (i === this.idx) ev.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    });
    const now = this.root.querySelector('.rp-now');
    now.querySelector('.rp-now-t').textContent = rpTime(s.t) || ('Step ' + (this.idx + 1));
    now.querySelector('.rp-now-h').textContent = s.title || '';
    now.querySelector('.rp-now-d').innerHTML = (s.entity ? `<span style="font-family:ui-monospace,Consolas,monospace">${escapeHtml(s.entity)}</span>` : '')
      + (s.techLabel ? `${s.entity ? '<br>' : ''}${escapeHtml(s.techLabel)}` : '');
    this.root.querySelectorAll('.rp-tech').forEach((t) => {
      const on = Number(t.dataset.at) <= this.idx;
      t.classList.toggle('hit', on);
      const tid = t.querySelector('.rp-tid'); if (tid) tid.classList.toggle('off', !on);
    });
    this.root.querySelector('.rp-fill').style.width = (n > 1 ? (this.idx / (n - 1)) * 100 : 100) + '%';
    this.root.querySelector('.rp-count').textContent = `${this.idx + 1} / ${n}`;
    this.root.querySelector('.rp-b.play').innerHTML = this.playing ? RP_ICON.pause : RP_ICON.play;
  },

  seek(i) {
    this.idx = Math.max(0, Math.min(this.steps.length - 1, i));
    this.update();
  },
  toggle() { this.playing ? this.pause() : this.play(); },
  play() {
    if (this.steps.length <= 1) return;
    if (this.idx >= this.steps.length - 1) this.idx = 0;   // replay from start
    this.playing = true; this.update(); this._tick();
  },
  _tick() {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      if (!this.playing) return;
      if (this.idx >= this.steps.length - 1) { this.pause(); return; }
      this.idx += 1; this.update(); this._tick();
    }, this.BASE / this.speed);
  },
  pause() { this.playing = false; clearTimeout(this.timer); if (this.root) this.update(); },
  setSpeed(x) {
    this.speed = x;
    this.root.querySelectorAll('.rp-sp').forEach((b) => b.classList.toggle('on', Number(b.dataset.s) === x));
  },
  close() {
    clearTimeout(this.timer); this.timer = null; this.playing = false;
    if (this.keyHandler) { document.removeEventListener('keydown', this.keyHandler); this.keyHandler = null; }
    if (this.releaseFocusTrap) { this.releaseFocusTrap(); this.releaseFocusTrap = null; }
    if (this.root && this.root.parentNode) this.root.parentNode.removeChild(this.root);
    this.root = null; this.report = null;
    if (this.opener && this.opener.focus) this.opener.focus();
    this.opener = null;
  },

  /* -------------------------- Investigation tab --------------------------
     Wires the already-shipped explainability + triage backend
     (edr/investigate.py, POST .../status) into the one incident-detail
     surface the app has, instead of a second modal. Offline analysis loads
     by default (no network call); the AI narrative is a separate, explicit
     opt-in click, matching the app's opt-in-AI stance elsewhere. */
  switchTab(tab) {
    this.root.querySelectorAll('.rp-tab').forEach((b) => {
      const on = b.dataset.tab === tab;
      b.classList.toggle('active', on); b.setAttribute('aria-selected', String(on));
    });
    this.root.querySelectorAll('.rp-tabpane').forEach((p) => { p.hidden = p.dataset.pane !== tab; });
    if (tab === 'investigate' && !this.report) this.loadInvestigation(false);
  },

  async loadInvestigation(useAi) {
    const box = this.root && this.root.querySelector('#rpInv'); if (!box) return;
    box.innerHTML = `<div class="empty" style="padding:20px 0">${useAi ? 'Asking the AI provider…' : 'Loading investigation…'}</div>`;
    const incId = this.inc.id;
    const rep = await safe(() => V.api.post('/api/edr/incidents/' + incId + '/investigate', { use_ai: !!useAi }), null);
    if (!this.root || this.inc.id !== incId) return;   // closed, or a different incident opened meanwhile
    this.report = rep;
    this.renderInvestigation();
  },

  renderInvestigation() {
    const box = this.root && this.root.querySelector('#rpInv'); if (!box) return;
    const r = this.report;
    if (!r) {
      box.innerHTML = stateBlock('error', 'Investigation unavailable',
        'Could not reach the engine for an analysis of this incident.');
      return;
    }
    // Found during a wiring audit (2026-07-30): this panel already computes
    // and DISPLAYS the recommended response (edr/investigate.py), but nothing
    // here ever called POST /api/edr/respond — the one endpoint that actually
    // isolates a host, kills a process, or blocks a domain. An analyst could
    // read "isolate_host recommended" and had no button to do it; the only
    // action reachable from the UI was relabeling the incident's status.
    // Wired to the real, existing action vocabulary (edr/response.py:
    // block_domain / unblock_domain / kill_process / isolate_host /
    // release_isolation) via the same dry-run-first, explicit-second-click
    // pattern this file already uses for the AI narrative just above.
    const actions = (r.recommended_actions || []).map((a, i) => `
      <div class="rp-rec">
        <div class="rp-rec-head"><span class="mono-tag">${escapeHtml(a.action || '')}</span>${a.target ? `<span class="rp-rec-t">${escapeHtml(a.target)}</span>` : ''}</div>
        <div class="rp-desc">${escapeHtml(a.rationale || '')}</div>
        ${a.action ? `
        <div class="rp-respond" data-idx="${i}">
          <button class="btn" data-respond-preview="${i}">${ICON.activity}<span>Preview what this would do</span></button>
          <div class="rp-respond-result" hidden></div>
        </div>` : ''}
      </div>`).join('')
      || '<div class="rp-desc" style="opacity:.6">No specific response action recommended.</div>';

    const aiBtn = (r.ai_available && !r.ai_narrative)
      ? `<button class="btn" id="rpAskAi" style="margin-top:4px">${ICON.brain}<span>Ask AI for a deeper narrative</span></button>` : '';
    const aiBlock = r.ai_narrative
      ? `<div class="rp-sec" style="margin-top:16px">AI narrative — ${escapeHtml(r.analyst || 'ai')}</div>
         <div class="rp-desc">${escapeHtml(r.ai_narrative)}</div>` : '';
    const aiErr = r.ai_error ? `<div class="rp-desc" style="opacity:.75;margin-top:8px">${escapeHtml(r.ai_error)}</div>` : '';

    const statusVal = this.inc.status || 'open';
    box.innerHTML = `
      <div class="rp-sec">What happened</div>
      <div class="rp-desc">${escapeHtml(r.summary || 'No summary available.')}</div>
      <div class="rp-sec" style="margin-top:16px">Why it matters</div>
      <div class="rp-desc">${escapeHtml(r.meaning || '—')}</div>
      <div class="rp-sec" style="margin-top:16px">Recommended response</div>
      ${actions}
      ${aiBtn}${aiBlock}${aiErr}
      <div class="rp-sec" style="margin-top:18px">Triage</div>
      <div class="rp-triage">
        <label class="rp-field"><span>Status</span>
          <select class="rp-select" id="rpStatus">${INCIDENT_STATES.map((s) =>
            `<option value="${s}"${s === statusVal ? ' selected' : ''}>${s.charAt(0).toUpperCase() + s.slice(1)}</option>`).join('')}
          </select>
        </label>
        <label class="rp-field"><span>Assignee</span>
          <input class="rp-input" id="rpAssignee" value="${escapeHtml(this.inc.assignee || '')}" placeholder="Unassigned" />
        </label>
        <label class="rp-field"><span>Notes</span>
          <textarea class="rp-textarea" id="rpNotes" rows="3" placeholder="Analyst notes…">${escapeHtml(this.inc.notes || '')}</textarea>
        </label>
        <button class="btn primary" id="rpSaveTriage">${ICON.check}<span>Save Triage</span></button>
      </div>`;

    const askBtn = box.querySelector('#rpAskAi');
    if (askBtn) askBtn.onclick = () => this.loadInvestigation(true);
    const saveBtn = box.querySelector('#rpSaveTriage');
    if (saveBtn) saveBtn.onclick = () => this.saveTriage();

    const recs = r.recommended_actions || [];
    box.querySelectorAll('[data-respond-preview]').forEach((btn) => {
      const idx = Number(btn.dataset.respondPreview);
      const rec = recs[idx];
      if (!rec || !rec.action) return;
      btn.onclick = () => this.respondPreview(rec, btn);
    });
  },

  // Step 1: dry_run — shows exactly what would happen, commits nothing. This
  // mirrors edr/response.py's own stated contract ("dry-run by default, a
  // real action must be explicitly requested") one level up into the UI,
  // rather than only trusting the backend default silently.
  async respondPreview(rec, btn) {
    const wrap = btn.closest('.rp-respond');
    const out = wrap.querySelector('.rp-respond-result');
    btn.disabled = true;
    const res = await safe(() => V.api.post('/api/edr/respond', {
      action: rec.action, target: rec.target || '', incident_id: this.inc.id, dry_run: true,
    }), null);
    btn.disabled = false;
    if (!res) {
      out.hidden = false;
      out.innerHTML = `<div class="rp-desc" style="opacity:.75">Could not reach the engine to preview this action.</div>`;
      return;
    }
    out.hidden = false;
    out.innerHTML = `
      <div class="rp-desc">${escapeHtml(res.result || res.status || 'Previewed.')}</div>
      <button class="btn primary" data-respond-confirm>${ICON.check}<span>Confirm — apply for real</span></button>`;
    btn.remove();
    const confirmBtn = out.querySelector('[data-respond-confirm]');
    confirmBtn.onclick = () => this.respondExecute(rec, confirmBtn, out);
  },

  // Step 2: the real thing. Only reachable after a preview has already run
  // for this exact card, and the button that triggers it is removed the
  // moment it is clicked once, so a double-click cannot double-fire a real
  // isolate/kill action.
  async respondExecute(rec, btn, out) {
    btn.disabled = true; btn.remove();
    const res = await safe(() => V.api.post('/api/edr/respond', {
      action: rec.action, target: rec.target || '', incident_id: this.inc.id, dry_run: false,
    }), null);
    if (res && res.status && res.status !== 'failed') {
      out.innerHTML += `<div class="rp-desc" style="margin-top:6px">${escapeHtml(res.result || res.status)}</div>`;
      toast(`${rec.action} applied.`, 'ok');
    } else {
      out.innerHTML += `<div class="rp-desc" style="margin-top:6px;opacity:.85">${escapeHtml((res && res.result) || 'The action did not complete — check logs.')}</div>`;
      toast(`${rec.action} failed — see incident log.`, 'error');
    }
  },

  async saveTriage() {
    const box = this.root && this.root.querySelector('#rpInv'); if (!box) return;
    const status = box.querySelector('#rpStatus').value;
    const assignee = box.querySelector('#rpAssignee').value.trim();
    const notes = box.querySelector('#rpNotes').value;
    const saveBtn = box.querySelector('#rpSaveTriage');
    if (saveBtn) saveBtn.disabled = true;
    const updated = await safe(() => V.api.post('/api/edr/incidents/' + this.inc.id + '/status',
      { status, assignee, notes }), null);
    if (saveBtn) saveBtn.disabled = false;
    if (updated && updated.id) {
      this.inc = updated;
      toast('Incident triage saved.', 'ok');
    } else {
      toast('Could not save triage — is protection running?', 'error');
    }
  },
};
function openReplay(id) { Replay.open(id); }

/* ============================ Command Palette (Ctrl+K) ===============
   Global search + quick actions. Ranking/grouping is pure CommandIndex
   logic (unit tested in command-index.test.js); this object is only the
   DOM binding — open/close, keyboard nav, painting results. Reuses the
   same shared action functions (toggleProtection, toggleMeetingMode, …)
   the pages themselves call, so running a command here is never a
   second implementation of what a button already does.
   ========================================================================= */
function buildBaseCommands() {
  const cmds = NAV.map(([id, label, icon]) =>
    ({ id: 'nav:' + id, group: 'Navigate', label, icon, run: () => route(id) }));
  cmds.push(
    { id: 'act:toggle-protection', group: 'Actions',
      label: state.protected ? 'Stop Protection' : 'Start Protection',
      icon: 'power', keywords: ['start', 'stop', 'engine'], run: toggleProtection },
    { id: 'act:meeting', group: 'Actions', label: 'Toggle Meeting Mode',
      icon: 'lock', keywords: ['quiet', 'presenting', 'mute alerts'], run: toggleMeetingMode },
    { id: 'act:kill-telemetry', group: 'Actions', label: 'Kill Windows Telemetry',
      icon: 'shield', keywords: ['privacy'], run: killTelemetry },
    { id: 'act:randomize-mac', group: 'Actions', label: 'Randomize MAC Address',
      icon: 'network', keywords: ['privacy', 'identity'], run: randomizeMac },
    { id: 'act:open-logs', group: 'Actions', label: 'Open Logs Folder',
      icon: 'activity', keywords: ['debug', 'diagnostics'], run: () => V && V.openLogs() },
  );
  return cmds;
}
// Recent incidents, fetched fresh each time the palette opens — read-only,
// same endpoint the Threats page already uses. Empty (not faked) if the
// engine isn't reporting or there's nothing to show.
async function fetchIncidentCommands() {
  if (!V || !state.engineUp) return [];
  const raw = await safe(() => V.api.get('/api/edr/incidents'), []);
  const arr = Array.isArray(raw) ? raw : (raw.incidents || []);
  return arr.slice(0, 25).map((i) => ({
    id: 'inc:' + (i.id || ''), group: 'Recent Incidents',
    label: i.title || i.name || i.rule || 'Incident',
    hint: (i.technique || '').toString().match(/T\d{4}(?:\.\d{3})?/)?.[0] || '',
    keywords: [i.entity, i.host, i.status, i.severity].filter(Boolean),
    icon: 'alert', run: () => openReplay(i.id),
  }));
}

const CommandPalette = {
  root: null, keyHandler: null, releaseFocusTrap: null, opener: null,
  base: [], incidents: [], groups: [], display: [], active: 0,

  toggle() { this.root ? this.close() : this.open(); },

  open() {
    if (this.root) { this.focusInput(); return; }
    this.opener = document.activeElement;
    this.base = buildBaseCommands();
    this.incidents = [];
    this.mount();
    this.filter('');
    fetchIncidentCommands().then((inc) => {
      if (!this.root) return; // closed before the fetch resolved
      this.incidents = inc;
      this.filter(this.root.querySelector('.cmdk-input').value);
    });
  },

  mount() {
    const scrim = el('div', 'cmdk-scrim');
    scrim.innerHTML = `<div class="cmdk" role="dialog" aria-label="Command palette">
      <div class="cmdk-inputwrap">${ICON.search}
        <input class="cmdk-input" placeholder="Search pages, actions and recent incidents…" autocomplete="off"
          spellcheck="false" role="combobox" aria-expanded="true" aria-controls="cmdkResults" aria-autocomplete="list" />
        <span class="cmdk-esc">ESC</span>
      </div>
      <div class="cmdk-results" id="cmdkResults" role="listbox"></div>
      <div class="cmdk-footer">
        <span><span class="cmdk-key">&uarr;&darr;</span> Navigate</span>
        <span><span class="cmdk-key">&crarr;</span> Select</span>
        <span><span class="cmdk-key">Esc</span> Close</span>
      </div>
    </div>`;
    scrim.addEventListener('mousedown', (e) => { if (e.target === scrim) this.close(); });
    document.body.appendChild(scrim);
    this.root = scrim;

    const input = scrim.querySelector('.cmdk-input');
    input.addEventListener('input', () => this.filter(input.value));
    this.keyHandler = (e) => {
      if (e.key === 'Escape') { e.preventDefault(); this.close(); }
      else if (e.key === 'ArrowDown') { e.preventDefault(); this.move(1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); this.move(-1); }
      else if (e.key === 'Enter') { e.preventDefault(); this.runActive(); }
    };
    document.addEventListener('keydown', this.keyHandler);
    this.releaseFocusTrap = trapFocus(scrim);
  },

  focusInput() {
    const input = this.root && this.root.querySelector('.cmdk-input');
    if (input) { input.value = ''; input.focus(); }
  },

  filter(q) {
    const ranked = CommandIndex.filterCommands(q, this.base.concat(this.incidents));
    this.groups = CommandIndex.groupCommands(ranked);
    this.display = this.groups.flatMap((g) => g.items);
    this.active = 0;
    this.paint();
  },

  paint() {
    const box = this.root && this.root.querySelector('.cmdk-results'); if (!box) return;
    if (!this.display.length) {
      box.innerHTML = stateBlock('empty', 'No matches', 'Try a page name, an action, or an incident title.');
      return;
    }
    let i = 0;
    box.innerHTML = this.groups.map((g) => `
      <div class="cmdk-group">${escapeHtml(g.group)}</div>
      ${g.items.map((c) => {
        const idx = i++;
        return `<div class="cmdk-item${idx === this.active ? ' active' : ''}" id="cmdk-opt-${idx}"
          data-i="${idx}" role="option" aria-selected="${idx === this.active}">
          <span class="cmdk-item-ic">${ICON[c.icon] || ICON.check}</span>
          <span class="cmdk-item-label">${escapeHtml(c.label)}</span>
          ${c.hint ? `<span class="mono-tag">${escapeHtml(c.hint)}</span>` : ''}
        </div>`;
      }).join('')}`).join('');
    box.querySelectorAll('.cmdk-item').forEach((n) => {
      n.onclick = () => { this.active = Number(n.dataset.i); this.runActive(); };
      n.onmouseenter = () => { this.active = Number(n.dataset.i); this.highlight(); };
    });
    this.highlight();
  },

  highlight() {
    const box = this.root && this.root.querySelector('.cmdk-results'); if (!box) return;
    box.querySelectorAll('.cmdk-item').forEach((n) => {
      const on = Number(n.dataset.i) === this.active;
      n.classList.toggle('active', on);
      n.setAttribute('aria-selected', String(on));
    });
    const input = this.root.querySelector('.cmdk-input');
    if (input) input.setAttribute('aria-activedescendant', 'cmdk-opt-' + this.active);
    const on = box.querySelector('.cmdk-item.active');
    if (on) on.scrollIntoView({ block: 'nearest' });
  },

  move(delta) {
    if (!this.display.length) return;
    this.active = (this.active + delta + this.display.length) % this.display.length;
    this.highlight();
  },

  runActive() {
    const cmd = this.display[this.active];
    if (!cmd) return;
    this.close();
    try { cmd.run && cmd.run(); } catch {}
  },

  close() {
    if (this.keyHandler) { document.removeEventListener('keydown', this.keyHandler); this.keyHandler = null; }
    if (this.releaseFocusTrap) { this.releaseFocusTrap(); this.releaseFocusTrap = null; }
    if (this.root && this.root.parentNode) this.root.parentNode.removeChild(this.root);
    this.root = null; this.groups = []; this.display = []; this.active = 0;
    if (this.opener && this.opener.focus) this.opener.focus();
    this.opener = null;
  },
};

/* ============================ Boot ================================== */
async function init() {
  buildChrome();
  PAGES.dashboard.render();
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); CommandPalette.toggle(); }
  });
  if (V) {
    V.onTelemetry((data) => {
      state.tele = data;
      updateTopbar(data);
      const page = PAGES[state.route];
      if (page && page.onTele) page.onTele(data);
    });
    // An explicit startPage (deep link / notification click) wins; otherwise
    // reopen on whatever page the analyst was last looking at.
    V.appInfo().then((info) => {
      const target = (info && info.startPage) || loadLastRoute();
      if (target && target !== 'dashboard') route(target);
    }).catch(() => {});
  }

  // Pick the boot experience: a deliberate setup sequence for a fresh install /
  // upgrade / repair, or the quick cinematic on a normal launch.
  let info = { scenario: 'normal' };
  if (V) { try { info = await V.lifecycleInfo(); } catch {} }
  if (info.scenario && info.scenario !== 'normal') await runSetupSplash(info.scenario);
  else await runSplashNormal();
}
document.addEventListener('DOMContentLoaded', init);
