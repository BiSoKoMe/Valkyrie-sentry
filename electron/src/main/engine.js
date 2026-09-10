'use strict';
// ---------------------------------------------------------------------------
// engine.js - lifecycle + telemetry bridge for the Python security engine.
//
// The Electron shell NEVER contains security logic. This module only:
//   * asks the already-shipped engine to start / stop (via the no-prompt
//     ValkyrieStart / ValkyrieStop scheduled tasks the installer registers,
//     falling back to start_all.ps1 / stop_all.ps1 in a source checkout), and
//   * reads the engine's local HTTP API (loopback) so the UI can render.
//
// All HTTP happens here in the Node main process, not the renderer - that way
// there is no cross-origin/localhost page anywhere in the product; the renderer
// only ever receives already-parsed JSON over IPC.
// ---------------------------------------------------------------------------

const { net } = require('electron');
// Resolved through the module object rather than destructured at load so the
// lifecycle tests can substitute schtasks/PowerShell. Destructuring captures
// the reference before any test can replace it, and child_process is a
// builtin, so the require.cache fake used for 'electron' cannot reach it.
const childProcess = require('child_process');
const path = require('path');
const fs = require('fs');
const lifecycle = require('./lifecycle');

const WEB_PORT = 8090;
const HOST = '127.0.0.1';

const SYS32 = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32');
const SCHTASKS = path.join(SYS32, 'schtasks.exe');
const POWERSHELL = path.join(SYS32, 'WindowsPowerShell', 'v1.0', 'powershell.exe');

// ---------------------------------------------------------------------------
// Install-layout discovery. When packaged, the engine + scripts live in
// resources\engine next to the app; in a source checkout they live at the repo
// root (two levels up from electron\src\main).
// ---------------------------------------------------------------------------
function engineRoot() {
  const packaged = path.join(process.resourcesPath || '', 'engine');
  if (fs.existsSync(path.join(packaged, 'start_all.ps1'))) return packaged;
  const repo = path.resolve(__dirname, '..', '..', '..');
  return repo;
}

function scriptPath(name) {
  return path.join(engineRoot(), name);
}

// Writable state location - single source of truth in lifecycle.js (mirrors
// valkyrie/config.py: %ProgramData%\Valkyrie installed, beside-exe portable,
// repo data/ in dev).
function dataDir() { return lifecycle.engineDataDir(); }

// Path to the bundled frozen engine (packaged / portable builds).
function bundledEngineExe() {
  return path.join(process.resourcesPath || '', 'engine', 'valkyrie.exe');
}

// Portable build: no service, no admin, no DNS takeover - just run the engine
// as a child so the dashboard works with all state kept beside the exe.
let _portableChild = null;
function ensurePortableEngine() {
  const exe = bundledEngineExe();
  if (!fs.existsSync(exe)) return false;
  if (_portableChild && !_portableChild.killed) return true;
  _portableChild = childProcess.spawn(
    exe, ['--web', '--no-ui', '--web-port', String(WEB_PORT)],
    { detached: false, stdio: 'ignore', windowsHide: true, env: lifecycle.engineEnv() }
  );
  _portableChild.on('exit', () => { _portableChild = null; });
  return true;
}
function stopPortableEngine() {
  if (_portableChild && !_portableChild.killed) {
    try { _portableChild.kill(); } catch {}
    _portableChild = null;
  }
}

// ---------------------------------------------------------------------------
// Low-level HTTP against the loopback API - built on Electron's `net` module
// (Chromium's network stack), NOT Node's built-in `http`. This is load-bearing:
// on a machine running the Valkyrie engine's own traffic filtering, raw
// Winsock connections (Node's http/net, curl, anything using plain sockets)
// to 127.0.0.1:WEB_PORT get silently black-holed - TCP connects instantly,
// the request is sent, and then nothing ever comes back, forever, until the
// caller's own timeout fires. WinHTTP-based clients (PowerShell, .NET) are
// unaffected and answer in well under a second. Electron's `net` module goes
// through the same OS network stack those do and is equally unaffected, so it
// is used here instead of `http`, not merely as a style preference.
// ---------------------------------------------------------------------------
function netGet(pathname, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = net.request({ method: 'GET', protocol: 'http:', hostname: HOST, port: WEB_PORT, path: pathname });
    let settled = false;
    const finish = (fn, arg) => { if (settled) return; settled = true; clearTimeout(timer); fn(arg); };
    // Abort alone is not enough: net.ClientRequest.abort() emits 'abort', and
    // an 'error' only follows on some Electron versions. When it does not, no
    // handler below ever runs, `finish` is never called, and this promise stays
    // pending forever -- the caller's await never returns and the panel sits on
    // its loading state permanently. Reject explicitly so a timeout is always a
    // rejection, never a hang.
    const timer = setTimeout(() => {
      req.abort();
      finish(reject, new Error(`timeout after ${timeoutMs}ms: ${pathname}`));
    }, timeoutMs);
    req.on('response', (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => finish(resolve, { statusCode: res.statusCode, body }));
      res.on('error', (e) => finish(reject, e));
    });
    req.on('error', (e) => finish(reject, e));
    req.end();
  });
}

// Resolves parsed JSON, or rejects on any transport/parse error (used both
// for health polling and telemetry).
// 6000ms, not 1500ms. Measured against a healthy engine on this machine:
//   /api/stats 2110ms   /api/events 1970ms
//   /api/components 2325ms   /api/controls/coverage 2758ms
// The old 1500ms default was below the real latency of most endpoints the app
// polls, so essentially every poll timed out and every panel reported "no
// data" against a perfectly healthy engine. Note this is a floor, not a fix:
// 2-3s for a loopback JSON call is itself a server-side defect (these routes
// recompute per request instead of caching, the same class as the 34s
// asset-inventory hang), and until that is fixed the poll interval can still
// be shorter than the response time.
// Raised again, 6000 -> 12000: the persistence collector's own documented
// worst case is an 8s wall-clock hold on the GIL per poll (see its "8s budget"
// fix) - a request that lands during that window needs a client-side timeout
// safely ABOVE 8s to have any chance of seeing the eventual real answer,
// not just a floor above the typical 2-3s case this default was last tuned for.
function apiGet(pathname, timeoutMs = 12000) {
  return netGet(pathname, timeoutMs).then(({ statusCode, body }) => {
    if (statusCode && statusCode >= 200 && statusCode < 300) return JSON.parse(body);
    throw new Error(`HTTP ${statusCode}`);
  });
}

// Same as apiGet but for endpoints that intentionally return non-JSON text
// (e.g. the compliance report's ?format=md), so apiGet's JSON.parse never
// gets in the way of a body that was never meant to be JSON.
function apiGetText(pathname, timeoutMs = 4000) {
  return netGet(pathname, timeoutMs).then(({ statusCode, body }) => {
    if (statusCode && statusCode >= 200 && statusCode < 300) return body;
    throw new Error(`HTTP ${statusCode}`);
  });
}

// Generic request (GET/POST) against the loopback API. Control POSTs carry the
// per-process token; a Node caller sends no Origin header, which the engine
// treats as same-origin, so token + loopback is sufficient.
// Every apiPost() call (kill_process, block_domain, hunt, incident triage,
// every mutating action in the app) went through this default. Found live
// (2026-09-07): Hunt reported "Could not reach the engine" with a healthy,
// reachable server - the underlying query itself ran in 2ms - because a POST
// landing during the persistence collector's documented 8s worst-case stall
// timed out client-side at 4s, well before the server ever got a chance to
// answer. A one-shot mutating action has no retry to fall back on the way a
// polling GET does, so this needed the same fix as apiGet's, not a shorter one.
function apiRequest(method, pathname, { token, body, timeoutMs = 12000 } = {}) {
  return new Promise((resolve, reject) => {
    const data = body != null ? JSON.stringify(body) : null;
    const headers = {};
    if (data) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(data);
    }
    if (token) headers['x-valkyrie-token'] = token;
    // net.request, not http.request - see the block comment above netGet().
    const req = net.request({ method, protocol: 'http:', hostname: HOST, port: WEB_PORT, path: pathname });
    for (const [k, v] of Object.entries(headers)) req.setHeader(k, v);
    let settled = false;
    const finish = (fn, arg) => { if (settled) return; settled = true; clearTimeout(timer); fn(arg); };
    // Abort alone is not enough: net.ClientRequest.abort() emits 'abort', and
    // an 'error' only follows on some Electron versions. When it does not, no
    // handler below ever runs, `finish` is never called, and this promise stays
    // pending forever -- the caller's await never returns and the panel sits on
    // its loading state permanently. Reject explicitly so a timeout is always a
    // rejection, never a hang.
    const timer = setTimeout(() => {
      req.abort();
      finish(reject, new Error(`timeout after ${timeoutMs}ms: ${pathname}`));
    }, timeoutMs);
    req.on('response', (res) => {
      let b = '';
      res.on('data', (c) => (b += c));
      res.on('end', () => {
        const ok = res.statusCode >= 200 && res.statusCode < 300;
        let parsed = null;
        try { parsed = b ? JSON.parse(b) : null; } catch {}
        if (ok) { finish(resolve, parsed); return; }
        // .status is set explicitly (not left to string-matching the
        // message) so callers - apiPost's retry below in particular -
        // can tell "the token is stale" apart from every other failure
        // mode without depending on the exact wording the backend chose
        // for that error, which is exactly the kind of fragile parsing
        // this audit pass was looking for.
        const err = new Error((parsed && parsed.error) || `HTTP ${res.statusCode}`);
        err.status = res.statusCode;
        finish(reject, err);
      });
      res.on('error', (e) => finish(reject, e));
    });
    req.on('error', (e) => finish(reject, e));
    if (data) req.write(data);
    req.end();
  });
}

// Cached per Electron-process-lifetime, but the Python engine mints a FRESH
// token on every launch (secrets.token_urlsafe(24) at module load - see
// valkyrie/web/server.py). The engine can restart underneath a still-running
// Electron shell - e.g. POST /api/system/restart, a component restart, or the
// self-healing watchdog recovering a crash - at which point every cached
// token silently stops matching. Found during an architecture audit: the
// restart control itself would have been the one action that broke every
// OTHER control afterward, with no visible error beyond an opaque 403 on the
// next click, until the user relaunched the whole app. `force` lets a caller
// that already knows the token is stale skip the (harmless but pointless)
// reuse of a value it just learned is wrong.
let _tokenCache = null;
async function controlToken(force = false) {
  if (_tokenCache && !force) return _tokenCache;
  // OS file access is the temporary control boundary. A non-elevated shell
  // cannot read a SYSTEM service's credential and remains a viewer. Never
  // fall back to the former unauthenticated HTTP bootstrap.
  const credentialPath = path.join(lifecycle.engineDataDir(), 'control', 'token');
  let token;
  try {
    token = (await fs.promises.readFile(credentialPath, 'utf8')).trim();
  } catch {
    throw new Error('Control requires an authorized local session with access to the protected service credential');
  }
  if (!/^[A-Za-z0-9_-]{32}$/.test(token)) throw new Error('Protected control credential is invalid');
  _tokenCache = token;
  return _tokenCache;
}
async function apiPost(pathname, body) {
  const token = await controlToken();
  try {
    return await apiRequest('POST', pathname, { token, body });
  } catch (err) {
    if (err.status !== 401 && err.status !== 403) throw err;
    const fresh = await controlToken(true).catch(() => null);
    if (!fresh || fresh === token) throw err;   // genuinely forbidden, not stale
    return apiRequest('POST', pathname, { token: fresh, body });
  }
}

// True when the engine's web API answers on loopback.
//
// Probes /api/ping, NOT /api/health - they answer different questions, and the
// engine says so itself: server.py's ping() docstring reads "Pure liveness ...
// touches NO state", and closes with "/api/health is a different question (is
// PROTECTION healthy) and is not a substitute for this one." The engine's own
// self-healing watchdog already learned that the hard way by probing an
// expensive endpoint: it measured LOAD, reported load as death, and declared a
// perfectly healthy server dead every 30s. This shell was making exactly the
// same substitution, one process further out.
//
// The budget is 4000ms, not 1000ms. The latencies measured on this machine and
// recorded above apiGet() - 1970ms to 2758ms - are ALL above the old 1s
// budget, which is why apiGet's own default was raised to 6000ms. isUp() was
// left behind at 1000ms, so it could never succeed against a healthy engine no
// matter how many times it retried, and the window sat on "Engine unreachable"
// forever. A liveness probe whose budget is below the service's real response
// time does not measure liveness - it always reports dead.
async function isUp() {
  try { await apiGet('/api/ping', 4000); return true; }
  catch { /* an engine older than /api/ping falls through to the legacy probe */ }
  try { await apiGet('/api/health', 4000); return true; }
  catch { return false; }
}

// Does a named scheduled task exist? (No UAC just to query.)
function taskExists(name) {
  return new Promise((resolve) => {
    childProcess.execFile(SCHTASKS, ['/query', '/tn', name], { windowsHide: true }, (err) => resolve(!err));
  });
}

function runTask(name) {
  return new Promise((resolve, reject) => {
    childProcess.execFile(SCHTASKS, ['/run', '/tn', name], { windowsHide: true }, (err) =>
      err ? reject(err) : resolve()
    );
  });
}

// Only meaningful for an "installed" build: register-tasks.ps1 is supposed to
// have registered both no-UAC tasks at install time (electron/build/
// installer.nsh's customInstall). Found empty in the wild once already (a
// machine whose service was healthy but whose tasks were simply never
// registered) - surfaced here so the app can say "this install is
// incomplete" instead of quietly falling through start()'s dev-checkout
// script fallback against an installed layout it was never designed for.
async function installationGaps() {
  if (lifecycle.mode() !== 'installed') return [];
  const [hasArm, hasDisarm] = await Promise.all([
    taskExists('ValkyrieArm'), taskExists('ValkyrieDisarm'),
  ]);
  const gaps = [];
  if (!hasArm) gaps.push('ValkyrieArm');
  if (!hasDisarm) gaps.push('ValkyrieDisarm');
  return gaps;
}

// Spawn a PowerShell script detached (used as the source-checkout fallback,
// where the scheduled tasks are not registered). start_all.ps1 self-elevates.
// `windowsHide: true` makes PowerShell itself invisible (Node sets
// CREATE_NO_WINDOW, applied before the process is even created - unlike
// `-WindowStyle Hidden`, which hides the console after Windows has already
// shown it, hence the extraArgs below rather than relying on that alone).
function runScriptDetached(name, extraArgs = []) {
  const script = scriptPath(name);
  if (!fs.existsSync(script)) {
    return Promise.reject(new Error(`missing ${name} at ${script}`));
  }
  const child = childProcess.spawn(
    POWERSHELL,
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', script, ...extraArgs],
    { detached: true, stdio: 'ignore', windowsHide: true }
  );
  child.unref();
  return Promise.resolve();
}

// "Protected" = the OS DNS adapter is pointed at the engine. arm/disarm and
// start_all/stop_all all record this by writing/removing valkyrie_dns_adapter.txt,
// so its presence is a reliable armed signal in both the service and dev models.
function isProtected() {
  try { return fs.existsSync(path.join(dataDir(), 'valkyrie_dns_adapter.txt')); }
  catch { return false; }
}

// Turn protection ON. In the packaged product the engine already runs as the
// ValkyrieShield service, so this just arms the DNS adapter (no-prompt task).
// In a source checkout there is no service, so start_all.ps1 both launches the
// engine and arms DNS.
async function start() {
  if (lifecycle.mode() === 'portable') {
    // Portable can't change system DNS (needs admin/service) - just ensure the
    // engine is running so the dashboard works, state kept beside the exe.
    ensurePortableEngine();
    return { started: true, via: 'portable', armed: false };
  }
  if (await taskExists('ValkyrieArm')) {
    await runTask('ValkyrieArm');
    return { started: true, via: 'arm-task' };
  }
  if (await taskExists('ValkyrieStart')) {
    await runTask('ValkyrieStart');
    return { started: true, via: 'task' };
  }
  // An installed layout that reaches this line is an INCOMPLETE INSTALL, not a
  // source checkout: register-tasks.ps1 never ran or failed, which the boot
  // path already refuses to paper over (see main.js's RECONCILE_ARM branch)
  // and which installationGaps() exists to name. Falling through to
  // start_all.ps1 here ran the dev-checkout script against an installed
  // machine anyway - and returned started:true regardless, so the caller then
  // waited ~48s for an arm marker nothing was going to write. Seen live: the
  // engine service was healthy and answering on 8090, both tasks were absent,
  // and Start Protection reported failure with no explanation. Refuse, and say
  // why, so the UI can offer the repair that actually fixes it.
  if (lifecycle.mode() === 'installed') {
    return { started: false, via: 'none', gaps: await installationGaps() };
  }
  // -Silent: the app has its own splash/progress UI, so the engine must
  // launch with no visible window - unlike a developer running this script
  // by hand from a terminal, where the console is deliberately kept.
  await runScriptDetached('start_all.ps1', ['-Silent']);
  return { started: true, via: 'script' };
}

// Re-run the installer's task registration (elevated) for an install that is
// missing ValkyrieArm/ValkyrieDisarm. This is what makes the Repair button
// able to fix an incomplete install: selfHeal() only restores data folders, so
// before this the dialog offered a Repair that could not touch the actual
// fault. One UAC prompt is correct here - it is a user-initiated repair, and
// registering a Highest-runlevel task requires admin.
async function repairInstallation() {
  const gaps = await installationGaps();
  if (!gaps.length) return { ok: true, gaps: [], via: 'nothing-to-do' };
  const root = path.join(process.resourcesPath || '', 'engine');
  const script = path.join(root, 'register-tasks.ps1');
  if (!fs.existsSync(script)) {
    return { ok: false, gaps, via: 'missing-register-tasks' };
  }
  // Embedded in a single-quoted PowerShell string, so a quote in the path
  // would break the command apart. Install paths never contain one; refuse
  // rather than build something malformed if that ever changes.
  if (script.includes("'") || root.includes("'")) {
    return { ok: false, gaps, via: 'unsupported-path' };
  }
  const inner =
    `Start-Process -FilePath '${POWERSHELL}' -Verb RunAs -WindowStyle Hidden -Wait ` +
    `-ArgumentList '-NoProfile -ExecutionPolicy Bypass -File "${script}" -Root "${root}"'`;
  await new Promise((resolve) => {
    childProcess.execFile(POWERSHELL, ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', inner],
      { windowsHide: true }, () => resolve());
  });
  // Trust the OS, not the exit code: the repair worked only if the tasks are
  // actually there now (the user can also decline the UAC prompt).
  const remaining = await installationGaps();
  return { ok: remaining.length === 0, gaps: remaining, via: 'register-tasks' };
}

// Turn protection OFF: disarm the DNS adapter (engine service keeps running).
async function stop() {
  if (await taskExists('ValkyrieDisarm')) {
    await runTask('ValkyrieDisarm');
    return { stopped: true, via: 'disarm-task' };
  }
  if (await taskExists('ValkyrieStop')) {
    await runTask('ValkyrieStop');
    return { stopped: true, via: 'task' };
  }
  await runScriptDetached('stop_all.ps1');
  return { stopped: true, via: 'script' };
}

// Poll until the API is up (or timeout). onTick(up:boolean) fires each attempt
// so the splash can drive its animated checks off real readiness.
async function waitUntilReady(onTick, { attempts = 60, intervalMs = 1000 } = {}) {
  for (let i = 0; i < attempts; i++) {
    const up = await isUp();
    if (onTick) onTick(up, i);
    if (up) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return false;
}

// Poll until DNS is actually ARMED (not just "the engine responded"), or give
// up. Needed because arming happens via an independent scheduled task
// (ValkyrieArm, see start() below) that this call never waits on directly -
// `schtasks /run` returns as soon as the task is QUEUED, not once
// arm-protection.ps1 (which itself now retries for up to ~35s while the
// engine finishes its own first-boot startup: blocklist download, Sysmon
// setup, Unbound bring-up) actually succeeds or gives up.
//
// Without this, engine:start's waitUntilReady(isUp) call above was the ONLY
// thing it awaited - and since the ValkyrieShield service is normally
// already running continuously, isUp() succeeds almost instantly regardless
// of whether arming has happened at all. "Start Protection" reported success
// (the button settled, the spinner cleared) while the real arm attempt was
// still silently retrying for up to another 35+ seconds - which reads
// exactly like the click did nothing, the original report this exists to fix.
async function waitUntilArmed(onTick, { attempts = 24, intervalMs = 2000 } = {}) {
  for (let i = 0; i < attempts; i++) {
    let armed = false;
    try {
      const stats = await apiGet('/api/stats', 6000);
      armed = isProtected() && stats && stats.dns_active === true;
    } catch { /* engine hiccup mid-poll - treat as not-yet-armed, keep trying */ }
    if (onTick) onTick(armed, i);
    if (armed) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return false;
}

// Snapshot for the dashboard: stats + recent events, tolerant of partial
// availability so a half-warmed engine still renders something real.
async function telemetry() {
  const marker = isProtected();
  const out = { ok: false, protected: marker, stats: null, events: [] };
  try { out.stats = await apiGet('/api/stats', 6000); out.ok = true; }
  catch (err) { console.error('[engine.telemetry] GET /api/stats failed:', err && err.stack || err); }
  try { out.events = await apiGet('/api/events', 6000); }
  catch (err) { console.error('[engine.telemetry] GET /api/events failed:', err && err.stack || err); }

  // The adapter marker alone is NOT proof of protection: it is a file that
  // outlives a crash, a reboot or a stopped service. Seen live - a marker from
  // two weeks earlier made the dashboard read "Protected / All clear" while
  // ValkyrieShield was STOPPED. So when the engine is reachable and states
  // whether DNS interception is actually running, that answer wins.
  // `dns_active` absent (older engine) -> fall back to the marker rather than
  // wrongly reporting unprotected.
  if (out.ok && out.stats && typeof out.stats.dns_active === 'boolean') {
    out.protected = marker && out.stats.dns_active;
  }
  return out;
}

module.exports = {
  WEB_PORT,
  isUp,
  start,
  stop,
  waitUntilReady,
  waitUntilArmed,
  telemetry,
  installationGaps,
  repairInstallation,
  apiGet,
  apiGetText,
  apiPost,
  isProtected,
  engineRoot,
  dataDir,
  ensurePortableEngine,
  stopPortableEngine,
  bundledEngineExe,
};
