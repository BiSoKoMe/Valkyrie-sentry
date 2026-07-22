'use strict';
// ---------------------------------------------------------------------------
// engine.js — lifecycle + telemetry bridge for the Python security engine.
//
// The Electron shell NEVER contains security logic. This module only:
//   * asks the already-shipped engine to start / stop (via the no-prompt
//     ValkyrieStart / ValkyrieStop scheduled tasks the installer registers,
//     falling back to start_all.ps1 / stop_all.ps1 in a source checkout), and
//   * reads the engine's local HTTP API (loopback) so the UI can render.
//
// All HTTP happens here in the Node main process, not the renderer — that way
// there is no cross-origin/localhost page anywhere in the product; the renderer
// only ever receives already-parsed JSON over IPC.
// ---------------------------------------------------------------------------

const http = require('http');
const { spawn, execFile } = require('child_process');
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

// Writable state location — single source of truth in lifecycle.js (mirrors
// valkyrie/config.py: %ProgramData%\Valkyrie installed, beside-exe portable,
// repo data/ in dev).
function dataDir() { return lifecycle.engineDataDir(); }

// Path to the bundled frozen engine (packaged / portable builds).
function bundledEngineExe() {
  return path.join(process.resourcesPath || '', 'engine', 'valkyrie.exe');
}

// Portable build: no service, no admin, no DNS takeover — just run the engine
// as a child so the dashboard works with all state kept beside the exe.
let _portableChild = null;
function ensurePortableEngine() {
  const exe = bundledEngineExe();
  if (!fs.existsSync(exe)) return false;
  if (_portableChild && !_portableChild.killed) return true;
  _portableChild = spawn(
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
// Low-level HTTP GET against the loopback API. Resolves parsed JSON, or rejects
// on any transport/parse error (used both for health polling and telemetry).
// ---------------------------------------------------------------------------
function apiGet(pathname, timeoutMs = 1500) {
  return new Promise((resolve, reject) => {
    const req = http.get(
      { host: HOST, port: WEB_PORT, path: pathname, timeout: timeoutMs },
      (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            try { resolve(JSON.parse(body)); }
            catch (e) { reject(e); }
          } else {
            reject(new Error(`HTTP ${res.statusCode}`));
          }
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

// Same as apiGet but for endpoints that intentionally return non-JSON text
// (e.g. the compliance report's ?format=md), so apiGet's JSON.parse never
// gets in the way of a body that was never meant to be JSON.
function apiGetText(pathname, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const req = http.get(
      { host: HOST, port: WEB_PORT, path: pathname, timeout: timeoutMs },
      (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) resolve(body);
          else reject(new Error(`HTTP ${res.statusCode}`));
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

// Generic request (GET/POST) against the loopback API. Control POSTs carry the
// per-process token; a Node caller sends no Origin header, which the engine
// treats as same-origin, so token + loopback is sufficient.
function apiRequest(method, pathname, { token, body, timeoutMs = 4000 } = {}) {
  return new Promise((resolve, reject) => {
    const data = body != null ? JSON.stringify(body) : null;
    const headers = {};
    if (data) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(data);
    }
    if (token) headers['x-valkyrie-token'] = token;
    const req = http.request(
      { host: HOST, port: WEB_PORT, path: pathname, method, headers, timeout: timeoutMs },
      (res) => {
        let b = '';
        res.on('data', (c) => (b += c));
        res.on('end', () => {
          const ok = res.statusCode >= 200 && res.statusCode < 300;
          let parsed = null;
          try { parsed = b ? JSON.parse(b) : null; } catch {}
          if (ok) resolve(parsed);
          else reject(new Error((parsed && parsed.error) || `HTTP ${res.statusCode}`));
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

let _tokenCache = null;
async function controlToken() {
  if (_tokenCache) return _tokenCache;
  const r = await apiGet('/api/system/token', 2000);
  _tokenCache = r && r.token;
  return _tokenCache;
}
async function apiPost(pathname, body) {
  const token = await controlToken().catch(() => null);
  return apiRequest('POST', pathname, { token, body });
}

// True when the engine's web API answers on loopback.
async function isUp() {
  try { await apiGet('/api/health', 1000); return true; }
  catch { return false; }
}

// Does a named scheduled task exist? (No UAC just to query.)
function taskExists(name) {
  return new Promise((resolve) => {
    execFile(SCHTASKS, ['/query', '/tn', name], { windowsHide: true }, (err) => resolve(!err));
  });
}

function runTask(name) {
  return new Promise((resolve, reject) => {
    execFile(SCHTASKS, ['/run', '/tn', name], { windowsHide: true }, (err) =>
      err ? reject(err) : resolve()
    );
  });
}

// Spawn a PowerShell script detached (used as the source-checkout fallback,
// where the scheduled tasks are not registered). start_all.ps1 self-elevates.
function runScriptDetached(name) {
  const script = scriptPath(name);
  if (!fs.existsSync(script)) {
    return Promise.reject(new Error(`missing ${name} at ${script}`));
  }
  const child = spawn(
    POWERSHELL,
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', script],
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
    // Portable can't change system DNS (needs admin/service) — just ensure the
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
  await runScriptDetached('start_all.ps1');
  return { started: true, via: 'script' };
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

// Snapshot for the dashboard: stats + recent events, tolerant of partial
// availability so a half-warmed engine still renders something real.
async function telemetry() {
  const out = { ok: false, protected: isProtected(), stats: null, events: [] };
  try { out.stats = await apiGet('/api/stats', 1500); out.ok = true; } catch {}
  try { out.events = await apiGet('/api/events', 1500); } catch {}
  return out;
}

module.exports = {
  WEB_PORT,
  isUp,
  start,
  stop,
  waitUntilReady,
  telemetry,
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
