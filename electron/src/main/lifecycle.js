'use strict';
// ---------------------------------------------------------------------------
// lifecycle.js - production install lifecycle for the Valkyrie desktop app.
//
// Owns everything that makes install / first-boot / upgrade / repair feel like
// a commercial product:
//   * build MODE detection (development | installed | portable),
//   * canonical writable-state locations (matches valkyrie/config.py),
//   * the install-state marker + scenario detection
//       (fresh install | upgrade | repair | normal),
//   * creating the runtime folder scaffold and self-healing it.
//
// The engine (Python) owns creating its own db/keys/config on first run; this
// module orchestrates around it and records that initialization happened so the
// first-boot sequence never repeats.
// ---------------------------------------------------------------------------

const { app } = require('electron');
const path = require('path');
const fs = require('fs');
const { PROTECTION_INTENT } = require('./protection_state');

const STATE_VERSION = 1;
const MARKER = 'install-state.json';

// Runtime folders created up-front so the product has a stable, professional
// layout from first boot (logs, caches, quarantine, threat intel, keys, ...).
const RUNTIME_DIRS = ['logs', 'cache', 'quarantine', 'threat-intel', 'keys', 'updates', 'config'];

// --- Build mode ---
function isDev() { return !app.isPackaged; }
// electron-builder's portable target runs from a temp dir and sets
// PORTABLE_EXECUTABLE_DIR to the real location of the .exe.
function isPortable() { return !!process.env.PORTABLE_EXECUTABLE_DIR; }
function mode() { return isDev() ? 'development' : isPortable() ? 'portable' : 'installed'; }

function repoRoot() { return path.resolve(__dirname, '..', '..', '..'); }
function portableDir() {
  return process.env.PORTABLE_EXECUTABLE_DIR || path.dirname(process.execPath);
}

// --- Canonical paths (MUST mirror valkyrie/config.py resolution) ---
function engineDataDir() {
  switch (mode()) {
    case 'development': return path.join(repoRoot(), 'data');
    case 'portable':    return path.join(portableDir(), 'ValkyrieData');
    default:            return path.join(process.env.ProgramData || 'C:\\ProgramData', 'Valkyrie');
  }
}

// Where the Electron-side install marker lives. Installed builds use a per-user
// location that is always writable; portable/dev keep it with their data.
function appStateDir() {
  return mode() === 'installed' ? app.getPath('userData') : engineDataDir();
}

// Env passed to the engine so a Portable launch keeps ALL state beside the exe
// and never touches %ProgramData% or Program Files.
function engineEnv() {
  const env = { ...process.env };
  if (mode() === 'portable') env.VALKYRIE_DATA_DIR = engineDataDir();
  return env;
}

// --- Install-state marker ---
function markerPath() { return path.join(appStateDir(), MARKER); }

function readState() {
  try { return JSON.parse(fs.readFileSync(markerPath(), 'utf8')); }
  catch { return null; }
}

// Merges onto whatever is already on disk rather than replacing it wholesale -
// this file now carries more than the original install marker (see
// protectionIntent() below), and a second caller's write must not silently
// erase a first caller's field. initializedAt in particular must survive
// every later write: it is first-boot's timestamp, not "last write's".
function writeState(extra) {
  const prev = readState() || {};
  const state = {
    ...prev,
    stateVersion: STATE_VERSION,
    version: app.getVersion(),
    mode: mode(),
    initializedAt: prev.initializedAt || new Date().toISOString(),
    ...extra,
  };
  try {
    fs.mkdirSync(appStateDir(), { recursive: true });
    fs.writeFileSync(markerPath(), JSON.stringify(state, null, 2), 'utf8');
  } catch { /* best-effort; a re-run just repeats first-boot harmlessly */ }
  return state;
}

// --- Protection intent -----------------------------------------------------
// Whether the USER has explicitly asked for DNS protection, independent of
// whether it is currently armed. Persisted in the same install-state.json
// this module already owns (no new file) so it survives restarts, reboots,
// and the engine being an always-on service that boot() can no longer use as
// a proxy for "is protection wanted". Only ever written from the explicit
// Start/Stop Protection action (main.js's engine:start/engine:stop IPC
// handlers) - never from an automatic recovery attempt, so a background
// re-arm can never look like a second explicit user decision.
function protectionIntent() {
  const s = readState();
  return (s && s.protectionIntent) || PROTECTION_INTENT.UNSET;
}

function setProtectionIntent(value) {
  return writeState({ protectionIntent: value });
}

// --- Scenario detection ---
//   fresh   - never initialized on this machine/user
//   upgrade - initialized by a DIFFERENT app version
//   repair  - same version but the runtime layout is broken/missing
//   normal  - initialized, same version, layout intact
function detectScenario() {
  const state = readState();
  if (!state || !state.initializedAt) return { scenario: 'fresh', previous: null };
  if (state.version !== app.getVersion()) return { scenario: 'upgrade', previous: state.version };
  if (integrityIssues().length > 0) return { scenario: 'repair', previous: state.version };
  return { scenario: 'normal', previous: state.version };
}

// --- Layout + integrity + self-heal ---
function ensureLayout() {
  const base = engineDataDir();
  const created = [];
  try {
    fs.mkdirSync(base, { recursive: true });
    for (const d of RUNTIME_DIRS) {
      const p = path.join(base, d);
      if (!fs.existsSync(p)) { fs.mkdirSync(p, { recursive: true }); created.push(d); }
    }
  } catch { /* ACLs on a service-owned dir may block some; non-fatal */ }
  return created;
}

// Missing pieces that make an install "broken". Kept conservative so we never
// nag on a healthy machine.
function integrityIssues() {
  const issues = [];
  const base = engineDataDir();
  try {
    if (!fs.existsSync(base)) issues.push('data directory missing');
    for (const d of RUNTIME_DIRS) {
      if (!fs.existsSync(path.join(base, d))) issues.push(`missing folder: ${d}`);
    }
  } catch { issues.push('data directory unreadable'); }
  return issues;
}

// Restore anything missing without exposing errors. The engine re-creates its
// db/keys/config on next start; here we rebuild the folder scaffold and restore
// the factory rules file from the bundled default if it went missing.
function selfHeal() {
  const restored = ensureLayout();
  try {
    const rules = path.join(engineDataDir(), 'valkyrie_rules.yaml');
    if (!fs.existsSync(rules)) {
      const bundled = path.join(process.resourcesPath || '', 'engine', 'rules.default.yaml');
      if (fs.existsSync(bundled)) { fs.copyFileSync(bundled, rules); restored.push('valkyrie_rules.yaml'); }
    }
  } catch { /* best-effort */ }
  return restored;
}

module.exports = {
  mode, isDev, isPortable,
  engineDataDir, appStateDir, engineEnv,
  readState, writeState, detectScenario,
  ensureLayout, integrityIssues, selfHeal,
  RUNTIME_DIRS,
  protectionIntent, setProtectionIntent,
};
