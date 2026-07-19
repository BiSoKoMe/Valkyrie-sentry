'use strict';
// ---------------------------------------------------------------------------
// main.js — Electron main process. The desktop shell only.
//
//   * Creates ONE frameless, dark, glass window (no browser chrome ever).
//   * Owns the Python engine lifecycle (start on launch, stop on request).
//   * Streams live telemetry to the renderer over IPC (all HTTP stays here,
//     so the renderer never touches localhost / cross-origin and no browser
//     window is ever shown).
// ---------------------------------------------------------------------------

const { app, BrowserWindow, ipcMain, shell, dialog } = require('electron');
const path = require('path');
const engine = require('./engine');
const lifecycle = require('./lifecycle');

const isDev = process.argv.includes('--dev');
let win = null;
let pollTimer = null;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Single-instance: clicking the shortcut again focuses the running app rather
// than launching a second copy (Steam/Discord behaviour).
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (win) { if (win.isMinimized()) win.restore(); win.focus(); }
  });
}

function createWindow() {
  win = new BrowserWindow({
    width: 1180,
    height: 760,
    minWidth: 960,
    minHeight: 640,
    show: false,
    frame: false,                 // custom title bar — no OS chrome
    titleBarStyle: 'hidden',
    backgroundColor: '#0a0a0d',    // matte black; avoids white flash on load
    backgroundMaterial: 'acrylic', // Win11 blur behind the window
    roundedCorners: true,
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload', 'preload.js'),
      contextIsolation: true,      // renderer is sandboxed; talks via preload
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
    },
  });

  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));

  // Reveal only once painted → no flash, smooth fade handled in CSS.
  win.once('ready-to-show', () => {
    win.show();
    // Verification launches bring the window to the front so a screen capture
    // sees it; harmless no-op in normal use.
    if (process.env.VALKYRIE_VERIFY === '1') {
      win.setAlwaysOnTop(true, 'screen-saver');
      win.focus();
    }
  });

  // Never let the shell navigate like a browser or spawn popups.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http')) shell.openExternal(url); // external links → OS browser
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (e) => e.preventDefault());

  win.on('maximize', () => win.webContents.send('window:state', { maximized: true }));
  win.on('unmaximize', () => win.webContents.send('window:state', { maximized: false }));
  win.on('closed', () => { win = null; });
}

// ---------------------------------------------------------------------------
// Telemetry polling: once the engine is up, push a snapshot to the renderer on
// a steady cadence. Polling (vs. a WS client dep) keeps the shell dependency-
// free and is plenty for a 1s dashboard refresh.
// ---------------------------------------------------------------------------
function startPolling() {
  if (pollTimer) return;
  const tick = async () => {
    if (!win) return;
    const data = await engine.telemetry();
    if (win) win.webContents.send('telemetry', data);
  };
  tick();
  pollTimer = setInterval(tick, 1500);
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

// ---------------------------------------------------------------------------
// IPC surface (mirrors preload.js). Renderer requests; main acts.
// ---------------------------------------------------------------------------
function registerIpc() {
  ipcMain.handle('engine:status', async () => ({ up: await engine.isUp() }));

  ipcMain.handle('engine:start', async () => {
    const r = await engine.start();
    const ready = await engine.waitUntilReady((up, i) => {
      if (win) win.webContents.send('engine:progress', { up, attempt: i });
    });
    if (ready) startPolling();
    return { ...r, ready };
  });

  ipcMain.handle('engine:stop', async () => {
    const r = await engine.stop();
    return r;
  });

  // Boot flow the splash calls once: ensure the engine is up, animating checks
  // off real readiness, then tell the renderer to reveal the dashboard.
  // Fast, side-effect-free scenario probe the splash calls first to choose the
  // right first-boot sequence (fresh / upgrade / repair / normal).
  ipcMain.handle('lifecycle:info', async () => {
    const det = lifecycle.detectScenario();
    return {
      scenario: det.scenario, previous: det.previous,
      mode: lifecycle.mode(), version: app.getVersion(),
      dataDir: lifecycle.engineDataDir(),
    };
  });

  // Full boot orchestration. Emits 'boot:step' events so the renderer can
  // animate a real "Preparing Valkyrie" sequence, then records that
  // initialization happened so first-boot never repeats.
  ipcMain.handle('boot', async () => {
    const noAutostart = process.env.VALKYRIE_NO_AUTOSTART === '1';
    const scenario = lifecycle.detectScenario().scenario;
    const setup = scenario !== 'normal';
    const step = (key, label, status) =>
      win && win.webContents.send('boot:step', { key, label, status });
    // First-boot runs once per install, so a deliberate, elegant pace (rather
    // than a jarring flash) is the commercial feel we want. Normal boots skip it.
    const pace = async (ms) => { if (setup) await sleep(ms); };

    // 1. Layout / data handling per scenario.
    if (scenario === 'fresh') {
      step('folders', 'Creating runtime folders', 'run'); await pace(650);
      lifecycle.ensureLayout();
      step('folders', 'Creating runtime folders', 'done'); await pace(200);
    } else if (scenario === 'repair') {
      step('repair', 'Repairing installation', 'run'); await pace(650);
      lifecycle.selfHeal();
      step('repair', 'Repairing installation', 'done'); await pace(200);
    } else if (scenario === 'upgrade') {
      step('preserve', 'Preserving your configuration', 'run'); await pace(650);
      lifecycle.ensureLayout();   // keeps existing data; only fills gaps
      step('preserve', 'Preserving your configuration', 'done'); await pace(200);
    }

    // 2. Ensure the protection engine is running.
    step('engine', 'Starting protection engine', 'run');
    const already = await engine.isUp();
    if (!already && !noAutostart) { try { await engine.start(); } catch {} }
    startPolling();
    let ready = already;
    if (!(noAutostart && !already)) {
      ready = await engine.waitUntilReady((up, i) =>
        win && win.webContents.send('engine:progress', { up, attempt: i }));
    }
    await pace(400);
    step('engine', 'Starting protection engine', ready ? 'done' : 'warn'); await pace(200);

    // 3. Integrity + health (setup scenarios only).
    if (setup) {
      step('verify', 'Verifying installation', 'run'); await pace(600);
      if (lifecycle.integrityIssues().length) lifecycle.selfHeal();
      step('verify', 'Verifying installation', 'done'); await pace(200);
      step('health', 'Running health check', 'run'); await pace(600);
      step('health', 'Running health check', ready ? 'done' : 'warn'); await pace(300);
    }

    // 4. Finalize — record initialization so first-boot never repeats. Only
    //    mark done once the engine is actually healthy, so a failed first run
    //    is retried (as a repair) next launch instead of being marked complete.
    if (ready && setup) lifecycle.writeState({ lastScenario: scenario });

    return { ready, already, scenario, mode: lifecycle.mode() };
  });

  // Manual self-heal (the "Repair" button in the professional error dialog).
  ipcMain.handle('lifecycle:repair', async () => {
    const restored = lifecycle.selfHeal();
    let ready = await engine.isUp();
    if (!ready) { try { await engine.start(); } catch {} ready = await engine.waitUntilReady(null, { attempts: 20 }); }
    return { restored, ready };
  });

  ipcMain.handle('telemetry:now', async () => engine.telemetry());

  // Generic, allowlisted API bridge so any page can read live data (and run the
  // few token-gated control actions) without the renderer ever touching HTTP.
  ipcMain.handle('api:get', (_e, p) =>
    typeof p === 'string' && p.startsWith('/api/')
      ? engine.apiGet(p, 4000)
      : Promise.reject(new Error('blocked')));
  ipcMain.handle('api:post', (_e, { path: p, body }) =>
    typeof p === 'string' && p.startsWith('/api/')
      ? engine.apiPost(p, body)
      : Promise.reject(new Error('blocked')));

  // Window controls for the custom title bar.
  ipcMain.on('window:minimize', () => win && win.minimize());
  ipcMain.on('window:maximize', () => {
    if (!win) return;
    win.isMaximized() ? win.unmaximize() : win.maximize();
  });
  ipcMain.on('window:close', () => win && win.close());

  ipcMain.handle('open-logs', async () => {
    // Logs live with the rest of the writable state (%ProgramData%\Valkyrie for
    // a packaged install). Ensure it exists so the folder always opens.
    const dir = engine.dataDir();
    try { require('fs').mkdirSync(dir, { recursive: true }); } catch {}
    await shell.openPath(dir);
    return dir;
  });

  ipcMain.handle('app:info', async () => ({
    version: app.getVersion(),
    dev: isDev,
    mode: lifecycle.mode(),
    engineRoot: engine.engineRoot(),
    dataDir: lifecycle.engineDataDir(),
    // Verification aid: jump straight to a page after splash (env-gated).
    startPage: process.env.VALKYRIE_START_PAGE || null,
  }));

  // Native, in-app error affordance — never a browser, never a traceback.
  // Buttons map to: 0 Retry · 1 Repair · 2 View Logs · 3 Continue Offline.
  ipcMain.handle('dialog:error', async (_e, { title, message }) => {
    if (!win) return { response: 0 };
    const r = await dialog.showMessageBox(win, {
      type: 'error',
      title: title || 'Valkyrie',
      message: message || 'Valkyrie ran into a problem.',
      detail: 'You can retry, repair the installation, view logs, or continue offline.',
      buttons: ['Retry', 'Repair', 'View Logs', 'Continue Offline'],
      defaultId: 0,
      cancelId: 3,
      noLink: true,
    });
    return { response: r.response };
  });
}

app.whenReady().then(() => {
  registerIpc();
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  stopPolling();
  // A portable build owns its engine child, so stop it with the window; an
  // installed build leaves the ValkyrieShield service running independently.
  if (lifecycle.mode() === 'portable') engine.stopPortableEngine();
  if (process.platform !== 'darwin') app.quit();
});
