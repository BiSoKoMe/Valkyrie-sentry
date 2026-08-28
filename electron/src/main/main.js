'use strict';
// ---------------------------------------------------------------------------
// main.js - Electron main process. The desktop shell only.
//
//   * Creates ONE frameless, dark, glass window (no browser chrome ever).
//   * Owns the Python engine lifecycle (start on launch, stop on request).
//   * Streams live telemetry to the renderer over IPC (all HTTP stays here,
//     so the renderer never touches localhost / cross-origin and no browser
//     window is ever shown).
// ---------------------------------------------------------------------------

// Valkyrie is a windowless GUI app (ADR 0001) - there is no console attached,
// so process.stdout/stderr are frequently a broken/absent pipe. Node's
// console.log/error normally swallow that, but on Windows a write to a
// closed pipe can throw EPIPE synchronously; uncaught inside a timer
// callback (e.g. the telemetry poll below), that took down the ENTIRE main
// process - reproduced live: "Error: EPIPE: broken pipe, write" at
// engine.js telemetry() -> console.error(), thrown from main.js's poll
// Timeout.tick. Must be registered before anything else can log.
for (const stream of [process.stdout, process.stderr]) {
  if (stream) stream.on('error', (err) => { if (err && err.code !== 'EPIPE') throw err; });
}

const { app, BrowserWindow, ipcMain, shell, dialog, Tray, Menu, nativeImage } = require('electron');
const path = require('path');
const engine = require('./engine');
const lifecycle = require('./lifecycle');
const { decideBootAction, PROTECTION_INTENT, BOOT_ACTION } = require('./protection_state');

const isDev = process.argv.includes('--dev');
let win = null;
let tray = null;
let isQuitting = false;      // true only when the user really quits (tray menu)
let pollTimer = null;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Single-instance: clicking the shortcut again focuses the running app rather
// than launching a second copy (Steam/Discord behaviour).
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => { showApp(); });
}

// Bring the window up from the tray / a second launch. Recreates it if it was
// destroyed. Never replays the splash: the window is only ever HIDDEN, not
// reloaded, so its renderer (and the already-finished splash) stay as they were.
function showApp() {
  if (!win) { createWindow(); return; }
  if (!win.isVisible()) win.show();
  if (win.isMinimized()) win.restore();
  win.focus();
}

// Live in the Windows tray (the hidden-icons area). Click = show the app menu;
// right-click = a small menu with a real Quit. Closing the window only hides it
// here, so protection + privacy keep running in the background.
function createTray() {
  if (tray) return;
  let icon = nativeImage.createEmpty();
  try {
    const p = path.join(__dirname, process.platform === 'win32' ? 'tray.ico' : 'tray.png');
    const img = nativeImage.createFromPath(p);
    if (!img.isEmpty()) icon = img;
  } catch { /* fall back to an empty image; tray still functions */ }
  tray = new Tray(icon);
  tray.setToolTip('Valkyrie');
  tray.on('click', showApp);
  tray.on('double-click', showApp);
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Open Valkyrie', click: showApp },
    { type: 'separator' },
    { label: 'Quit Valkyrie', click: () => { isQuitting = true; app.quit(); } },
  ]));
}

function createWindow() {
  win = new BrowserWindow({
    width: 1180,
    height: 760,
    minWidth: 960,
    minHeight: 640,
    show: false,
    frame: false,                 // custom title bar - no OS chrome
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

  // Reveal only once painted -> no flash, smooth fade handled in CSS.
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

  // DevTools is never opened programmatically, and is explicitly blocked in
  // packaged builds: a security product should not leave an open console
  // into its own renderer reachable by anyone with local access to the
  // machine. app.isPackaged (not the --dev flag) is the check, since it
  // reflects how the app was actually built, not what it was launched with.
  if (app.isPackaged) {
    win.webContents.on('devtools-opened', () => win.webContents.closeDevTools());
    win.webContents.on('before-input-event', (event, input) => {
      const key = (input.key || '').toLowerCase();
      if (key === 'f12' || (input.control && input.shift && key === 'i')) event.preventDefault();
    });
  }

  win.on('maximize', () => win.webContents.send('window:state', { maximized: true }));
  win.on('unmaximize', () => win.webContents.send('window:state', { maximized: false }));

  // Closing hides Valkyrie to the tray instead of quitting: it keeps running
  // (protection + privacy stay on) and reopening from the tray shows THIS same
  // window - so the "hi, I am Valkyrie" splash never replays. A real quit
  // (tray -> Quit) sets isQuitting and lets the close through.
  win.on('close', (e) => {
    if (!isQuitting) { e.preventDefault(); win.hide(); }
  });
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
    // A background poller must never be able to take the whole app down -
    // one bad tick (network hiccup, a logging call that itself throws) just
    // gets skipped; the next tick 1.5s later tries again.
    try {
      const data = await engine.telemetry();
      if (win) win.webContents.send('telemetry', data);
    } catch (err) {
      console.error('[main.startPolling] tick failed (will retry):', err && err.stack || err);
    }
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
    // Record INTENT the moment the user asks, independent of whether the arm
    // attempt below actually succeeds this instant - boot()'s recovery logic
    // needs to know the user wants protection on even through a later
    // transient failure, exactly like host_safety.py's watchdog keeps trying
    // to restore connectivity rather than treating one failed tick as final.
    lifecycle.setProtectionIntent(PROTECTION_INTENT.ENABLED);
    const r = await engine.start();
    const ready = await engine.waitUntilReady((up, i) => {
      if (win) win.webContents.send('engine:progress', { up, attempt: i });
    });
    if (ready) startPolling();
    return { ...r, ready };
  });

  ipcMain.handle('engine:stop', async () => {
    lifecycle.setProtectionIntent(PROTECTION_INTENT.DISABLED);
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

    // 2. Ensure the protection engine is running. "Is the engine up?" and "is
    //    protection actually active?" are separate questions - ValkyrieShield
    //    is a persistent service that is essentially always up once
    //    installed, so isUp() alone can never notice DNS having gone quietly
    //    disarmed. protection_state.decideBootAction() is the pure decision;
    //    the intent behind it never arms on behalf of a user who hasn't asked.
    step('engine', 'Starting protection engine', 'run');
    const already = await engine.isUp();
    const intent = lifecycle.protectionIntent();
    const preAction = decideBootAction({
      engineUp: already, intent, mode: lifecycle.mode(),
      protected: null, noAutostart,
    });
    if (preAction === BOOT_ACTION.ENSURE_ENGINE) { try { await engine.start(); } catch {} }
    startPolling();
    let ready = already;
    if (!(noAutostart && !already)) {
      ready = await engine.waitUntilReady((up, i) =>
        win && win.webContents.send('engine:progress', { up, attempt: i }));
    }
    await pace(400);
    step('engine', 'Starting protection engine', ready ? 'done' : 'warn'); await pace(200);

    // 2b. Reconcile protection intent against the LIVE armed state. This is
    // the actual fix: only runs once the engine is confirmed reachable, only
    // acts when the user has explicitly enabled protection before, and only
    // ever calls the same engine.start() the user's own toggle uses - no
    // second DNS-modification path. Skipped outright on an installed build
    // missing its scheduled tasks: falling through to start()'s source-
    // checkout script fallback against an installed layout would be worse
    // than doing nothing, so an incomplete install is surfaced instead of
    // silently mis-handled.
    let installationGaps = [];
    let protectionRecovery = 'not-attempted';
    if (ready) {
      installationGaps = await engine.installationGaps();
      const tel = await engine.telemetry();
      const postAction = decideBootAction({
        engineUp: true, intent, mode: lifecycle.mode(),
        protected: tel.protected, noAutostart,
      });
      if (postAction === BOOT_ACTION.RECONCILE_ARM) {
        if (lifecycle.mode() === 'installed' && installationGaps.length > 0) {
          protectionRecovery = 'skipped-incomplete-install';
          console.error('[main.boot] protection intent is enabled and DNS is ' +
            'not active, but this install is missing scheduled task(s): ' +
            installationGaps.join(', ') + ' - not attempting auto-recovery ' +
            'to avoid falling back to a dev-checkout script against an ' +
            'installed layout.');
        } else {
          try {
            await engine.start();
            protectionRecovery = (await engine.telemetry()).protected ? 'recovered' : 'failed';
          } catch { protectionRecovery = 'failed'; }
        }
      } else if (intent === PROTECTION_INTENT.ENABLED) {
        protectionRecovery = tel.protected ? 'already-protected' : 'not-attempted';
      }
    }

    // 3. Integrity + health (setup scenarios only).
    if (setup) {
      step('verify', 'Verifying installation', 'run'); await pace(600);
      if (lifecycle.integrityIssues().length) lifecycle.selfHeal();
      step('verify', 'Verifying installation', 'done'); await pace(200);
      step('health', 'Running health check', 'run'); await pace(600);
      step('health', 'Running health check', ready ? 'done' : 'warn'); await pace(300);
    }

    // 4. Finalize - record initialization so first-boot never repeats. Only
    //    mark done once the engine is actually healthy, so a failed first run
    //    is retried (as a repair) next launch instead of being marked complete.
    if (ready && setup) lifecycle.writeState({ lastScenario: scenario });

    return {
      ready, already, scenario, mode: lifecycle.mode(),
      protectionIntent: intent, protectionRecovery, installationGaps,
    };
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
  // Same allowlist as api:get, for the handful of endpoints that
  // intentionally return plain text (e.g. ?format=md reports) instead of JSON.
  ipcMain.handle('api:getText', (_e, p) =>
    typeof p === 'string' && p.startsWith('/api/')
      ? engine.apiGetText(p, 4000)
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
  // The title-bar close button hides to the tray (same as the OS close). Quit
  // is only ever explicit, via the tray menu.
  ipcMain.on('window:close', () => win && win.hide());

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

  // Native, in-app error affordance - never a browser, never a traceback.
  // Buttons map to: 0 Retry . 1 Repair . 2 View Logs . 3 Continue Offline.
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
  createTray();
  app.on('activate', () => { showApp(); });
});

// Real quit path (tray -> Quit, or OS shutdown): let windows actually close.
app.on('before-quit', () => { isQuitting = true; });

app.on('window-all-closed', () => {
  // Normal window close only HIDES to tray, so this fires only on a real quit.
  stopPolling();
  if (tray) { try { tray.destroy(); } catch { /* ignore */ } tray = null; }
  // A portable build owns its engine child, so stop it with the window; an
  // installed build leaves the ValkyrieShield service running independently.
  if (lifecycle.mode() === 'portable') engine.stopPortableEngine();
  if (process.platform !== 'darwin') app.quit();
});
