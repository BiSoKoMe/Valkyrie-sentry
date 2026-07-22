'use strict';
// ---------------------------------------------------------------------------
// preload.js — the ONLY bridge between the sandboxed renderer and the shell.
//
// contextIsolation is on, so the renderer sees exactly this frozen `valkyrie`
// object and nothing else — no Node, no ipcRenderer, no require. Every capability
// is an explicit, named channel.
// ---------------------------------------------------------------------------

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('valkyrie', {
  // ── Boot / engine lifecycle ──────────────────────────────────────────
  boot: () => ipcRenderer.invoke('boot'),
  lifecycleInfo: () => ipcRenderer.invoke('lifecycle:info'),
  repair: () => ipcRenderer.invoke('lifecycle:repair'),
  engineStatus: () => ipcRenderer.invoke('engine:status'),
  startEngine: () => ipcRenderer.invoke('engine:start'),
  stopEngine: () => ipcRenderer.invoke('engine:stop'),

  // First-boot step events ("Preparing Valkyrie" sequence).
  onBootStep: (cb) => {
    const h = (_e, data) => cb(data);
    ipcRenderer.on('boot:step', h);
    return () => ipcRenderer.removeListener('boot:step', h);
  },

  // Splash listens to real readiness ticks to pace its animated checks.
  onEngineProgress: (cb) => {
    const h = (_e, data) => cb(data);
    ipcRenderer.on('engine:progress', h);
    return () => ipcRenderer.removeListener('engine:progress', h);
  },

  // ── Live telemetry (pushed from main every ~1.5s) ────────────────────
  onTelemetry: (cb) => {
    const h = (_e, data) => cb(data);
    ipcRenderer.on('telemetry', h);
    return () => ipcRenderer.removeListener('telemetry', h);
  },
  telemetryNow: () => ipcRenderer.invoke('telemetry:now'),

  // Allowlisted live-data bridge for per-page views.
  api: {
    get: (p) => ipcRenderer.invoke('api:get', p),
    getText: (p) => ipcRenderer.invoke('api:getText', p),
    post: (p, body) => ipcRenderer.invoke('api:post', { path: p, body }),
  },

  // ── Window controls (custom title bar) ───────────────────────────────
  minimize: () => ipcRenderer.send('window:minimize'),
  maximize: () => ipcRenderer.send('window:maximize'),
  close: () => ipcRenderer.send('window:close'),
  onWindowState: (cb) => {
    const h = (_e, data) => cb(data);
    ipcRenderer.on('window:state', h);
    return () => ipcRenderer.removeListener('window:state', h);
  },

  // ── Misc ─────────────────────────────────────────────────────────────
  openLogs: () => ipcRenderer.invoke('open-logs'),
  appInfo: () => ipcRenderer.invoke('app:info'),
  errorDialog: (title, message) =>
    ipcRenderer.invoke('dialog:error', { title, message }),
});
