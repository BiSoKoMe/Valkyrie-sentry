'use strict';
const { pathToFileURL } = require('url');
const path = require('path');

const PAGE = pathToFileURL(path.join(__dirname, '..', 'renderer', 'index.html')).href;
const MAX_BODY_BYTES = 64 * 1024;
const POST_ROUTES = [
  /^\/api\/(telemetry\/(kill|restore)|mac\/(randomize|restore)|profile\/set)$/,
  /^\/api\/(system\/(restart|shutdown)|meeting\/(start|stop))$/,
  /^\/api\/(ransomware|amsi)\/self-test$/,
  /^\/api\/components\/[A-Za-z0-9_.-]+\/restart$/,
  /^\/api\/edr\/(respond|hunt)$/,
  /^\/api\/edr\/incidents\/[A-Za-z0-9_-]+\/(status|investigate|triage)$/,
];

function trustedSender(event, win) {
  if (!win || win.isDestroyed()) return false;
  const contents = win.webContents;
  if (!contents || contents.isDestroyed()) return false;
  const frame = event && event.senderFrame;
  return !!frame && event.sender === contents && frame === contents.mainFrame
    && frame.url === PAGE;
}

function apiPath(value, method = 'GET') {
  if (typeof value !== 'string' || value.length > 4096 || !value.startsWith('/api/')) {
    throw new Error('Blocked API path');
  }
  // Reject path normalization tricks before URL parsing can hide them.
  const pathname = value.split('?')[0];
  if (/[\\#\s]/.test(value) || /%|\/\.|\/\//.test(pathname)) throw new Error('Blocked API path');
  if (method === 'POST' && (value.includes('?') || !POST_ROUTES.some(pattern => pattern.test(value)))) {
    throw new Error('Blocked API operation');
  }
  return value;
}

function postArguments(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid API request');
  const pathname = apiPath(value.path, 'POST');
  const body = value.body === undefined ? {} : value.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Invalid API body');
  if (Buffer.byteLength(JSON.stringify(body), 'utf8') > MAX_BODY_BYTES) throw new Error('API body exceeds limit');
  if ('dry_run' in body && typeof body.dry_run !== 'boolean') throw new Error('dry_run must be boolean');
  return { pathname, body };
}

function guardIpc(raw, getWindow) {
  return {
    handle(channel, handler) {
      raw.handle(channel, (event, ...args) => {
        if (!trustedSender(event, getWindow())) throw new Error('Untrusted IPC sender');
        return handler(event, ...args);
      });
    },
    on(channel, handler) {
      raw.on(channel, (event, ...args) => {
        if (trustedSender(event, getWindow())) handler(event, ...args);
      });
    },
  };
}

module.exports = { trustedSender, apiPath, postArguments, guardIpc, PAGE };
