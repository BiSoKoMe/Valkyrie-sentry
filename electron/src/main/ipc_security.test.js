'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const security = require('./ipc_security');

test('only the exact main frame in the current application window is trusted', () => {
  const mainFrame = { url: security.PAGE };
  const contents = { mainFrame, isDestroyed: () => false };
  const win = { webContents: contents, isDestroyed: () => false };
  assert.equal(security.trustedSender({ sender: contents, senderFrame: mainFrame }, win), true);
  assert.equal(security.trustedSender({ sender: contents, senderFrame: { url: security.PAGE } }, win), false);
  assert.equal(security.trustedSender({ sender: {}, senderFrame: mainFrame }, win), false);
  mainFrame.url = 'https://untrusted.example/';
  assert.equal(security.trustedSender({ sender: contents, senderFrame: mainFrame }, win), false);
  assert.equal(security.trustedSender({}, null), false);
});

test('mutation bridge permits named operations and rejects path tricks', () => {
  assert.deepEqual(security.postArguments({ path: '/api/edr/respond', body: { dry_run: true } }),
    { pathname: '/api/edr/respond', body: { dry_run: true } });
  for (const path of ['/api/debug/telemetry/fault', '/api/browser/events', '/api/future-action',
    '/api/../system/shutdown', '/api/%2e%2e/shutdown', '/api/edr/respond?token=foo',
    '/api/edr/respond#fragment', '/api/edr\\respond', 'https://untrusted.example/api/edr/respond']) {
    assert.throws(() => security.postArguments({ path }), /Blocked/);
  }
  assert.throws(() => security.postArguments({ path: '/api/edr/respond', body: { dry_run: 'false' } }));
  assert.throws(() => security.postArguments({ path: '/api/edr/respond', body: { value: 'x'.repeat(65537) } }));
});

test('registration wrapper refuses an untrusted sender before dispatch', () => {
  const handlers = {};
  let calls = 0;
  const raw = { handle: (key, fn) => { handlers[key] = fn; }, on: (key, fn) => { handlers[key] = fn; } };
  const ipc = security.guardIpc(raw, () => null);
  ipc.handle('control', () => { calls++; });
  ipc.on('window:close', () => { calls++; });
  assert.throws(() => handlers.control({}), /Untrusted/);
  handlers['window:close']({});
  assert.equal(calls, 0);
});
