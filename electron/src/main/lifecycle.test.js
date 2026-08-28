'use strict';
/* =========================================================================
   Unit tests for lifecycle.js's state persistence - specifically the
   writeState() merge fix and the new protectionIntent()/setProtectionIntent()
   pair this task added.

   REGRESSION BEING GUARDED: writeState() used to REPLACE install-state.json
   wholesale on every call (`{stateVersion, version, mode, initializedAt: NOW,
   ...extra}` with no read of the existing file first). That was harmless
   while there was exactly one caller (boot()'s `{lastScenario}`), but the
   moment a second, independent caller needed to persist something
   (protectionIntent, written from the Start/Stop Protection toggle) it would
   have silently erased whatever boot() had already written, and reset
   initializedAt - "first boot time" - to "whenever protection was last
   toggled". Fixed by merging onto readState() first.

   'electron' is faked the same way engine.test.js already does it: a real
   module resolution replaced with a plain object in require.cache before
   lifecycle.js is required, so `const { app } = require('electron')`
   resolves to the fake. Each test gets a real temp directory as `userData`
   and forces isPackaged:true (mode() === 'installed') so writeState()/
   readState() never touch this repo's own data/ folder.

   Run with: node --test electron/src/main/lifecycle.test.js
   ========================================================================= */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ELECTRON_PATH = require.resolve('electron');
const LIFECYCLE_PATH = require.resolve('./lifecycle.js');

function freshLifecycle(userDataDir) {
  delete require.cache[LIFECYCLE_PATH];
  require.cache[ELECTRON_PATH] = {
    id: ELECTRON_PATH, filename: ELECTRON_PATH, loaded: true, children: [],
    exports: {
      app: {
        isPackaged: true, // forces mode() === 'installed'
        getVersion: () => '1.2.3-test',
        getPath: (name) => {
          if (name === 'userData') return userDataDir;
          throw new Error(`fake app.getPath: unexpected "${name}"`);
        },
      },
    },
  };
  return require('./lifecycle.js');
}

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'valkyrie-lifecycle-test-'));
}

test('writeState merges onto existing state instead of replacing it', () => {
  const lifecycle = freshLifecycle(tmpDir());
  lifecycle.writeState({ lastScenario: 'fresh' });
  const firstInitializedAt = lifecycle.readState().initializedAt;

  lifecycle.setProtectionIntent('enabled');
  const state = lifecycle.readState();

  assert.equal(state.lastScenario, 'fresh', 'an earlier field must survive a later, unrelated write');
  assert.equal(state.protectionIntent, 'enabled');
  assert.equal(state.initializedAt, firstInitializedAt,
    'initializedAt is first-boot time, not last-write time');
});

test('protectionIntent() defaults to "unset" before any explicit enable/disable', () => {
  const lifecycle = freshLifecycle(tmpDir());
  assert.equal(lifecycle.protectionIntent(), 'unset');
});

test('setProtectionIntent persists across a fresh require (simulates an app restart)', () => {
  const dir = tmpDir();
  freshLifecycle(dir).setProtectionIntent('enabled');
  assert.equal(freshLifecycle(dir).protectionIntent(), 'enabled');
});

test('setProtectionIntent(disabled) after enabled correctly overwrites it, not merges as a set', () => {
  const dir = tmpDir();
  const lifecycle = freshLifecycle(dir);
  lifecycle.setProtectionIntent('enabled');
  lifecycle.setProtectionIntent('disabled');
  assert.equal(lifecycle.protectionIntent(), 'disabled');
});
