'use strict';
/* =========================================================================
   Unit tests for protection_state.decideBootAction() - the pure decision
   that replaced boot()'s old "isUp() true => nothing to do" logic.

   No mocking needed: the function under test touches no filesystem, network,
   or child process (same reasoning as valkyrie/host_safety.py's
   decide_dns_action, which this module was deliberately built to mirror).

   Run with: node --test electron/src/main/protection_state.test.js
   ========================================================================= */

const test = require('node:test');
const assert = require('node:assert/strict');
const { decideBootAction, PROTECTION_INTENT, BOOT_ACTION } = require('./protection_state');

// --- Case 1: service down, protection never enabled -----------------------
test('installed, engine down, intent unset -> leave (NSSM recovers the service; never arm unasked)', () => {
  const action = decideBootAction({
    engineUp: false, intent: PROTECTION_INTENT.UNSET, mode: 'installed',
    protected: null, noAutostart: false,
  });
  assert.equal(action, BOOT_ACTION.LEAVE);
});

test('development, engine down, intent unset -> leave (no "engine-only, no-arm" lever exists in dev mode)', () => {
  const action = decideBootAction({
    engineUp: false, intent: PROTECTION_INTENT.UNSET, mode: 'development',
    protected: null, noAutostart: false,
  });
  assert.equal(action, BOOT_ACTION.LEAVE);
});

test('portable, engine down, intent unset -> ensure-engine (portable start() never touches DNS)', () => {
  const action = decideBootAction({
    engineUp: false, intent: PROTECTION_INTENT.UNSET, mode: 'portable',
    protected: null, noAutostart: false,
  });
  assert.equal(action, BOOT_ACTION.ENSURE_ENGINE);
});

// --- Case 2: service up, protection disabled, user never enabled ----------
test('installed, engine up, intent unset -> leave (remain disarmed)', () => {
  const action = decideBootAction({
    engineUp: true, intent: PROTECTION_INTENT.UNSET, mode: 'installed',
    protected: false, noAutostart: false,
  });
  assert.equal(action, BOOT_ACTION.LEAVE);
});

test('installed, engine up, intent explicitly disabled -> leave', () => {
  const action = decideBootAction({
    engineUp: true, intent: PROTECTION_INTENT.DISABLED, mode: 'installed',
    protected: false, noAutostart: false,
  });
  assert.equal(action, BOOT_ACTION.LEAVE);
});

// --- Case 3: service up, protection enabled, DNS correctly redirected -----
test('installed, engine up, intent enabled, already protected -> leave (nothing to fix)', () => {
  const action = decideBootAction({
    engineUp: true, intent: PROTECTION_INTENT.ENABLED, mode: 'installed',
    protected: true, noAutostart: false,
  });
  assert.equal(action, BOOT_ACTION.LEAVE);
});

// --- Case 4: service up, protection enabled, DNS externally reset ---------
test('installed, engine up, intent enabled, NOT protected -> reconcile-arm (the core recovery case)', () => {
  const action = decideBootAction({
    engineUp: true, intent: PROTECTION_INTENT.ENABLED, mode: 'installed',
    protected: false, noAutostart: false,
  });
  assert.equal(action, BOOT_ACTION.RECONCILE_ARM);
});

// --- Case 5: stale marker (isProtected()-only would say true; the live,
// truthful telemetry().protected this function is fed already resolves the
// stale-marker case to false before it ever reaches this decision) ---------
test('stale marker resolved to protected:false upstream -> still reconciles when intent is enabled', () => {
  // telemetry().protected = marker && dns_active. A stale marker with
  // dns_active:false already yields false by the time it reaches here -
  // decideBootAction must never re-trust the marker on its own.
  const action = decideBootAction({
    engineUp: true, intent: PROTECTION_INTENT.ENABLED, mode: 'installed',
    protected: false, noAutostart: false,
  });
  assert.equal(action, BOOT_ACTION.RECONCILE_ARM);
});

test('stale marker resolved to protected:false upstream, intent unset -> leave, not protected', () => {
  const action = decideBootAction({
    engineUp: true, intent: PROTECTION_INTENT.UNSET, mode: 'installed',
    protected: false, noAutostart: false,
  });
  assert.equal(action, BOOT_ACTION.LEAVE);
});

// --- noAutostart escape hatch always wins ----------------------------------
test('VALKYRIE_NO_AUTOSTART short-circuits every branch, even with intent enabled and disarmed', () => {
  assert.equal(decideBootAction({
    engineUp: false, intent: PROTECTION_INTENT.ENABLED, mode: 'installed',
    protected: null, noAutostart: true,
  }), BOOT_ACTION.LEAVE);
  assert.equal(decideBootAction({
    engineUp: true, intent: PROTECTION_INTENT.ENABLED, mode: 'installed',
    protected: false, noAutostart: true,
  }), BOOT_ACTION.LEAVE);
});

// --- portable never arms, even fully enabled -------------------------------
test('portable, engine up, intent enabled, not protected -> leave (portable cannot arm system DNS)', () => {
  const action = decideBootAction({
    engineUp: true, intent: PROTECTION_INTENT.ENABLED, mode: 'portable',
    protected: false, noAutostart: false,
  });
  assert.equal(action, BOOT_ACTION.LEAVE);
});

// --- Case 7: repeated calls converge, never re-arm once actually protected -
test('calling again after protected becomes true no longer reconciles (no duplicate arm)', () => {
  const stillDisarmed = decideBootAction({
    engineUp: true, intent: PROTECTION_INTENT.ENABLED, mode: 'installed',
    protected: false, noAutostart: false,
  });
  assert.equal(stillDisarmed, BOOT_ACTION.RECONCILE_ARM);

  // Simulates the boot() re-check immediately after a successful arm.
  const nowProtected = decideBootAction({
    engineUp: true, intent: PROTECTION_INTENT.ENABLED, mode: 'installed',
    protected: true, noAutostart: false,
  });
  assert.equal(nowProtected, BOOT_ACTION.LEAVE);

  // And a second, independent boot() call in the same state is identical -
  // the function is pure, so repetition can never accumulate action.
  const repeated = decideBootAction({
    engineUp: true, intent: PROTECTION_INTENT.ENABLED, mode: 'installed',
    protected: true, noAutostart: false,
  });
  assert.equal(repeated, BOOT_ACTION.LEAVE);
});
