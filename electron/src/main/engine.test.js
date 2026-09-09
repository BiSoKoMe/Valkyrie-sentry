'use strict';
/* =========================================================================
   Unit tests for engine.js's control-token handling.

   Regression test for a real bug found during an architecture audit
   (2026-07-30): the Electron main process cached the control token forever,
   but the Python engine mints a FRESH one on every launch. If the engine
   restarts under a still-running Electron shell (POST /api/system/restart,
   a component restart, the self-healing watchdog recovering a crash), every
   subsequent POST would silently 403 with the stale cached token until the
   whole app was relaunched - including the restart control itself being the
   one action that broke every other control afterward.

   'electron's net module is faked by pre-populating require.cache with a
   fake module BEFORE requiring engine.js (CommonJS's module cache means
   engine.js's own `const { net } = require('electron')` resolves to this
   fake instead of running the real (stub, path-string-only outside the
   Electron runtime) 'electron' package). No real listener, no new
   dependency - same zero-dependency style as the existing renderer tests.

   Updated 2026-08-07 for commit 34d037c, which replaced Node's http module
   with Electron's net module for the actual loopback API calls (raw
   Winsock connections were getting silently black-holed on a host running
   Valkyrie's own traffic filtering - see engine.js's netGet() comment).
   Before that fix this file mocked 'http'; net.request's shape differs
   (setHeader()/abort() instead of a headers option, and the request
   object itself emits 'response' rather than a get()/request() callback
   receiving it), so the fake had to change shape, not just target.
   Run with: node --test electron/src/main/engine.test.js
   ========================================================================= */

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');

// ---------------------------------------------------------------------------
// Fake net.request layer. `plan` is a queue of {statusCode, body} the next
// request consumes in order, so each test scripts exactly the server
// responses it needs without a real socket.
// ---------------------------------------------------------------------------
let _plan = [];
function scriptResponses(...responses) { _plan = responses.slice(); }

// Mirrors Electron's net.ClientRequest/IncomingMessage shape closely enough
// for engine.js's netGet()/apiRequest(): the request is an EventEmitter with
// setHeader/write/end/abort, 'response' fires with an EventEmitter carrying
// statusCode + 'data'/'end'.
function fakeNetRequest(_options) {
  const req = new EventEmitter();
  req.setHeader = () => {};
  req.write = () => {};
  req.abort = () => { req.emit('error', new Error('aborted')); };
  req.end = () => {
    const next = _plan.shift() || { statusCode: 500, body: '{}' };
    setImmediate(() => {
      const res = new EventEmitter();
      res.statusCode = next.statusCode;
      req.emit('response', res);
      setImmediate(() => {
        res.emit('data', Buffer.from(next.body));
        res.emit('end');
      });
    });
  };
  return req;
}

const ELECTRON_PATH = require.resolve('electron');
require.cache[ELECTRON_PATH] = {
  id: ELECTRON_PATH, filename: ELECTRON_PATH, loaded: true, children: [],
  exports: { net: { request: fakeNetRequest } },
};

// engine.js's _tokenCache is module-level state, exactly like it would be in
// a real Electron process - so each test needs a FRESH module instance (a
// fresh cache), same as each test simulating its own independent app launch.
// Reusing one require()'d instance across tests leaked test 1's cached token
// into test 2 and desynced the scripted response queue against it.
const ENGINE_PATH = require.resolve('./engine.js');
function freshEngine(t, tokens = ['A'.repeat(32)]) {
  t.mock.method(require('./lifecycle'), 'engineDataDir', () => 'test-data');
  let index = 0;
  t.mock.method(require('fs').promises, 'readFile', async (filename) => {
    assert.equal(filename, require('path').join('test-data', 'control', 'token'));
    const value = tokens[Math.min(index++, tokens.length - 1)];
    if (value instanceof Error) throw value;
    return value;
  });
  delete require.cache[ENGINE_PATH];
  return require('./engine.js');
}

test('apiPost: a stale cached token is retried once with a fresh one', async (t) => {
  const engine = freshEngine(t, ['A'.repeat(32), 'B'.repeat(32)]);
  // 1st apiPost call: controlToken() fetches "token-A" (GET), then the POST
  // itself is rejected 403 (simulating the engine having restarted and
  // minted a new token since "token-A" was cached), so apiPost refetches
  // (GET -> "token-B") and retries the POST, which now succeeds.
  scriptResponses(
    { statusCode: 403, body: JSON.stringify({ error: 'forbidden: missing or invalid control token' }) }, // stale POST
    { statusCode: 200, body: JSON.stringify({ ok: true }) },          // retried POST succeeds
  );
  const result = await engine.apiPost('/api/edr/respond', { action: 'isolate_host' });
  assert.deepEqual(result, { ok: true });
});

test('apiPost: a genuinely forbidden request is NOT retried forever', async (t) => {
  const engine = freshEngine(t);
  // The refetched token is identical to the one that just failed -- a real
  // auth failure, not staleness -- so apiPost must surface the error rather
  // than loop.
  scriptResponses(
    { statusCode: 403, body: JSON.stringify({ error: 'forbidden' }) },
  );
  await assert.rejects(
    () => engine.apiPost('/api/edr/respond', {}),
    /forbidden/
  );
});

test('apiPost: a non-auth failure is never retried', async (t) => {
  const engine = freshEngine(t);
  // A 500 must propagate immediately -- retrying a fresh token would not
  // help and would mask a real server error as a token problem.
  scriptResponses(
    { statusCode: 500, body: JSON.stringify({ error: 'internal error' }) },
  );
  await assert.rejects(
    () => engine.apiPost('/api/edr/respond', {}),
    /internal error/
  );
});

test('apiPost: inaccessible credentials do not trigger HTTP bootstrap or mutation', async (t) => {
  const engine = freshEngine(t, [new Error('EACCES')]);
  scriptResponses({ statusCode: 200, body: '{}' });
  await assert.rejects(() => engine.apiPost('/api/edr/respond', {}), /authorized local session/);
  assert.equal(_plan.length, 1);
});

// ---------------------------------------------------------------------------
// waitUntilArmed - regression test for a real report (2026-09-07): "Start
// Protection" reported success the instant the (normally already-running)
// engine answered a ping, while the real arm attempt - an INDEPENDENT
// scheduled task this call never otherwise waited on - was still silently
// retrying in the background for up to another 35+ seconds. The button
// settled, then the UI read "Not Protected" for the whole gap, which looks
// exactly like the click did nothing.
// ---------------------------------------------------------------------------
test('waitUntilArmed: only resolves true once BOTH the marker and dns_active agree', async (t) => {
  const engine = freshEngine(t);
  t.mock.method(require('fs'), 'existsSync', (p) => {
    assert.equal(p, require('path').join('test-data', 'valkyrie_dns_adapter.txt'));
    return true;   // the marker was written; dns_active is the piece still catching up
  });
  scriptResponses(
    { statusCode: 200, body: JSON.stringify({ dns_active: false }) },  // still arming
    { statusCode: 200, body: JSON.stringify({ dns_active: false }) },  // still arming
    { statusCode: 200, body: JSON.stringify({ dns_active: true }) },   // now armed
  );
  const ticks = [];
  const armed = await engine.waitUntilArmed((isArmed, i) => ticks.push(isArmed), { attempts: 5, intervalMs: 1 });
  assert.equal(armed, true);
  assert.deepEqual(ticks, [false, false, true]);
});

test('waitUntilArmed: gives up and returns false after exhausting its attempts', async (t) => {
  const engine = freshEngine(t);
  t.mock.method(require('fs'), 'existsSync', () => false);   // marker never appears
  scriptResponses(
    { statusCode: 200, body: JSON.stringify({ dns_active: false }) },
    { statusCode: 200, body: JSON.stringify({ dns_active: false }) },
    { statusCode: 200, body: JSON.stringify({ dns_active: false }) },
  );
  const armed = await engine.waitUntilArmed(() => {}, { attempts: 3, intervalMs: 1 });
  assert.equal(armed, false);
});

test('waitUntilArmed: a transient API error mid-poll does not abort the wait', async (t) => {
  const engine = freshEngine(t);
  t.mock.method(require('fs'), 'existsSync', () => true);
  scriptResponses(
    { statusCode: 500, body: JSON.stringify({ error: 'temporary hiccup' }) },  // one bad poll
    { statusCode: 200, body: JSON.stringify({ dns_active: true }) },          // then it recovers
  );
  const armed = await engine.waitUntilArmed(() => {}, { attempts: 3, intervalMs: 1 });
  assert.equal(armed, true);
});
