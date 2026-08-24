'use strict';
/* =========================================================================
   Unit tests for engine.js's control-token handling.

   Regression test for a real bug found during an architecture audit
   (2026-07-30): the Electron main process cached the control token forever,
   but the Python engine mints a FRESH one on every launch. If the engine
   restarts under a still-running Electron shell (POST /api/system/restart,
   a component restart, the self-healing watchdog recovering a crash), every
   subsequent POST would silently 403 with the stale cached token until the
   whole app was relaunched — including the restart control itself being the
   one action that broke every other control afterward.

   'electron's net module is faked by pre-populating require.cache with a
   fake module BEFORE requiring engine.js (CommonJS's module cache means
   engine.js's own `const { net } = require('electron')` resolves to this
   fake instead of running the real (stub, path-string-only outside the
   Electron runtime) 'electron' package). No real listener, no new
   dependency — same zero-dependency style as the existing renderer tests.

   Updated 2026-08-07 for commit 34d037c, which replaced Node's http module
   with Electron's net module for the actual loopback API calls (raw
   Winsock connections were getting silently black-holed on a host running
   Valkyrie's own traffic filtering — see engine.js's netGet() comment).
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
// a real Electron process — so each test needs a FRESH module instance (a
// fresh cache), same as each test simulating its own independent app launch.
// Reusing one require()'d instance across tests leaked test 1's cached token
// into test 2 and desynced the scripted response queue against it.
const ENGINE_PATH = require.resolve('./engine.js');
function freshEngine() {
  delete require.cache[ENGINE_PATH];
  return require('./engine.js');
}

test('apiPost: a stale cached token is retried once with a fresh one', async () => {
  const engine = freshEngine();
  // 1st apiPost call: controlToken() fetches "token-A" (GET), then the POST
  // itself is rejected 403 (simulating the engine having restarted and
  // minted a new token since "token-A" was cached), so apiPost refetches
  // (GET -> "token-B") and retries the POST, which now succeeds.
  scriptResponses(
    { statusCode: 200, body: JSON.stringify({ token: 'token-A' }) },  // controlToken()
    { statusCode: 403, body: JSON.stringify({ error: 'forbidden: missing or invalid control token' }) }, // stale POST
    { statusCode: 200, body: JSON.stringify({ token: 'token-B' }) },  // controlToken(force)
    { statusCode: 200, body: JSON.stringify({ ok: true }) },          // retried POST succeeds
  );
  const result = await engine.apiPost('/api/edr/respond', { action: 'isolate_host' });
  assert.deepEqual(result, { ok: true });
});

test('apiPost: a genuinely forbidden request is NOT retried forever', async () => {
  const engine = freshEngine();
  // The refetched token is identical to the one that just failed -- a real
  // auth failure, not staleness -- so apiPost must surface the error rather
  // than loop.
  scriptResponses(
    { statusCode: 200, body: JSON.stringify({ token: 'token-C' }) },
    { statusCode: 403, body: JSON.stringify({ error: 'forbidden' }) },
    { statusCode: 200, body: JSON.stringify({ token: 'token-C' }) },  // same token again
  );
  await assert.rejects(
    () => engine.apiPost('/api/edr/respond', {}),
    /forbidden/
  );
});

test('apiPost: a non-auth failure is never retried', async () => {
  const engine = freshEngine();
  // A 500 must propagate immediately -- retrying a fresh token would not
  // help and would mask a real server error as a token problem.
  scriptResponses(
    { statusCode: 200, body: JSON.stringify({ token: 'token-D' }) },
    { statusCode: 500, body: JSON.stringify({ error: 'internal error' }) },
  );
  await assert.rejects(
    () => engine.apiPost('/api/edr/respond', {}),
    /internal error/
  );
});
