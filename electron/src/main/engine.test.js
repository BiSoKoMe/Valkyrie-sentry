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

   http is faked by monkey-patching the shared 'http' module object BEFORE
   requiring engine.js (CommonJS's module cache means both this file and
   engine.js share the exact same object, so patching .request/.get here is
   visible to engine.js's own `const http = require('http')`). No real
   listener, no new dependency — same zero-dependency style as the existing
   renderer tests. Run with: node --test electron/src/main/engine.test.js
   ========================================================================= */

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const http = require('http');

// ---------------------------------------------------------------------------
// Fake HTTP layer. `plan` is a queue of {statusCode, body} the next request
// consumes in order, so each test scripts exactly the server responses it
// needs without a real socket.
// ---------------------------------------------------------------------------
let _plan = [];
function scriptResponses(...responses) { _plan = responses.slice(); }

function fakeRequest(options, callback) {
  const req = new EventEmitter();
  req.write = () => {};
  req.end = () => {
    const next = _plan.shift() || { statusCode: 500, body: '{}' };
    setImmediate(() => {
      const res = new EventEmitter();
      res.statusCode = next.statusCode;
      callback(res);
      setImmediate(() => {
        res.emit('data', Buffer.from(next.body));
        res.emit('end');
      });
    });
  };
  return req;
}

http.request = fakeRequest;
http.get = (options, callback) => {
  const req = fakeRequest(options, callback);
  req.end();
  return req;
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
