'use strict';
/* =========================================================================
   Unit tests for engine.start()'s behaviour on an INCOMPLETE INSTALL, and for
   the repair that fixes one.

   Regression test for a real machine (2026-09-10): the ValkyrieShield service
   was healthy and answering on 8090, dns_active was true, and BOTH no-prompt
   scheduled tasks (ValkyrieArm / ValkyrieDisarm) were absent - register-tasks.ps1
   had never successfully run, which the installer only warns about. Pressing
   Start Protection then fell through to start_all.ps1, the source-checkout
   fallback, against an installed layout - the exact thing main.js's boot path
   and engine.js's installationGaps() comment both say must not happen - and
   returned started:true regardless. The UI waited ~48s for an arm marker that
   nothing was going to write, then reported failure with no explanation.

   child_process is a builtin, so the require.cache fake this directory uses for
   'electron' cannot reach it; engine.js resolves it through the module object
   instead so these tests can substitute schtasks and PowerShell.
   Run with: node --test electron/src/main/engine_start.test.js
   ========================================================================= */

const test = require('node:test');
const assert = require('node:assert/strict');

const ELECTRON_PATH = require.resolve('electron');
require.cache[ELECTRON_PATH] = {
  id: ELECTRON_PATH, filename: ELECTRON_PATH, loaded: true, children: [],
  exports: { net: { request: () => { throw new Error('no HTTP in these tests'); } } },
};

const ENGINE_PATH = require.resolve('./engine.js');

// Stand in for the OS: `tasks` is the set of scheduled tasks that "exist", and
// every schtasks/PowerShell invocation is recorded so a test can assert what
// the app actually tried to do.
function fakeHost(t, {
  tasks = [], mode = 'installed', registers = null, hasRegisterScript = true,
} = {}) {
  const present = new Set(tasks);
  const calls = { query: [], run: [], spawned: [], powershell: [] };
  const cp = require('child_process');

  // A test process has no process.resourcesPath, so the packaged helper never
  // exists on disk here. Answer only for that script and defer to the real fs
  // for everything else (engineRoot() uses existsSync too).
  const fs = require('fs');
  const realExists = fs.existsSync.bind(fs);
  t.mock.method(fs, 'existsSync', (target) =>
    (String(target).includes('register-tasks.ps1') ? hasRegisterScript : realExists(target)));

  t.mock.method(cp, 'execFile', (file, args, opts, cb) => {
    const done = typeof opts === 'function' ? opts : cb;
    if (/schtasks/i.test(file)) {
      const name = args[args.indexOf('/tn') + 1];
      if (args[0] === '/query') {
        calls.query.push(name);
        return void setImmediate(() => done(present.has(name) ? null : new Error('not found')));
      }
      calls.run.push(name);
      return void setImmediate(() => done(null));
    }
    // PowerShell -Command "<Start-Process ... -Verb RunAs ...>"
    calls.powershell.push(args[args.length - 1]);
    if (registers) registers.forEach((n) => present.add(n));
    return void setImmediate(() => done(null));
  });

  t.mock.method(cp, 'spawn', (file, args) => {
    calls.spawned.push({ file, args });
    return { unref() {}, on() {}, killed: false };
  });

  t.mock.method(require('./lifecycle'), 'mode', () => mode);
  delete require.cache[ENGINE_PATH];
  return { engine: require('./engine.js'), calls };
}

test('start: an installed layout missing the arm task refuses instead of running the dev script', async (t) => {
  const { engine, calls } = fakeHost(t, { tasks: [] });
  const r = await engine.start();

  assert.equal(r.started, false, 'must not claim it started something it did not');
  assert.deepEqual(r.gaps, ['ValkyrieArm', 'ValkyrieDisarm']);
  assert.deepEqual(calls.spawned, [], 'start_all.ps1 must NOT be run against an installed layout');
  assert.deepEqual(calls.run, [], 'no task should have been triggered');
});

test('start: a healthy installed layout still arms through the no-prompt task', async (t) => {
  const { engine, calls } = fakeHost(t, { tasks: ['ValkyrieArm', 'ValkyrieDisarm'] });
  const r = await engine.start();

  assert.equal(r.started, true);
  assert.equal(r.via, 'arm-task');
  assert.deepEqual(calls.run, ['ValkyrieArm']);
  assert.deepEqual(calls.spawned, []);
});

test('start: a source checkout still falls back to start_all.ps1', async (t) => {
  const { engine, calls } = fakeHost(t, { tasks: [], mode: 'development' });
  const r = await engine.start();

  assert.equal(r.started, true);
  assert.equal(r.via, 'script');
  assert.equal(calls.spawned.length, 1, 'the dev fallback is correct OFF an installed layout');
  assert.match(String(calls.spawned[0].args.join(' ')), /start_all\.ps1/);
});

test('installationGaps: names exactly the tasks that are missing', async (t) => {
  const { engine } = fakeHost(t, { tasks: ['ValkyrieArm'] });
  assert.deepEqual(await engine.installationGaps(), ['ValkyrieDisarm']);
});

test('repairInstallation: reports success only if the tasks are really there afterwards', async (t) => {
  // The elevated helper runs and the tasks appear.
  const ok = fakeHost(t, { tasks: [], registers: ['ValkyrieArm', 'ValkyrieDisarm'] });
  const good = await ok.engine.repairInstallation();
  assert.equal(good.ok, true);
  assert.deepEqual(good.gaps, []);
  assert.equal(ok.calls.powershell.length, 1);
  assert.match(ok.calls.powershell[0], /-Verb RunAs/,
    'registering a Highest-runlevel task needs elevation');
  assert.match(ok.calls.powershell[0], /register-tasks\.ps1/);
});

test('repairInstallation: a declined UAC prompt is reported as still broken, not as success', async (t) => {
  // registers: null -> the helper "runs" but nothing is registered, which is
  // what a declined elevation prompt looks like from here. Trusting the exit
  // code instead of re-checking the OS would call this a successful repair.
  const { engine, calls } = fakeHost(t, { tasks: [], registers: null });
  const r = await engine.repairInstallation();

  assert.equal(r.ok, false);
  assert.deepEqual(r.gaps, ['ValkyrieArm', 'ValkyrieDisarm']);
  assert.equal(calls.powershell.length, 1, 'it should still have attempted the repair');
});

test('repairInstallation: a healthy install does no work and prompts for nothing', async (t) => {
  const { engine, calls } = fakeHost(t, { tasks: ['ValkyrieArm', 'ValkyrieDisarm'] });
  const r = await engine.repairInstallation();

  assert.equal(r.ok, true);
  assert.equal(r.via, 'nothing-to-do');
  assert.deepEqual(calls.powershell, [], 'never raise a UAC prompt on a healthy machine');
});

test('repairInstallation: says so plainly when the helper script itself is missing', async (t) => {
  const { engine, calls } = fakeHost(t, { tasks: [], hasRegisterScript: false });
  const r = await engine.repairInstallation();

  assert.equal(r.ok, false);
  assert.equal(r.via, 'missing-register-tasks');
  assert.deepEqual(calls.powershell, [], 'nothing to run, so no elevation prompt');
});
