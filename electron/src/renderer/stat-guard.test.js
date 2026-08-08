'use strict';
/* Source-level invariant: no stat card may render a telemetry number without
 * first checking that the poll actually succeeded.
 *
 * WHY A SOURCE TEST AND NOT A UNIT TEST:
 * The bug this guards against was never a wrong function -- statVal() is four
 * tokens long and obviously correct. The bug was that a call site was MISSED.
 * The topbar's blocked-counter shipped unguarded while its two siblings on the
 * adjacent lines were guarded; then the first fix corrected that one line and
 * left five more onTele() sites rendering the same false "0". A unit test of
 * statVal() would have passed the entire time, both before and after the bug.
 *
 * So the invariant worth enforcing is a property of the file, not of a
 * function: every animateNumber() call carrying telemetry goes through
 * statVal() or NO_DATA. Adding a new stat card without the guard fails here.
 *
 * Run with:  node --test electron/src/renderer/*.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const APP = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
const LINES = APP.split(/\r?\n/);

// Call sites that legitimately pass a non-telemetry value: these numbers do not
// come from the /api/stats poll, so "the poll failed" is not a state they have.
const EXEMPT = [
  /animateNumber\(\s*node/,            // inside animateNumber's own definition
  /card-cov/,                          // coverage panel: own endpoint, own guard
  /card-mttd|card-mttr/,               // metrics panel: own endpoint, own guard
  /card-inv/,                          // asset inventory: own endpoint, own guard
  // Dashboard renders through a loop; the guard is applied one line earlier
  // when `vals` is built. Covered instead by the dedicated `vals` test below,
  // which is stricter than this line check could be.
  /Object\.entries\(vals\)/,
  // Components page fetches /api/components, not /api/stats, and already
  // early-returns a "Could not reach the engine" state block before these
  // lines are reached -- so by the time they run, the data is real.
  /card-compTotal|card-compHealthy|card-compAttn/,
];

test('every telemetry stat card is guarded by statVal()/NO_DATA', () => {
  const offenders = [];
  LINES.forEach((line, i) => {
    if (!line.includes('animateNumber(')) return;
    if (EXEMPT.some((re) => re.test(line))) return;
    const guarded = line.includes('statVal(') || line.includes('NO_DATA');
    if (!guarded) offenders.push(`  line ${i + 1}: ${line.trim()}`);
  });
  assert.equal(
    offenders.length, 0,
    'These animateNumber() calls render a raw telemetry number and will show a\n'
    + 'false "0" whenever a poll fails. Wrap the value in statVal(up, ...):\n'
    + offenders.join('\n'),
  );
});

test('the Dashboard `vals` map guards every field it feeds to the cards', () => {
  // This is the stricter replacement for exempting the Object.entries(vals)
  // loop above: the loop is fine, but only because every value going INTO
  // `vals` was guarded. A new card added here with a bare `|| 0` is the exact
  // regression that shipped the first time.
  const start = APP.indexOf('const vals = {');
  assert.ok(start > -1, 'Dashboard `vals` map not found');
  const vals = APP.slice(start, APP.indexOf('};', start));
  const bare = vals.split(/\r?\n/)
    .filter((l) => /stats\.\w+\s*\|\|\s*0/.test(l))
    .map((l) => '  ' + l.trim());
  assert.equal(bare.length, 0,
    'These Dashboard fields render a raw 0 on a failed poll:\n' + bare.join('\n'));
});

test('statVal returns the number when up, NO_DATA when down', () => {
  // Re-derive the helper from source rather than importing (app.js is a browser
  // script, not a module) -- this keeps the test honest about the real text.
  assert.ok(/function statVal\(up, v\) \{ return up \? \(v \|\| 0\) : NO_DATA; \}/.test(APP),
    'statVal() is missing or its definition changed shape');
  assert.ok(/const NO_DATA = '—';/.test(APP), 'NO_DATA sentinel is missing');
});

test('animateNumber distinguishes no-data from layer-off from real zero', () => {
  // Three states that all used to render as "0". The sentinel branch must come
  // before the null branch, or NO_DATA would fall through and print "Off".
  const body = APP.slice(APP.indexOf('function animateNumber'));
  const noDataAt = body.indexOf('to === NO_DATA');
  const nullAt = body.indexOf('to == null');
  assert.ok(noDataAt > -1, 'animateNumber has no NO_DATA branch');
  assert.ok(nullAt > -1, 'animateNumber lost its null ("Off") branch');
  assert.ok(noDataAt < nullAt,
    'NO_DATA branch must precede the null branch or it renders as "Off"');
});

test('the NO_DATA branch preserves the last known value', () => {
  // Clearing dataset.v would make the counter animate up from 0 when the engine
  // returns, which reads as a burst of fresh activity that never happened.
  const start = APP.indexOf('to === NO_DATA');
  const branch = APP.slice(start, start + 420);
  assert.ok(!/dataset\.v\s*=/.test(branch),
    'NO_DATA branch must not reset dataset.v (last known value is kept so the\n'
    + 'number animates back from where it was, not up from zero)');
});
