'use strict';
/* The "Privacy actions" header metric must report the privacy layer's OWN work.
 *
 * THE BUG THIS PINS (caught live on a real machine, 2026-09-07):
 * privacyActionCount() returned dns_blocked + fw_blocked + elements_cleaned --
 * which is exactly the "Blocked" chip's value plus one more term. With
 * elements_cleaned at null (the privacy layer switched off), the header showed
 *
 *     BLOCKED 12,789        PRIVACY ACTIONS 12,789
 *
 * side by side: the same 12,789 DNS/firewall blocks counted twice under two
 * different names, reading to a user as ~25,000 things done. Worse, it meant a
 * completely inert privacy engine still rendered a large reassuring number,
 * because the sum was dominated by DNS blocking -- the one figure that would
 * have revealed the privacy layer was doing nothing was buried inside it.
 *
 * Two invariants, both real failure modes, so this cannot quietly regress:
 *   1. the metric never sums the blocked counters back in;
 *   2. null ("layer is off") never collapses into 0 ("ran, found nothing").
 *
 * Run with:  node --test electron/src/renderer/privacy-metric.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const APP = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');

// Pull the real function out of app.js (a browser-global script, not a module)
// and evaluate it, so these assertions run the shipping implementation rather
// than a copy that could drift away from it.
function loadPrivacyActionCount() {
  const start = APP.indexOf('function privacyActionCount(');
  assert.notEqual(start, -1, 'privacyActionCount must still exist in app.js');
  // Walk braces from the function's opening { to its matching close.
  const open = APP.indexOf('{', start);
  let depth = 0;
  let end = -1;
  for (let i = open; i < APP.length; i += 1) {
    if (APP[i] === '{') depth += 1;
    else if (APP[i] === '}') {
      depth -= 1;
      if (depth === 0) { end = i + 1; break; }
    }
  }
  assert.notEqual(end, -1, 'could not find the end of privacyActionCount');
  const src = APP.slice(start, end);
  // eslint-disable-next-line no-new-func
  return new Function(`${src}; return privacyActionCount;`)();
}

const privacyActionCount = loadPrivacyActionCount();

const BLOCKS = { dns_blocked: 239, fw_blocked: 12412 };

test('does not re-count DNS/firewall blocks as privacy actions', () => {
  // The exact live shape: thousands of blocks, privacy layer reporting nothing.
  const stats = { ...BLOCKS, elements_cleaned: null };
  const got = privacyActionCount(stats, true);
  assert.notEqual(got, BLOCKS.dns_blocked + BLOCKS.fw_blocked,
    'privacy actions must not equal the blocked count');
  assert.equal(got, null);
});

test('null (layer switched off) is preserved, never coerced to 0', () => {
  assert.equal(privacyActionCount({ ...BLOCKS, elements_cleaned: null }, true), null);
});

test('a real 0 (ran, found nothing) is distinct from null', () => {
  assert.equal(privacyActionCount({ ...BLOCKS, elements_cleaned: 0 }, true), 0);
});

test('reports the privacy layer own count when it has one', () => {
  assert.equal(privacyActionCount({ ...BLOCKS, elements_cleaned: 42 }, true), 42);
});

test('engine down reports null regardless of stale counters', () => {
  assert.equal(privacyActionCount({ ...BLOCKS, elements_cleaned: 42 }, false), null);
  assert.equal(privacyActionCount(null, true), null);
});

test('the topbar renders the off-state as the NO_DATA dash, not "0"', () => {
  // fmt(null) returns '0', so the call site must gate on null itself. Guard the
  // wiring, since the function alone being correct is not enough.
  assert.match(
    APP,
    /_privacy\s*!=\s*null\s*\)\s*\?\s*fmt\(_privacy\)\s*:\s*'—'/,
    'tbPrivacy must render "—" when the privacy layer reports null');
});
