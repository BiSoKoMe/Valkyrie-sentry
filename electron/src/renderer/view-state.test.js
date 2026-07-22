'use strict';
/* =========================================================================
   Unit tests for view-state.js — the pure "offline vs empty vs list" logic
   that keeps every live panel honest about whether protection is running.
   Zero dependencies: Node's built-in test runner. Run with:
     node --test electron/src/renderer/view-state.test.js
   ========================================================================= */

const test = require('node:test');
const assert = require('node:assert/strict');
const ViewState = require('./view-state.js');

const LIST_FNS = {
  feedState: ViewState.feedState,
  topBlockedState: ViewState.topBlockedState,
  processListState: ViewState.processListState,
};

for (const [name, fn] of Object.entries(LIST_FNS)) {
  test(`${name}: engine offline always wins, even with stale data present`, () => {
    const s = fn(false, [{ x: 1 }, { y: 2 }]);
    assert.equal(s.kind, 'offline');
    assert.ok(s.title, 'offline state must have a title');
    assert.ok(s.sub, 'offline state must explain what to do next');
  });

  test(`${name}: engine up + no items -> genuine "empty", not offline`, () => {
    const s = fn(true, []);
    assert.equal(s.kind, 'empty');
    assert.notEqual(s.title, 'Protection is off');
  });

  test(`${name}: engine up + undefined items -> treated as empty, not a crash`, () => {
    const s = fn(true, undefined);
    assert.equal(s.kind, 'empty');
  });

  test(`${name}: engine up + items -> 'list', caller renders real content`, () => {
    const s = fn(true, [{ a: 1 }]);
    assert.equal(s.kind, 'list');
    assert.equal(s.title, null);
    assert.equal(s.sub, null);
  });
}

const BADGE_FNS = {
  privacyRowsState: ViewState.privacyRowsState,
  intelRowsState: ViewState.intelRowsState,
};

for (const [name, fn] of Object.entries(BADGE_FNS)) {
  test(`${name}: offline when engine down`, () => {
    assert.equal(fn(false).kind, 'offline');
  });
  test(`${name}: list when engine up (no separate empty state)`, () => {
    assert.equal(fn(true).kind, 'list');
  });
}

test('liveListState: distinct copy per caller (panels do not share generic text)', () => {
  const feed = ViewState.feedState(false, []);
  const bars = ViewState.topBlockedState(false, []);
  assert.notEqual(feed.sub, bars.sub);
});

test('hasItems: rejects non-arrays and empty arrays, accepts populated arrays', () => {
  assert.equal(ViewState.hasItems(null), false);
  assert.equal(ViewState.hasItems(undefined), false);
  assert.equal(ViewState.hasItems([]), false);
  assert.equal(ViewState.hasItems([1]), true);
});
