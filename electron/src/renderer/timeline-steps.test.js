'use strict';
/* =========================================================================
   Unit tests for timeline-steps.js - the label-selection logic that was
   silently wrong for every real incident (see the module's own header).
   Fixtures below are real shapes copied from the live product database
   (valkyrie.db's edr_incidents.timeline), not invented examples.
   Run with:
     node --test electron/src/renderer/timeline-steps.test.js
   ========================================================================= */

const test = require('node:test');
const assert = require('node:assert/strict');
const TS = require('./timeline-steps.js');

test('a detection entry (no user_message) falls back to summary, not "Event"', () => {
  const entry = {
    kind: 'detection',
    summary: 'Baseline anomaly for WmiPrvSE.exe',
    data: { severity: 'low', entity: '', source: 'dns.anomaly' },
  };
  assert.equal(TS.stepTitle(entry), 'Baseline anomaly for WmiPrvSE.exe');
  assert.equal(TS.stepKindLabel(entry), ''); // detection is the default kind, no badge
  assert.equal(TS.stepSource(entry), 'dns.anomaly');
});

test('a decision entry prefers the plain-language user_message over summary', () => {
  const entry = {
    kind: 'decision',
    summary: 'block: Medium-confidence surveillance flow (T1071.004 — DNS C2 / beaconing).',
    data: {
      action: 'block', threat_class: 'surveillance', confidence: 'medium',
      user_message: 'Big V blocked a suspicious connection and is watching more closely.',
    },
  };
  assert.equal(TS.stepTitle(entry),
    'Big V blocked a suspicious connection and is watching more closely.');
  assert.equal(TS.stepKindLabel(entry), 'decision');
});

test('an authority entry has no user_message and falls back to its terse summary', () => {
  const entry = {
    kind: 'authority',
    summary: 'block -> block',
    data: { action: 'block', requested: 'block', downgraded: false, vetoed: false },
  };
  assert.equal(TS.stepTitle(entry), 'block -> block');
  assert.equal(TS.stepKindLabel(entry), 'authorized');
});

test('a remediation_plan entry uses its summary, never the literal "Event"', () => {
  const entry = {
    kind: 'remediation_plan',
    summary: '2 action(s) justified by evidence; 1 blind spot(s) cap irreversible steps',
    data: { actions: [], blind_spots: ['x'] },
  };
  assert.equal(TS.stepTitle(entry),
    '2 action(s) justified by evidence; 1 blind spot(s) cap irreversible steps');
  assert.equal(TS.stepKindLabel(entry), 'plan');
});

test('an entry with none of the known fields at all still falls back to "Event", never crashes', () => {
  assert.equal(TS.stepTitle({}), 'Event');
  assert.equal(TS.stepTitle({ kind: 'mystery' }), 'Event');
  assert.equal(TS.stepKindLabel({}), '');
  assert.equal(TS.stepKindLabel({ kind: 'mystery' }), '');
});

test('a hypothetical future entry with a real top-level title still wins over summary', () => {
  // Forward/backward compatibility: if TimelineEntry ever grows a real
  // title field, it must not be shadowed by this fix.
  const entry = { kind: 'detection', title: 'Explicit title', summary: 'Fallback summary' };
  assert.equal(TS.stepTitle(entry), 'Explicit title');
});

test('entity/source/severity/technique read through to nested data when not top-level', () => {
  const entry = {
    kind: 'detection',
    data: { entity: 'python.exe', source: 'network_collector', severity: 'medium', technique: 'T1071.004' },
  };
  assert.equal(TS.stepEntity(entry), 'python.exe');
  assert.equal(TS.stepSource(entry), 'network_collector');
  assert.equal(TS.stepSeverity(entry), 'medium');
  assert.equal(TS.stepTechnique(entry), 'T1071.004');
});

test('top-level fields still take priority over nested data when both are present', () => {
  const entry = { entity: 'top-level-entity', data: { entity: 'nested-entity' } };
  assert.equal(TS.stepEntity(entry), 'top-level-entity');
});
