'use strict';
/* Unit tests for command-index.js - run with: node --test electron/src/renderer/*.test.js */

const test = require('node:test');
const assert = require('node:assert/strict');
const CommandIndex = require('./command-index.js');

const FIXTURE = [
  { id: 'nav-dashboard', group: 'Navigation', label: 'Dashboard' },
  { id: 'nav-dns', group: 'Navigation', label: 'DNS' },
  { id: 'nav-devices', group: 'Navigation', label: 'Devices' },
  { id: 'act-stop', group: 'Actions', label: 'Stop Protection', keywords: ['disable', 'off'] },
  { id: 'act-mac', group: 'Actions', label: 'Randomize MAC', keywords: ['privacy', 'network'] },
  { id: 'inc-1', group: 'Recent Incidents', label: 'Suspicious PowerShell', hint: 'T1059.001' },
];

test('filterCommands: empty query returns every command, unranked', () => {
  const r = CommandIndex.filterCommands('', FIXTURE);
  assert.equal(r.length, FIXTURE.length);
  const r2 = CommandIndex.filterCommands('   ', FIXTURE);
  assert.equal(r2.length, FIXTURE.length);
});

test('filterCommands: exact label match ranks first', () => {
  const r = CommandIndex.filterCommands('dns', FIXTURE);
  assert.equal(r[0].id, 'nav-dns');
});

test('filterCommands: prefix match beats substring match', () => {
  // "dev" is a prefix of "Devices" but only a substring of nothing else here -
  // add a case where prefix vs substring actually compete.
  const fixture = [
    { id: 'a', group: 'X', label: 'Meeting Mode' },   // "mode" is a substring
    { id: 'b', group: 'X', label: 'Mode Overview' },  // "mode" is a prefix
  ];
  const r = CommandIndex.filterCommands('mode', fixture);
  assert.equal(r[0].id, 'b');
});

test('filterCommands: matches via keywords, not just label', () => {
  const r = CommandIndex.filterCommands('privacy', FIXTURE);
  assert.ok(r.some((c) => c.id === 'act-mac'));
});

test('filterCommands: matches MITRE technique in hint field', () => {
  const r = CommandIndex.filterCommands('t1059', FIXTURE);
  assert.equal(r.length, 1);
  assert.equal(r[0].id, 'inc-1');
});

test('filterCommands: no match returns empty array, not null/undefined', () => {
  const r = CommandIndex.filterCommands('zzz_no_such_thing', FIXTURE);
  assert.deepEqual(r, []);
});

test('filterCommands: case-insensitive', () => {
  const r = CommandIndex.filterCommands('DASHBOARD', FIXTURE);
  assert.equal(r[0].id, 'nav-dashboard');
});

test('filterCommands: handles a non-array input without throwing', () => {
  assert.deepEqual(CommandIndex.filterCommands('x', null), []);
  assert.deepEqual(CommandIndex.filterCommands('x', undefined), []);
});

test('groupCommands: preserves first-seen group order and item order', () => {
  const g = CommandIndex.groupCommands(FIXTURE);
  assert.deepEqual(g.map((x) => x.group), ['Navigation', 'Actions', 'Recent Incidents']);
  assert.equal(g[0].items.length, 3);
  assert.equal(g[0].items[0].id, 'nav-dashboard');
});

test('groupCommands: empty input yields empty groups, no crash', () => {
  assert.deepEqual(CommandIndex.groupCommands([]), []);
  assert.deepEqual(CommandIndex.groupCommands(undefined), []);
});

test('scoreText: exact > prefix > word-boundary > substring > none', () => {
  const s = CommandIndex.scoreText;
  assert.ok(s('dashboard', 'dashboard') > s('dashboard', 'dash'));
  assert.ok(s('dashboard', 'dash') > s('mode overview', 'over'));
  assert.ok(s('mode overview', 'over') > s('overwatch', 'wat'));
  assert.equal(s('dashboard', 'zzz'), 0);
});
