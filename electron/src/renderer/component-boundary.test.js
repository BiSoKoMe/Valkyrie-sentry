'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const APP = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
const between = (start, end) => APP.slice(APP.indexOf(start), APP.indexOf(end));

test('navigation presents the three product boundaries directly', () => {
  assert.match(APP, /\['Valkyrie EDR',/);
  assert.match(APP, /\['NYX',/);
  assert.match(APP, /\['Aegis',/);
  assert.match(APP, /\['aegis',\s*'Investigations'/);
  assert.match(APP, /item\.setAttribute\('aria-label', label\)/);
  assert.match(APP, /item\.title = label/);
  assert.match(APP, /\['NYX', 'Aegis'\]\.includes\(group\)/);
});

test('NYX owns outbound exposure inference', () => {
  const nyx = between('PAGES.nyx = {', '/* ---- Aegis:');
  assert.match(nyx, /\/api\/nyx\/exposure\/status/);
  assert.match(nyx, /\/api\/nyx\/exposure\/ledger/);
  assert.match(nyx, /What traffic reveals/);
  assert.match(APP, /Exposure history unavailable/);
  assert.match(APP, /label\.textContent = 'Start protection'/);
  assert.doesNotMatch(nyx, /\/api\/v1\/aegis/);
});

test('Aegis is backed by durable EDR cases and opens the evidence replay', () => {
  const aegis = between('PAGES.aegis = {', '/* ---- Protection ----');
  assert.match(aegis, /\/api\/v1\/aegis\/status/);
  assert.match(aegis, /\/api\/v1\/aegis\/cases/);
  assert.match(aegis, /openReplay\(row\.dataset\.id\)/);
  assert.match(aegis, /does not independently authorize/);
  assert.match(aegis, /openCases\.map/);
  assert.match(aegis, /Case ledger unavailable/);
  assert.match(aegis, /Data unavailable/);
  assert.doesNotMatch(aegis, /\/api\/aegis\/ledger/);
});
