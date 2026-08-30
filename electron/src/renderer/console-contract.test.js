'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const read = (name) => fs.readFileSync(path.join(__dirname, name), 'utf8');
const APP = read('app.js');
const HTML = read('index.html');
const CSS = read('console-v2.css');

test('the operator console preserves its recorded design direction', () => {
  assert.match(HTML, /seed fe27994f/);
  assert.match(HTML, /console-v2\.css/);
  assert.match(CSS, /Valkyrie instrument console/i);
});

test('the latest decision story keeps all five provenance stages', () => {
  for (const stage of ['origin', 'actor', 'request', 'evidence', 'verdict']) {
    assert.match(APP, new RegExp(`decisionStage\\('${stage}'`));
  }
  assert.match(APP, /Evidence &amp; authority/);
  assert.match(APP, /Evidence missing/);
});

test('the renderer does not advertise an AI decision path', () => {
  assert.doesNotMatch(APP, /Loading AI Engine|Ask AI|AI narrative/i);
  assert.match(APP, /use_ai:\s*false/);
  assert.match(APP, /Deterministic local policy outcome/);
});

test('the dashboard is constrained to the space beside the navigation rail', () => {
  assert.match(CSS, /width:\s*calc\(100vw - var\(--sidebar-w\)\)/);
  assert.match(CSS, /max-width:\s*calc\(100vw - var\(--sidebar-w\)\)/);
  assert.match(CSS, /\.chain-flow\s*\{[^}]*width:\s*100%/s);
});
