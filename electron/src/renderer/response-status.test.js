'use strict';
/* =========================================================================
   Unit tests for response-status.js - what a response result is allowed to
   claim happened. Zero dependencies: Node's built-in test runner. Run with:
     node --test electron/src/renderer/response-status.test.js
   ========================================================================= */

const test = require('node:test');
const assert = require('node:assert/strict');
const ResponseStatus = require('./response-status.js');

test('succeeded: true only for the exact "succeeded" status', () => {
  assert.equal(ResponseStatus.succeeded('succeeded'), true);
});

test('succeeded: false for skipped - a refusal is not a success', () => {
  assert.equal(ResponseStatus.succeeded('skipped'), false);
});

test('succeeded: false for failed, dry_run, pending, and unknown/undefined values', () => {
  for (const status of ['failed', 'dry_run', 'pending', 'bogus', undefined, null, '']) {
    assert.equal(ResponseStatus.succeeded(status), false, `expected ${JSON.stringify(status)} to not be success`);
  }
});

test('outcomeLabel: distinguishes a refusal from a failure in the label itself', () => {
  assert.equal(ResponseStatus.outcomeLabel('skipped'), 'refused — see the detail below');
  assert.equal(ResponseStatus.outcomeLabel('failed'), 'failed');
  assert.notEqual(ResponseStatus.outcomeLabel('skipped'), ResponseStatus.outcomeLabel('failed'));
});

test('outcomeLabel: never returns the success label for a non-succeeded status', () => {
  for (const status of ['skipped', 'failed', 'pending', 'bogus']) {
    assert.notEqual(ResponseStatus.outcomeLabel(status), 'applied');
  }
});
