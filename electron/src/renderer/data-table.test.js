'use strict';
/* Unit tests for data-table.js - run with: node --test electron/src/renderer/*.test.js */

const test = require('node:test');
const assert = require('node:assert/strict');
const DataTable = require('./data-table.js');

test('sortRows: numeric ascending and descending', () => {
  const rows = [{ n: 3 }, { n: 1 }, { n: 2 }];
  assert.deepEqual(DataTable.sortRows(rows, 'n', 'asc').map((r) => r.n), [1, 2, 3]);
  assert.deepEqual(DataTable.sortRows(rows, 'n', 'desc').map((r) => r.n), [3, 2, 1]);
});

test('sortRows: string sort is natural/case-insensitive', () => {
  const rows = [{ s: 'item10' }, { s: 'item2' }, { s: 'Item1' }];
  assert.deepEqual(DataTable.sortRows(rows, 's', 'asc').map((r) => r.s), ['Item1', 'item2', 'item10']);
});

test('sortRows: null/undefined/empty values always sort last', () => {
  const rows = [{ v: 5 }, { v: null }, { v: 1 }, { v: undefined }, { v: '' }];
  const asc = DataTable.sortRows(rows, 'v', 'asc');
  assert.deepEqual(asc.slice(0, 2).map((r) => r.v), [1, 5]);
  const desc = DataTable.sortRows(rows, 'v', 'desc');
  assert.deepEqual(desc.slice(0, 2).map((r) => r.v), [5, 1]);
});

test('sortRows: no column returns a copy in original order', () => {
  const rows = [{ n: 3 }, { n: 1 }];
  const out = DataTable.sortRows(rows, null, 'asc');
  assert.deepEqual(out, rows);
  assert.notEqual(out, rows);   // copy, not the same array reference
});

test('sortRows: stable — equal keys keep original relative order', () => {
  const rows = [{ k: 1, tag: 'a' }, { k: 1, tag: 'b' }, { k: 1, tag: 'c' }];
  assert.deepEqual(DataTable.sortRows(rows, 'k', 'asc').map((r) => r.tag), ['a', 'b', 'c']);
});

test('sortRows: does not mutate the input array', () => {
  const rows = [{ n: 3 }, { n: 1 }];
  const copy = rows.map((r) => ({ ...r }));
  DataTable.sortRows(rows, 'n', 'asc');
  assert.deepEqual(rows, copy);
});

test('toCSV: plain values are not quoted', () => {
  const csv = DataTable.toCSV([{ a: 'x', b: 1 }], ['a', 'b']);
  assert.equal(csv, 'a,b\r\nx,1');
});

test('toCSV: values with commas, quotes, or newlines are quoted/escaped', () => {
  const csv = DataTable.toCSV([{ a: 'has,comma', b: 'has"quote', c: 'has\nnewline' }], ['a', 'b', 'c']);
  assert.equal(csv, 'a,b,c\r\n"has,comma","has""quote","has\nnewline"');
});

test('toCSV: null/undefined become empty fields', () => {
  const csv = DataTable.toCSV([{ a: null, b: undefined }], ['a', 'b']);
  assert.equal(csv, 'a,b\r\n,');
});

test('toCSV: infers columns from the first row when none given', () => {
  const csv = DataTable.toCSV([{ x: 1, y: 2 }]);
  assert.equal(csv, 'x,y\r\n1,2');
});

test('toCSV: empty rows still produces a header line', () => {
  assert.equal(DataTable.toCSV([], ['a', 'b']), 'a,b');
});

test('toJSON: pretty-printed, round-trips', () => {
  const rows = [{ a: 1, b: 'x' }];
  const json = DataTable.toJSON(rows);
  assert.deepEqual(JSON.parse(json), rows);
  assert.ok(json.includes('\n'));   // pretty-printed, not minified
});

test('rowToTSV: tab-joins the given columns in order', () => {
  assert.equal(DataTable.rowToTSV({ a: 1, b: 'x', c: null }, ['a', 'b', 'c']), '1\tx\t');
});
