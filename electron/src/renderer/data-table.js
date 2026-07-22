'use strict';
/* =========================================================================
   data-table.js — pure logic for the app's one reusable data-grid: sorting
   and export. Decoupled from the DOM (same pattern as view-state.js and
   command-index.js) so it's unit testable and any future table (Fleet
   inventory, forensics file list, …) can reuse it instead of hand-rolling
   sort/export again.
   ========================================================================= */

// Stable sort by one column. Nulls/undefined always sort last regardless of
// direction — a missing value is never "smallest", it's "unknown".
function sortRows(rows, col, dir) {
  const list = Array.isArray(rows) ? rows.slice() : [];
  if (!col) return list;
  const mul = dir === 'desc' ? -1 : 1;
  return list
    .map((r, i) => [r, i])
    .sort(([a, ai], [b, bi]) => {
      const av = a ? a[col] : undefined, bv = b ? b[col] : undefined;
      const aNull = av == null || av === '', bNull = bv == null || bv === '';
      if (aNull && bNull) return ai - bi;
      if (aNull) return 1;
      if (bNull) return -1;
      let cmp;
      if (typeof av === 'number' && typeof bv === 'number') cmp = av - bv;
      else cmp = String(av).localeCompare(String(bv), undefined, { numeric: true, sensitivity: 'base' });
      return cmp !== 0 ? cmp * mul : ai - bi;   // stable: original order breaks ties
    })
    .map(([r]) => r);
}

// RFC 4180-ish CSV: quote a field only when it contains a comma, quote, or
// newline; escape embedded quotes by doubling them. CRLF line endings.
function toCSV(rows, cols) {
  const columns = cols && cols.length ? cols : Object.keys((rows && rows[0]) || {});
  const esc = (v) => {
    const s = v == null ? '' : String(v);
    return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const lines = [columns.map(esc).join(',')];
  for (const r of rows || []) lines.push(columns.map((c) => esc(r ? r[c] : '')).join(','));
  return lines.join('\r\n');
}

function toJSON(rows) {
  return JSON.stringify(rows || [], null, 2);
}

// One row as tab-separated text — what a spreadsheet paste expects.
function rowToTSV(row, cols) {
  const columns = cols && cols.length ? cols : Object.keys(row || {});
  return columns.map((c) => (row && row[c] != null ? String(row[c]) : '')).join('\t');
}

const DataTable = { sortRows, toCSV, toJSON, rowToTSV };

/* global module, window */
if (typeof module !== 'undefined' && module.exports) module.exports = DataTable;
if (typeof window !== 'undefined') window.DataTable = DataTable;
