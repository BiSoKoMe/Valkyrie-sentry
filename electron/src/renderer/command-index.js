'use strict';
/* =========================================================================
   command-index.js - pure ranking/grouping logic for the command palette
   (Ctrl+K). Decoupled from the DOM so scoring behavior is unit testable,
   same pattern as view-state.js. Loaded as a classic <script> before app.js
   (no bundler, CSP is script-src 'self') and dual-exported for Node tests.

   A "command" here is a plain object the caller controls:
     { id, group, label, hint, keywords: [...] , ...anything else (e.g. run) }
   This module never invokes anything - it only decides what matches and in
   what order, so it has no opinion on what a command *does*.
   ========================================================================= */

function norm(s) { return String(s || '').toLowerCase(); }

// Score a single haystack string against a query. Higher = better match.
// Exact > prefix > word-boundary-prefix > substring > no match (0).
function scoreText(text, q) {
  const t = norm(text);
  if (!t || !q) return 0;
  if (t === q) return 100;
  if (t.startsWith(q)) return 80;
  if (t.split(/\s+/).some((w) => w.startsWith(q))) return 60;
  if (t.includes(q)) return 40;
  return 0;
}

// Best score for a command across its label, group and keywords.
function scoreCommand(cmd, q) {
  const fields = [cmd.label, cmd.group, cmd.hint, ...(cmd.keywords || [])].filter(Boolean);
  let best = 0;
  for (const f of fields) best = Math.max(best, scoreText(f, q));
  return best;
}

// Filter + rank commands against a query. Empty/whitespace query returns the
// full list unranked (palette shows everything, grouped, before typing).
function filterCommands(query, commands) {
  const list = Array.isArray(commands) ? commands : [];
  const q = norm(query).trim();
  if (!q) return list.slice();
  return list
    .map((c) => ({ c, s: scoreCommand(c, q) }))
    .filter((x) => x.s > 0)
    .sort((a, b) => b.s - a.s)
    .map((x) => x.c);
}

// Group commands by `.group`, preserving first-seen group order and
// within-group order (the order the caller/filter already produced).
function groupCommands(commands) {
  const order = [];
  const byGroup = new Map();
  for (const c of Array.isArray(commands) ? commands : []) {
    const g = c.group || '';
    if (!byGroup.has(g)) { byGroup.set(g, []); order.push(g); }
    byGroup.get(g).push(c);
  }
  return order.map((g) => ({ group: g, items: byGroup.get(g) }));
}

const CommandIndex = { scoreText, scoreCommand, filterCommands, groupCommands };

/* global module, window */
if (typeof module !== 'undefined' && module.exports) module.exports = CommandIndex;
if (typeof window !== 'undefined') window.CommandIndex = CommandIndex;
