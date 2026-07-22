'use strict';
/* =========================================================================
   view-state.js — pure "what should this list/panel show right now" logic,
   decoupled from the DOM so it can be unit tested directly.

   The rule these functions encode (the same one already shipped on the
   Threats page): a security product must never let an absence of data read
   as "checked, found nothing" when the truth is "not checked at all". Every
   live panel needs three distinct outcomes:
     - 'offline' — the engine isn't reporting; nothing was observed.
     - 'empty'   — the engine is reporting and genuinely found nothing.
     - 'list'    — real data to render.

   Loaded as a classic <script> before app.js (renderer has no bundler and a
   strict `script-src 'self'` CSP, so this stays dependency-free) and also
   exported via module.exports for the Node unit tests in view-state.test.js.
   ========================================================================= */

function hasItems(items) {
  return Array.isArray(items) && items.length > 0;
}

// Shared shape: { kind: 'offline'|'empty'|'list', title, sub }
// title/sub are null for 'list' — the caller renders its own real content.
function liveListState(up, items, copy) {
  if (!up) return { kind: 'offline', title: copy.offlineTitle || 'Protection is off', sub: copy.offlineSub };
  if (!hasItems(items)) return { kind: 'empty', title: copy.emptyTitle, sub: copy.emptySub };
  return { kind: 'list', title: null, sub: null };
}

const ViewState = {
  hasItems,
  liveListState,

  feedState(up, events) {
    return liveListState(up, events, {
      offlineSub: 'Start protection to begin seeing live DNS, firewall and threat activity.',
      emptyTitle: 'No activity yet',
      emptySub: 'Valkyrie is monitoring — activity will appear here as it happens.',
    });
  },

  topBlockedState(up, top) {
    return liveListState(up, top, {
      offlineSub: 'Start protection to see blocked destinations here.',
      emptyTitle: 'No blocks yet',
      emptySub: 'Valkyrie is monitoring — nothing has been blocked.',
    });
  },

  processListState(up, rows) {
    return liveListState(up, rows, {
      offlineSub: 'Start protection to see process network activity.',
      emptyTitle: 'No process activity yet',
      emptySub: 'Valkyrie is watching — no network-active processes observed yet.',
    });
  },

  // These two panels always have *some* rows to show once the engine is up
  // (status badges, not an observation list), so they only need the binary
  // offline/online split — never a separate "empty" branch.
  privacyRowsState(up) {
    return up ? { kind: 'list', title: null, sub: null }
      : { kind: 'offline', title: 'Protection is off', sub: 'Start protection to see privacy subsystem status.' };
  },

  intelRowsState(up) {
    return up ? { kind: 'list', title: null, sub: null }
      : { kind: 'offline', title: 'Protection is off', sub: 'Start protection to see intelligence engine status.' };
  },
};

/* global module, window */
if (typeof module !== 'undefined' && module.exports) module.exports = ViewState;
if (typeof window !== 'undefined') window.ViewState = ViewState;
