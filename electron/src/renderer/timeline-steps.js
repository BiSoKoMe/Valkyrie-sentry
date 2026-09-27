'use strict';
/* =========================================================================
   timeline-steps.js - turn one raw incident timeline entry into the label a
   human should see, decoupled from the DOM so the label-selection logic can
   be tested directly.

   valkyrie/edr/engine.py's TimelineEntry carries only kind/summary/timestamp
   /data - never a top-level title/reason/activity/source. Confirmed against
   the live product database (16k+ real incidents): every single timeline
   entry, of every kind (detection/decision/authority/remediation_plan/
   status/response/note), is shaped exactly that way. The incident replay UI
   was reading the fields that don't exist and showing the literal word
   "Event" for every step of every real incident as a result.

   `data.user_message` (set on "decision" entries by valkyrie/decision.py) is
   the plain-language framing the product's own vision wants ("Big V blocked
   a suspicious connection and is watching more closely"), so it wins when
   present. `summary` is what every other real entry reliably carries and is
   the actual fallback now, not a dead one. title/reason/activity/source are
   still checked for forward/backward compatibility, but must never be the
   ONLY path to a real label - nothing the engine writes today ever sets
   them.
   ========================================================================= */

const KIND_LABEL = {
  decision: 'decision', authority: 'authorized', remediation_plan: 'plan',
  status: 'status', response: 'response', note: 'note',
};

function stepTitle(entry) {
  const d = (entry && entry.data) || {};
  return d.user_message || entry.title || entry.reason || entry.activity
       || entry.summary || entry.source || 'Event';
}

function stepKindLabel(entry) {
  return KIND_LABEL[entry && entry.kind] || '';
}

function stepEntity(entry) {
  const d = (entry && entry.data) || {};
  return entry.entity || entry.target || d.entity || d.target || '';
}

function stepSource(entry) {
  const d = (entry && entry.data) || {};
  return entry.source || d.source || '';
}

function stepSeverity(entry) {
  const d = (entry && entry.data) || {};
  return entry.severity || d.severity || '';
}

function stepTechnique(entry) {
  const d = (entry && entry.data) || {};
  return entry.technique || d.technique || '';
}

const TimelineSteps = {
  KIND_LABEL, stepTitle, stepKindLabel, stepEntity, stepSource, stepSeverity,
  stepTechnique,
};

/* global module, window */
if (typeof module !== 'undefined' && module.exports) module.exports = TimelineSteps;
if (typeof window !== 'undefined') window.TimelineSteps = TimelineSteps;
