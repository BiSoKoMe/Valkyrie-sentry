'use strict';
/* Classifies the ResponseAction status the engine returns from
 * POST /api/edr/respond (edr/schema.py RESPONSE_STATES: dry_run, pending,
 * succeeded, failed, skipped) into what the UI is allowed to tell the
 * operator actually happened.
 *
 * WHY THIS EXISTS AS ITS OWN MODULE, NOT AN INLINE `!== 'failed'` CHECK:
 * a refused action - e.g. KillProcessResponder returning "skipped" because
 * the target PID has no observed create_time and a bare PID is ambiguous -
 * is not a failure, but it is very much not a success either. Treating
 * "anything but failed" as success reports a REFUSED action to the operator
 * as "kill_process applied.", which is a false all-clear on exactly the
 * action the operator clicked "Confirm - apply for real" to be sure of.
 */
const ResponseStatus = {
  // The ONLY status that means the requested change actually happened.
  succeeded(status) {
    return status === 'succeeded';
  },

  // One line safe to show next to a toast/result panel for a non-dry-run
  // response. Never used for 'dry_run' itself - that has its own preview UI.
  outcomeLabel(status) {
    switch (status) {
      case 'succeeded': return 'applied';
      case 'skipped':   return 'refused — see the detail below';
      case 'failed':    return 'failed';
      case 'pending':   return 'pending';
      default:          return 'unknown result';
    }
  },
};

/* global module, window */
if (typeof module !== 'undefined' && module.exports) module.exports = ResponseStatus;
if (typeof window !== 'undefined') window.ResponseStatus = ResponseStatus;
