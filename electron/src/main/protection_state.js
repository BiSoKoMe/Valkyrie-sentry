'use strict';
// ---------------------------------------------------------------------------
// protection_state.js - pure decision logic for the DNS protection lifecycle.
//
// Mirrors valkyrie/host_safety.py's separation on purpose: policy is decided
// here as a pure function of plain data, so it is exhaustively unit-testable
// without Electron, IPC, or the filesystem. The actual side effect (calling
// engine.start(), which is what runs the ValkyrieArm task / arm-protection.ps1)
// stays a thin, separately-reasoned-about call in main.js - this module never
// touches DNS itself and never will.
//
// THE BUG THIS CLOSES
// --------------------
// main.js's boot() used to ask exactly one question - "is the engine
// process up?" - and treated "yes" as "nothing to do". That conflates two
// independent facts: the ValkyrieShield service is a persistent Windows
// service that is essentially ALWAYS up once installed, so isUp() being true
// tells you nothing about whether the OS is actually routing DNS through it.
// A machine can sit with a healthy, listening engine and disarmed DNS
// indefinitely, because nothing ever re-asks the arming question once the
// engine is already running.
//
// THE FIX'S SHAPE
// ----------------
// Three independent facts go in: is the engine up, does the user actually
// want protection on (persisted intent - see lifecycle.protectionIntent()),
// and is protection actually active right now (the engine's own truthful
// telemetry().protected, which already accounts for a stale marker file).
// Exactly one of a small set of actions comes out. The critical invariant:
// arming NEVER happens unless intent is explicitly 'enabled' - a user who
// has never touched the protection toggle gets 'leave' in every branch.
// ---------------------------------------------------------------------------

const PROTECTION_INTENT = Object.freeze({
  ENABLED: 'enabled',
  DISABLED: 'disabled',
  UNSET: 'unset',
});

const BOOT_ACTION = Object.freeze({
  LEAVE: 'leave',                 // nothing to do
  ENSURE_ENGINE: 'ensure-engine', // bring the engine process up (see per-branch note below)
  RECONCILE_ARM: 'reconcile-arm', // engine reachable but disarmed while intent says it shouldn't be
});

/**
 * Decide the ONE safe boot-time action. Pure; never touches the filesystem,
 * network, or a child process.
 *
 * @param {object} input
 * @param {boolean} input.engineUp     - engine.isUp() result, taken BEFORE this decision.
 * @param {string}  input.intent       - lifecycle.protectionIntent() value.
 * @param {string}  input.mode         - lifecycle.mode(): 'development' | 'portable' | 'installed'.
 * @param {boolean|null} input.protected - live telemetry().protected; null/undefined
 *                                         when not yet knowable (engine not reachable).
 * @param {boolean} input.noAutostart  - the VALKYRIE_NO_AUTOSTART escape hatch.
 * @returns {string} one of BOOT_ACTION's values.
 */
function decideBootAction({ engineUp, intent, mode, protected: isProtected, noAutostart }) {
  if (noAutostart) return BOOT_ACTION.LEAVE;

  if (!engineUp) {
    // Portable's "start" never touches system DNS (see engine.js's start()) -
    // safe to bring up unconditionally, same as today.
    if (mode === 'portable') return BOOT_ACTION.ENSURE_ENGINE;
    // In every other mode, engine.start() is also capable of arming DNS as a
    // side effect (the installed model's ValkyrieArm task, or a source
    // checkout's start_all.ps1 which does both in one script - there is no
    // "just start the process" lever for those two modes). Only take it when
    // the user has explicitly asked for protection before; otherwise the
    // installed service's own restart-on-exit (NSSM AppExit=Restart) or a
    // manual launch is what brings the engine back, and the dashboard
    // honestly shows "engine offline" rather than silently re-arming DNS for
    // a user who never asked.
    if (intent === PROTECTION_INTENT.ENABLED) return BOOT_ACTION.ENSURE_ENGINE;
    return BOOT_ACTION.LEAVE;
  }

  // Engine already reachable - the common case for the installed persistent
  // service, and the exact case the old `if (!already) ...` logic never
  // re-examined once true.
  if (mode === 'portable') return BOOT_ACTION.LEAVE; // cannot arm DNS at all
  if (intent === PROTECTION_INTENT.ENABLED && isProtected === false) {
    return BOOT_ACTION.RECONCILE_ARM;
  }
  return BOOT_ACTION.LEAVE;
}

module.exports = { PROTECTION_INTENT, BOOT_ACTION, decideBootAction };
