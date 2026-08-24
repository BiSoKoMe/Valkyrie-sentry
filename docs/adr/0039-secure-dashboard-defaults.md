# ADR 0039 — Secure dashboard defaults + off-loopback API/WS auth

- **Status:** Accepted
- **Phase:** 0 (security / secure defaults)
- **Date:** 2026-07-12

## Context

The web dashboard is the product's most sensitive surface: `/api/events` and the
`/ws` stream expose **live DNS resolutions — i.e. real-time browsing history** —
plus process attribution and system status. Two defects compounded:

1. **`WEB_HOST` defaulted to `0.0.0.0`.** The server bound every interface, so on
   any shared network (home Wi-Fi, café, the GL.iNet router deployment) every
   other device could reach the dashboard.
2. **Read endpoints were unauthenticated.** Only state-changing control/EDR POSTs
   were guarded (loopback + Origin + token). `GET /api/events`, `/api/stats`,
   `/api/intelligence`, the EDR GETs, and the `/ws` live stream had **no auth at
   all** — anyone who could reach the port could read the browsing feed.

For a privacy-first product this is the worst possible leak: the tool that exists
to stop you being watched was itself broadcasting your browsing to the LAN.

## Decision

Defense in layers, without breaking the same-machine experience:

1. **Loopback by default.** `config.WEB_HOST` → `127.0.0.1`. The dashboard is now
   unreachable off-box unless the operator explicitly opts in with
   `--web-host 0.0.0.0`. The launcher, health check, and browser all use
   `localhost`, so nothing in the daily-use flow changes.
2. **Off-loopback API guard (middleware).** Any `/api/*` request from a
   non-loopback peer must carry the control token (`X-Valkyrie-Token` header or
   `?token=`). Loopback callers are unaffected — the local dashboard needs no
   token, exactly as before.
3. **WebSocket guard.** HTTP middleware does not cover WebSocket scope, so `/ws`
   applies the same rule explicitly: a non-loopback subscriber must supply
   `?token=…`; otherwise the socket is closed with code 1008.
4. **Loud warning** at startup when bound off-loopback, naming the exposure and
   where the token lives (`data/control_token.txt`).

Control/EDR POSTs keep their stricter loopback+Origin+token guards on top.

## Change report

- **What changed:** `config.py` (`WEB_HOST` default → loopback, documented);
  `web/server.py` (new `_offloopback_api_guard` middleware; `/ws` peer/token
  check); `__main__.py` (off-loopback warning).
- **Why:** eliminate LAN exposure of browsing history by default, and require
  authentication for any remote data access when exposure is explicitly enabled.
- **Security impact:** major positive. Closes the highest-severity finding from
  the architecture audit. Default deployments are now loopback-only; exposed
  deployments require a shared secret for every data read.
- **Performance impact:** negligible — one string-prefix + peer check per HTTP
  request; no effect on the DNS/firewall datapath.
- **Compatibility impact:** minimal and intentional. Same-machine dashboard,
  launcher, and control buttons are unchanged. The **one** behavior change: users
  who *relied* on reaching the dashboard from another device must now pass
  `--web-host 0.0.0.0` **and** supply the control token — documented in the
  startup warning. This is the correct trade for a privacy tool.
- **Risks:** a user upgrading who viewed the dashboard from another device will
  find it unreachable until they opt in. Mitigation: explicit, actionable startup
  warning; documented in README (ADR-0005). No silent failure.
- **Tests added:** `tests/test_web_auth.py` — loopback allowed without token;
  remote 403 without/with-wrong token; remote 200 with token; HTML shell still
  served; `/ws` loopback streams, remote rejected without token, remote allowed
  with token. Full suite: 21 passed, 0 failed, 2 skipped.
- **Rollback plan:** revert the three edits. `WEB_HOST` returns to `0.0.0.0` and
  the guards disappear. Clean `git revert`; no persisted state involved.

## Consequences

The dashboard is now safe-by-default and authenticated-when-exposed. This is also
the groundwork for the Phase-4 enterprise auth model (RBAC/SSO): the control
token is a placeholder credential that a real identity layer will later replace,
but the loopback-default and per-request authorization seam are now in place.
