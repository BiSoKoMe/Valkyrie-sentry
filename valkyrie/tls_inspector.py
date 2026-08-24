"""TLS inspection — runs mitmproxy in-process to intercept HTTPS traffic.

mitmproxy terminates TLS using a locally-generated root CA, lets the
ValkyrieAddon (tls_addon.py) inspect/block/strip each request, then
re-encrypts and forwards upstream. The CA must be installed as trusted on
each device that proxies through Valkyrie, or browsers will reject the
forged certificate.

mitmproxy is run via its library API (DumpMaster) on a private asyncio
event loop in a background thread, rather than shelling out to `mitmdump`,
so the addon can hold live references to the shared Store/Blocklist/
Behavioral/Rules instances instead of re-creating them in a subprocess.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from pathlib import Path
from typing import Optional

from . import secure_file
from .config import TLS_CA_CERT_PATH, TLS_MITMPROXY_CONF_DIR, TLS_PROXY_PORT

log = logging.getLogger("valkyrie.tls")


CA_INSTALL_INSTRUCTIONS = """\
Install the Valkyrie CA certificate to inspect HTTPS traffic on each device:

  Windows:
    certutil -addstore Root "{cert}"

  iPhone / iPad:
    AirDrop {cert} to the device, open it, then enable it under
    Settings > General > About > Certificate Trust Settings

  Android:
    Settings > Security > Encryption & credentials > Install a certificate
    > CA certificate, then select {cert}

  macOS:
    sudo security add-trusted-cert -d -r trustRoot \\
        -k /Library/Keychains/System.keychain "{cert}"
"""


class TLSInspector:
    """Owns the mitmproxy lifecycle and exposes start/stop/status."""

    def __init__(self, store, blocklist=None, behavioral=None, rules=None,
                 threat_intel=None, port: int = TLS_PROXY_PORT) -> None:
        self.store      = store
        self.blocklist   = blocklist
        self.behavioral  = behavioral
        self.rules       = rules
        self.threat_intel = threat_intel
        self.port        = port

        self._master = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._addon = None

    # ------------------------------------------------------------------
    # CA certificate
    # ------------------------------------------------------------------

    def setup_ca(self) -> Path:
        """Generate the mitmproxy CA on first run (if missing) and copy it
        to a stable, user-facing path. Returns the cert path.

        mitmproxy auto-generates its CA into its config dir the first time
        it starts, so we ensure that dir exists; the actual generation
        happens inside start() when DumpMaster initializes.
        """
        TLS_MITMPROXY_CONF_DIR.mkdir(parents=True, exist_ok=True)
        secure_file.harden(TLS_MITMPROXY_CONF_DIR, is_dir=True)
        generated = TLS_MITMPROXY_CONF_DIR / "mitmproxy-ca-cert.pem"
        if generated.exists() and not TLS_CA_CERT_PATH.exists():
            # The .pem here is the CERTIFICATE only — public by design. It must
            # stay readable: the user has to be able to open it to install it
            # into the trust store, and it grants nothing on its own.
            TLS_CA_CERT_PATH.write_bytes(generated.read_bytes())
            key_src = TLS_MITMPROXY_CONF_DIR / "mitmproxy-ca.pem"
            if key_src.exists():
                from .config import TLS_CA_KEY_PATH
                # This one contains the PRIVATE KEY. Restrict it the moment it
                # is written — a copy of a protected key into an unprotected
                # location would silently undo the directory hardening above.
                TLS_CA_KEY_PATH.write_bytes(key_src.read_bytes())
                ok, detail = secure_file.harden(TLS_CA_KEY_PATH)
                if not ok:
                    log.error("CA private key at %s could not be protected: %s",
                              TLS_CA_KEY_PATH, detail)
        print(CA_INSTALL_INSTRUCTIONS.format(cert=TLS_CA_CERT_PATH))
        return TLS_CA_CERT_PATH

    def ca_key_status(self) -> tuple[bool, str]:
        """Is the CA private key protected from other local accounts?

        Exposed here so the dashboard/self-test can report the answer rather
        than the question only being asked at start().
        """
        from .config import TLS_CA_KEY_PATH
        if not TLS_CA_KEY_PATH.exists():
            return True, "no CA key on disk yet"
        return secure_file.verify(TLS_CA_KEY_PATH)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Start mitmproxy on a background thread. Returns False (and does
        not raise) if mitmproxy is not installed, or if the proxy fails to
        actually bind its listening socket (e.g. port already in use).

        NOTE ON A REAL PAST BUG: this used to call ready.set() immediately
        after constructing DumpMaster and adding the addon, i.e. BEFORE
        loop.run_until_complete(master.run()) had even started — meaning
        before mitmproxy's proxyserver addon had called setup_servers() to
        actually bind the listening socket. That made start() return True
        (and is_running() report True) even when the bind hadn't happened
        yet, or would shortly fail (e.g. port already in use causes the
        server to exit asynchronously *after* ready.set() had already
        fired). Verified empirically: probing the socket immediately after
        start() returned True showed it still closed, and occupying the
        port first made start() return True while the background thread
        died ~1s later. See docs/TLS_ZEROLOG_AUDIT_REPORT.md. Fixed by
        waiting for mitmproxy's own proxyserver.is_running flag (set inside
        Proxyserver.running(), which mitmproxy calls only after
        setup_servers() succeeds) before signalling ready — bounded so a
        stuck bind can't hang start() forever.
        """
        try:
            from mitmproxy import options
            from mitmproxy.tools.dump import DumpMaster
        except ImportError:
            return False

        from .tls_addon import ValkyrieAddon

        # ------------------------------------------------------------------
        # Protect the CA private key BEFORE mitmproxy generates it.
        #
        # mitmproxy creates its CA (mitmproxy-ca.pem, which CONTAINS the
        # private key) inside confdir on first start. On Windows the engine's
        # data dir lives under %ProgramData%, whose default ACL grants
        # BUILTIN\Users read — so without this the CA key would be readable by
        # every local account on the machine. Whoever has that key can mint a
        # trusted certificate for any domain and impersonate it to this host
        # with a valid padlock, which turns the security product into the
        # attack. Hardening the directory FIRST means the key is restricted the
        # instant it is written, rather than existing world-readable for the
        # window between generation and a later fix-up.
        #
        # Fail CLOSED: if the directory cannot be protected, do not create a CA
        # key there at all. A deliberate escape hatch exists for anyone who
        # genuinely accepts the risk, but it must be set explicitly.
        TLS_MITMPROXY_CONF_DIR.mkdir(parents=True, exist_ok=True)
        ok, detail = secure_file.harden(TLS_MITMPROXY_CONF_DIR, is_dir=True)
        if not ok and os.environ.get("VALKYRIE_ALLOW_EXPOSED_CA_KEY") != "1":
            log.error(
                "TLS inspection refused to start: the CA key directory cannot "
                "be protected (%s). The CA private key would be readable by "
                "other local accounts, which would let them impersonate any "
                "HTTPS site to this machine. Fix the directory permissions, or "
                "set VALKYRIE_ALLOW_EXPOSED_CA_KEY=1 to accept that risk.",
                detail)
            return False
        if not ok:
            log.warning("TLS inspection starting with an EXPOSED CA key "
                        "directory (%s) — VALKYRIE_ALLOW_EXPOSED_CA_KEY=1 was "
                        "set. Any local account can impersonate any HTTPS "
                        "site to this machine.", detail)

        ready = threading.Event()
        error: list[Exception] = []
        bound: list[bool] = []

        def _run() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            try:
                opts = options.Options(
                    listen_host="127.0.0.1",
                    listen_port=self.port,
                    confdir=str(TLS_MITMPROXY_CONF_DIR),
                )
                # mitmproxy's DumpMaster falls back to asyncio.get_running_loop()
                # when loop= is omitted, which raises RuntimeError here because
                # no loop is actively running yet at construction time (we only
                # start running it below via loop.run_until_complete). Pass our
                # explicit loop instead.
                master = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
                self._addon = ValkyrieAddon(
                    store=self.store, blocklist=self.blocklist,
                    behavioral=self.behavioral, rules=self.rules,
                    threat_intel=self.threat_intel,
                )
                master.addons.add(self._addon)
                self._master = master

                async def _signal_when_bound_or_dead() -> None:
                    # Poll for the actual bind outcome instead of trusting
                    # construction success. proxyserver.is_running only
                    # flips True once setup_servers() has actually bound the
                    # listening socket (see Proxyserver.running() in
                    # mitmproxy.addons.proxyserver). Startup errors (e.g.
                    # port already in use) surface via mitmproxy's
                    # ErrorCheck addon calling sys.exit(1) from *inside*
                    # this same event loop — that raises SystemExit on the
                    # task running master.run(), which is handled below by
                    # the outer except; should_exit is also checked here in
                    # case a future mitmproxy version signals failure that
                    # way instead.
                    for _ in range(50):   # ~5s at 0.1s each
                        if master.should_exit.is_set():
                            bound.append(False)
                            ready.set()
                            return
                        ps = master.addons.get("proxyserver")
                        if ps is not None and getattr(ps, "is_running", False):
                            bound.append(True)
                            ready.set()
                            return
                        await asyncio.sleep(0.1)
                    # Timed out waiting for a definitive bind/fail signal.
                    bound.append(False)
                    ready.set()

                loop.create_task(_signal_when_bound_or_dead())
                loop.run_until_complete(master.run())
            except BaseException as exc:
                # BaseException (not just Exception): mitmproxy's ErrorCheck
                # addon reports startup failures (e.g. "port already in
                # use") by calling sys.exit(1) from within the running
                # coroutine, which raises SystemExit — a BaseException
                # subclass that a plain `except Exception` does NOT catch.
                # Missing this previously meant the poller above had to hit
                # its full timeout to notice the bind had failed, since
                # neither `error` nor `bound` got populated promptly.
                error.append(exc if isinstance(exc, Exception) else RuntimeError(str(exc)))
                ready.set()
            finally:
                loop.close()

        self._thread = threading.Thread(target=_run, daemon=True, name="tls-inspector")
        self._thread.start()
        ready.wait(timeout=8)
        if error or self._master is None or not bound or not bound[0]:
            return False
        return True

    def stop(self) -> None:
        if self._master is not None and self._loop is not None:
            try:
                self._loop.call_soon_threadsafe(self._master.shutdown)
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._master = None
        self._loop = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and self._master is not None

    def get_intercept_count(self) -> int:
        return self._addon.intercept_count if self._addon is not None else 0
