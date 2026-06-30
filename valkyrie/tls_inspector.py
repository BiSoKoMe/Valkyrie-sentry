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
import threading
from pathlib import Path
from typing import Optional

from .config import TLS_CA_CERT_PATH, TLS_MITMPROXY_CONF_DIR, TLS_PROXY_PORT


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
                 port: int = TLS_PROXY_PORT) -> None:
        self.store      = store
        self.blocklist   = blocklist
        self.behavioral  = behavioral
        self.rules       = rules
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
        generated = TLS_MITMPROXY_CONF_DIR / "mitmproxy-ca-cert.pem"
        if generated.exists() and not TLS_CA_CERT_PATH.exists():
            TLS_CA_CERT_PATH.write_bytes(generated.read_bytes())
            key_src = TLS_MITMPROXY_CONF_DIR / "mitmproxy-ca.pem"
            if key_src.exists():
                from .config import TLS_CA_KEY_PATH
                TLS_CA_KEY_PATH.write_bytes(key_src.read_bytes())
        print(CA_INSTALL_INSTRUCTIONS.format(cert=TLS_CA_CERT_PATH))
        return TLS_CA_CERT_PATH

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Start mitmproxy on a background thread. Returns False (and does
        not raise) if mitmproxy is not installed."""
        try:
            from mitmproxy import options
            from mitmproxy.tools.dump import DumpMaster
        except ImportError:
            return False

        from .tls_addon import ValkyrieAddon

        TLS_MITMPROXY_CONF_DIR.mkdir(parents=True, exist_ok=True)
        ready = threading.Event()
        error: list[Exception] = []

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
                master = DumpMaster(opts, with_termlog=False, with_dumper=False)
                self._addon = ValkyrieAddon(
                    store=self.store, blocklist=self.blocklist,
                    behavioral=self.behavioral, rules=self.rules,
                )
                master.addons.add(self._addon)
                self._master = master
                ready.set()
                loop.run_until_complete(master.run())
            except Exception as exc:
                error.append(exc)
                ready.set()
            finally:
                loop.close()

        self._thread = threading.Thread(target=_run, daemon=True, name="tls-inspector")
        self._thread.start()
        ready.wait(timeout=10)
        if error or self._master is None:
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
