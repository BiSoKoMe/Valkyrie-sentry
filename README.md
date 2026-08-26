# Valkyrie

**A privacy gateway for your Windows PC.**

> **Proof, not a pitch.** Detection claims here are backed by a real
> evaluation: live Atomic Red Team attack techniques executed against a
> running instance on a disposable VM and scored against its own incident
> log — not a synthetic test, not a rules-count. Current proven floor:
> **38 of 52 in-scope techniques detected (73.1%)**, with every miss
> explained and one live-found, live-fixed false-positive bug documented
> with before/after numbers. Read the methodology and full results in
> [`docs/LIVE_FIRE_EVALUATION.md`](docs/LIVE_FIRE_EVALUATION.md), or the
> formal write-up in [`docs/RESEARCH_PAPER.md`](docs/RESEARCH_PAPER.md).

---

## 1. What is Valkyrie

Valkyrie is a bouncer for your internet connection. Every app on your computer constantly makes hidden connections to advertisers, trackers, and data brokers - Valkyrie sits at the door and turns away the ones that are just there to watch you, while letting the traffic you actually want through. It runs quietly in the background and has no noticeable effect on normal browsing: pages load the same, your apps work the same. You just stop being followed.

---

## 2. What it protects against

Valkyrie blocks the ways your machine leaks information about you. It stops background apps from silently "phoning home," using a list of **572,000+ known tracker and ad domains** and a firewall list of **12,000+ malicious IP ranges**. When something brand new shows up that isn't on any list yet, behavioral heuristics can still flag it by the *shape* of the DNS request - an unusually random-looking (high-entropy) hostname, an abnormal burst of lookups from one app, or an abuse-prone TLD. It also switches off **16 of Windows' own built-in tracking systems** (telemetry), and - when the optional Unbound resolver is installed - it looks up website addresses privately instead of leaking every site you visit to Google or Cloudflare. Finally, it watches for apps trying to sneak around your DNS protection (DoH bypass attempts) and flags them.

To be honest about the limits: Valkyrie does **not** hide your physical location from cell towers, it does **not** hide activity from your internet provider (that needs a VPN, which is a planned feature), and it cannot inspect a handful of apps that use certificate pinning - most banking apps, for example - which deliberately refuse any inspection.

---

## 3. Requirements

1. **Windows 10 or 11.**
2. **Python 3.10 or higher**, installed from the official site: <https://www.python.org/downloads/> - **not** the Microsoft Store version, which does not work reliably for a background service. During install, tick **"Add Python to PATH."**
3. **Administrator access** on your computer (needed once, for setup).
4. **Unbound DNS resolver** - optional but recommended for fully private lookups: <https://nlnetlabs.nl/projects/unbound/download/>

---

## 4. Installation (first time only)

You only do this once.

1. Download or clone this repository to a folder on your PC.

2. Open a terminal in the Valkyrie folder. (In File Explorer, open the folder, click the address bar, type `cmd`, and press Enter.)

3. Install the dependencies:

   ```
   pip install -r requirements_modular.txt
   ```

4. Run the one-time setup. In the Valkyrie folder, right-click **`setup_task.ps1`** and choose **"Run with PowerShell."** Click **Yes** on the Administrator prompt when it appears.

   This registers Valkyrie as a Windows task so that, from now on, it can start with full privileges **without** asking you for an Administrator prompt every single time.

That's it. You never need to do step 4 again.

---

## 5. Daily use

**To start protection:**

```
Double-click start_valkyrie.bat
```

No Administrator prompt appears. Valkyrie starts automatically and your browser opens the dashboard at <http://localhost:8090>.

**To stop protection:**

```
Double-click stop_valkyrie.bat
```

Your internet settings return to normal.

**Alternative - the visual launcher:** double-click **`launcher.bat`** to open a clean status page (`launcher.html`). It shows whether Valkyrie is **Running** or **Stopped** and gives you buttons to open the dashboard, restart, or stop protection.

---

## 6. The dashboard

The dashboard (at <http://localhost:8090>) is your live window into what Valkyrie is doing:

- **Live DNS events** - every domain your computer looks up, in real time, with the decision (allowed, blocked, or flagged).
- **DNS blocked** and **Firewall blocked** counts for the last 24 hours.
- **Which app** made each request, so you can see exactly who was phoning home.
- **MAC address** panel - randomize or restore your Wi-Fi hardware address.
- **System** panel - Windows telemetry status, file-integrity check, and whether zero-log (RAM-only) mode is on.
- **System Control** panel - a live **protection health** indicator (green when the DNS sinkhole is confirmed answering, red if it silently stops), a **Meeting Mode** kill switch, and **Restart Valkyrie** / **Stop Protection** buttons.
- **Security . EDR** link (top-right) - opens the detection & response console.

**Meeting Mode** is a one-tap kill switch for sensitive moments: it blocks *all* outbound network traffic instantly. The dashboard stays reachable (loopback is exempt) so you can turn it back off, and it shows how long it has been active.

> **Private by default.** The dashboard now binds to **loopback (`127.0.0.1`)
> only**, so its live browsing feed is *not* reachable from other devices on your
> network. To view it from another device (e.g. a router deployment), start
> Valkyrie with `--web-host 0.0.0.0`; when you do, off-loopback access requires
> the control token in `data/control_token.txt`.

---

## 6b. Security / EDR console

Beyond blocking, Valkyrie ships a **detection & response** console at
<http://localhost:8090/edr>. It interprets what Valkyrie already sees and turns it
into things a defender actually works with.

> **Scope, honestly.** This layer correlates process, network, persistence,
> and ETW telemetry (PowerShell script-block logging, WMI activity, Sysmon)
> into incidents and lets you respond to them. It is *not* a kernel-level EDR
> - there is no signed minifilter/ELAM driver, so pre-execution blocking and
> tamper-proof visibility are out of reach without one (see
> `docs/ARCHITECTURE.md`'s infrastructure-boundaries table). What it *does*
> have is real, measured evidence behind it: **73.1% of a live, destructive
> Atomic Red Team battery detected on a genuinely running instance** - not a
> synthetic replay, not a rules count. See
> **[`docs/LIVE_FIRE_EVALUATION.md`](docs/LIVE_FIRE_EVALUATION.md)** for the
> full methodology, the honest list of what wasn't detected and why, and a
> real case study of a self-inflicted false-positive bug found and fixed with
> before/after proof.

- **Incidents with timelines** - related detections (a repeated beacon, a
  threat-intel-IP callback, a DoH-bypass attempt) are correlated into a single
  incident with a running timeline and an escalating severity, instead of a flat
  wall of alerts.
- **Threat hunting** - a safe, structured query surface over your event history,
  plus one-click saved hunts ("beacon candidates", "noisiest talkers", "rare
  domains", ...).
- **Response actions** - block a domain, kill a process, or network-isolate the
  endpoint - **dry-run first** (you see the exact effect before anything happens)
  and fully audited.
- **Automated investigation** - a built-in, fully-local analyst writes up every
  incident with a severity rationale, MITRE ATT&CK techniques, and recommended
  actions. This analyst is **deterministic (rule-based), not a machine-learning
  model** - it runs entirely offline and nothing leaves your machine. An optional
  LLM-assisted narrative is available but **off by default**, and the AI backend
  is **vendor-neutral** (Anthropic, OpenAI, or a fully-local OpenAI-compatible
  server). A network provider sends incident details to the configured endpoint -
  opt in only if you want that; the local provider keeps everything on-box.
- **Plugin architecture** - drop a `*.py` file into `data/plugins/` to add your
  own detections, responders, or enrichers. Plugins run as ordinary Python with
  Valkyrie's privileges, so loading is gated on trust: place an `allowed.sha256`
  manifest (one approved SHA-256 per line) in the plugin directory and only those
  exact files load - everything else is skipped (fail-closed). Without a manifest
  plugins still load, but each is flagged **unverified** and logged. Full
  sandboxing is on the roadmap.

Full details, including the privacy trade-offs and the signed remote-response
channel for managed fleets, are in **`docs/EDR.md`**.

---

## 7. Advanced flags

If you prefer to start Valkyrie yourself from a terminal:

```
python -m valkyrie [options]
```

| Flag | What it does |
|------|--------------|
| `--port 53` | DNS listen port (default: `5300`) |
| `--web` | Enable the web dashboard |
| `--web-port 8090` | Dashboard port (default: `8080`; the start scripts use `8090`) |
| `--web-host 0.0.0.0` | Dashboard bind address (default: `127.0.0.1`, loopback-only; use `0.0.0.0` to expose on the LAN - then off-loopback calls require the control token) |
| `--no-ui` | Disable the terminal display (run headless) |
| `--zero-log` | RAM-only mode - nothing is written to disk |
| `--mac-rand` | Randomize your MAC address on reconnect |
| `--tls` | Enable HTTPS/TLS inspection (needs the optional `mitmproxy` package) |
| `--kill-telemetry` | Scan and disable Windows telemetry |
| `--meeting-on` / `--meeting-off` | Meeting Mode kill switch - block / restore all outbound traffic |
| `--fingerprint` | Normalize the TCP/IP fingerprint (TTL 64, TCP timestamps off) |
| `--no-edr` | Disable the EDR layer (incidents, hunting, response) |
| `--endpoint` | Enable endpoint telemetry - observe process starts (LOLBins, Office-spawns-shell, temp-dir execution) **and** outbound connections to threat-intel IPs (catches hard-coded-IP C2 that skips DNS), feeding both into the EDR layer |
| `--incidents` | Print current EDR incidents and exit |
| `--hunt NAME` | Run a saved threat hunt and exit (`--hunt list` to see them) |
| `--edr-plugin-dir DIR` | Load third-party EDR plugins from a directory |
| `--debug` | Show detailed DNS forwarding logs |

On startup Valkyrie runs a **self-test** - it checks its dependencies, that the data folder is writable, and that its DNS port is free. If anything critical is wrong it prints the reason and exits cleanly rather than pretending to protect you. After that, a background **heartbeat** keeps re-checking that the DNS sinkhole is actually answering, and flips the dashboard to a red "protection degraded" state the moment it isn't.

**Example - the full stack with everything enabled:**

```
python -m valkyrie --port 53 --web --no-ui --web-port 8090 --mac-rand --tls --debug
```

---

## 7b. Standalone executable (`valkyrie.exe`)

Prefer a single double-clickable file with no Python install on the target
machine? The whole app - EDR layer and web console included - can be packaged
into **`valkyrie.exe`** with PyInstaller. On a Windows machine, run
**`build_exe.bat`** (or `build_exe.ps1`); the result is `dist\valkyrie.exe`,
which keeps its `data\` folder, rules, and logs next to itself. Full
instructions and the (honest) cross-compile caveat are in
**`docs/BUILD_EXE.md`**.

---

## 8. Hardware deployment (GL.iNet)

Valkyrie can also be installed onto a GL.iNet travel router (OpenWrt) so that **every device on the network** - phones, laptops, smart TVs - is protected automatically, with nothing to install on each device. The installer script and its instructions live in **`install_sentry.sh`**; run it on the router over SSH.

---

## 9. Emergency recovery

If anything goes wrong and your internet stops working, the simplest fix is to **double-click `stop_valkyrie.bat`**, which resets everything automatically.

If that isn't available, open **PowerShell as Administrator** and run:

```
taskkill /F /IM python.exe 2>$null
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ResetServerAddresses
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ResetServerAddresses
ipconfig /flushdns
```

This stops Valkyrie, hands your DNS back to normal, and clears the lookup cache.

---

## 9b. Documentation & evidence

For anyone evaluating Valkyrie technically, not just running it:

| Document | What's in it |
|---|---|
| **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** | The real system diagram (sensors → correlation → incidents), and an honest capability map: shipped, buildable, and infrastructure boundaries that no amount of code can close (e.g. no signed kernel driver) |
| **[`docs/LIVE_FIRE_EVALUATION.md`](docs/LIVE_FIRE_EVALUATION.md)** | **Start here for detection claims.** Real Atomic Red Team execution against a running instance, methodology, the full benchmark result (73.1% proven floor), every miss explained, and a real found-and-fixed bug with before/after proof |
| [`docs/RESEARCH_PAPER.md`](docs/RESEARCH_PAPER.md) | The same evaluation, written up formally (abstract, methodology, threats to validity) for anyone who wants the academic-paper version |
| [`docs/DETECTION_EFFICACY_REPORT.md`](docs/DETECTION_EFFICACY_REPORT.md) | A weaker, complementary measurement: synthetic technique-representative inputs fed straight to the classifier code (no execution, no sensors) - useful for fast regression checking, not a substitute for the live-fire result above |
| [`docs/EDR.md`](docs/EDR.md) | Full detection & response console reference |
| [`docs/GAP_ANALYSIS.md`](docs/GAP_ANALYSIS.md) | What's shipped vs. planned, updated as an ongoing process |

**On screenshots/demo:** this repo is developed in an environment that cannot
launch the Electron desktop shell to capture live screenshots (no windowed
GUI available). The dashboard and EDR console are real and running code, not
mockups - the honest way to see them is to run Valkyrie yourself (Section 5)
and open <http://localhost:8090>.

## 10. Project structure

The files a new user actually cares about:

```
Valkyrie\
├── start_valkyrie.bat        Start protection (double-click, daily use)
├── stop_valkyrie.bat         Stop protection (double-click, daily use)
├── setup_task.ps1            One-time setup (run once as Administrator)
├── launcher.bat              Opens the visual status/control page
├── requirements_modular.txt  Python dependencies to install
├── valkyrie_rules.yaml       Your personal allow / block rules
├── install_sentry.sh         GL.iNet router installer
├── start_all.ps1 / stop_all.ps1   The scripts the tasks actually run
├── valkyrie\                 The application itself (python -m valkyrie)
│   ├── __main__.py           Entry point and command-line flags
│   ├── dns_interceptor.py    The DNS bouncer core
│   ├── telemetry_killer.py   Disables Windows telemetry
│   └── web\
│       ├── dashboard.html    The live dashboard
│       └── launcher.html     The visual start/stop page
└── data\                     Blocklists, logs, and database (auto-created)
```
