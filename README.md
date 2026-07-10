# Valkyrie

**A privacy gateway for your Windows PC.**

---

## 1. What is Valkyrie

Valkyrie is a bouncer for your internet connection. Every app on your computer constantly makes hidden connections to advertisers, trackers, and data brokers — Valkyrie sits at the door and turns away the ones that are just there to watch you, while letting the traffic you actually want through. It runs quietly in the background and has no noticeable effect on normal browsing: pages load the same, your apps work the same. You just stop being followed.

---

## 2. What it protects against

Valkyrie blocks the ways your machine leaks information about you. It stops background apps from silently "phoning home," using a list of **572,000+ known tracker and ad domains** and a firewall list of **12,000+ malicious IP ranges**. When something brand new shows up that isn't on any list yet, behavioral detection catches it by how it acts. It also switches off **16 of Windows' own built-in tracking systems** (telemetry), and — when the optional Unbound resolver is installed — it looks up website addresses privately instead of leaking every site you visit to Google or Cloudflare. Finally, it watches for apps trying to sneak around your DNS protection (DoH bypass attempts) and flags them.

To be honest about the limits: Valkyrie does **not** hide your physical location from cell towers, it does **not** hide activity from your internet provider (that needs a VPN, which is a planned feature), and it cannot inspect a handful of apps that use certificate pinning — most banking apps, for example — which deliberately refuse any inspection.

---

## 3. Requirements

1. **Windows 10 or 11.**
2. **Python 3.10 or higher**, installed from the official site: <https://www.python.org/downloads/> — **not** the Microsoft Store version, which does not work reliably for a background service. During install, tick **"Add Python to PATH."**
3. **Administrator access** on your computer (needed once, for setup).
4. **Unbound DNS resolver** — optional but recommended for fully private lookups: <https://nlnetlabs.nl/projects/unbound/download/>

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

**Alternative — the visual launcher:** double-click **`launcher.bat`** to open a clean status page (`launcher.html`). It shows whether Valkyrie is **Running** or **Stopped** and gives you buttons to open the dashboard, restart, or stop protection.

---

## 6. The dashboard

The dashboard (at <http://localhost:8090>) is your live window into what Valkyrie is doing:

- **Live DNS events** — every domain your computer looks up, in real time, with the decision (allowed, blocked, or flagged).
- **DNS blocked** and **Firewall blocked** counts for the last 24 hours.
- **Which app** made each request, so you can see exactly who was phoning home.
- **MAC address** panel — randomize or restore your Wi-Fi hardware address.
- **System** panel — Windows telemetry status, file-integrity check, and whether zero-log (RAM-only) mode is on.
- **System Control** panel — one-click **Restart Valkyrie** or **Stop Protection** buttons.
- **Security · EDR** link (top-right) — opens the endpoint detection & response console.

---

## 6b. Security / EDR console

Beyond blocking, Valkyrie ships a full **endpoint detection & response** layer at
<http://localhost:8090/edr>. It interprets what Valkyrie already sees and turns it
into things a defender actually works with:

- **Incidents with timelines** — related detections (a repeated beacon, a
  threat-intel-IP callback, a DoH-bypass attempt) are correlated into a single
  incident with a running timeline and an escalating severity, instead of a flat
  wall of alerts.
- **Threat hunting** — a safe, structured query surface over your event history,
  plus one-click saved hunts ("beacon candidates", "noisiest talkers", "rare
  domains", …).
- **Response actions** — block a domain, kill a process, or network-isolate the
  endpoint — **dry-run first** (you see the exact effect before anything happens)
  and fully audited.
- **AI-assisted investigation** — a local analyst writes up every incident with a
  severity rationale, MITRE ATT&CK techniques, and recommended actions. An
  optional Claude-assisted narrative is available but **off by default** (it
  sends incident details to a third party — opt in only if you want that).
- **Plugin architecture** — drop a `*.py` file into `data/plugins/` to add your
  own detections, responders, or enrichers.

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
| `--no-ui` | Disable the terminal display (run headless) |
| `--zero-log` | RAM-only mode — nothing is written to disk |
| `--mac-rand` | Randomize your MAC address on reconnect |
| `--tls` | Enable HTTPS/TLS inspection (needs the optional `mitmproxy` package) |
| `--kill-telemetry` | Scan and disable Windows telemetry |
| `--no-edr` | Disable the EDR layer (incidents, hunting, response) |
| `--incidents` | Print current EDR incidents and exit |
| `--hunt NAME` | Run a saved threat hunt and exit (`--hunt list` to see them) |
| `--edr-plugin-dir DIR` | Load third-party EDR plugins from a directory |
| `--debug` | Show detailed DNS forwarding logs |

**Example — the full stack with everything enabled:**

```
python -m valkyrie --port 53 --web --no-ui --web-port 8090 --mac-rand --tls --debug
```

---

## 8. Hardware deployment (GL.iNet)

Valkyrie can also be installed onto a GL.iNet travel router (OpenWrt) so that **every device on the network** — phones, laptops, smart TVs — is protected automatically, with nothing to install on each device. The installer script and its instructions live in **`install_sentry.sh`**; run it on the router over SSH.

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
