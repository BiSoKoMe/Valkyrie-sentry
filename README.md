# Valkyrie
**Local Privacy Engine — DNS sinkhole, firewall blocker, WiFi guard**

Stops corporate tracking at the network level. Valkyrie intercepts telemetry, ad-tracking, and data-broker traffic before it leaves your machine — across every app, every website, and every WiFi network.

---

## Terminal Commands (All Modes)

### 1. Install dependencies
```bash
pip install -r requirements.txt
pip install -r requirements_web.txt
```

### 2. Build the web UI (first time / after updates)
```bash
cd ui
npm install
npm run build
cd ..
```

### 3. Start the backend server
```bash
python -m uvicorn valkyrie_api:app --host 127.0.0.1 --port 8000
```
Then open `http://localhost:8000` in your browser.

---

### Protection Modes (run in a separate admin terminal)

#### Shield Mode — Maximum protection (recommended)
Combines DNS sinkhole + firewall injection + WiFi guard simultaneously.
```bash
python valkyrie.py shield
```

#### DNS Sinkhole only
Blocks tracker domains at the DNS level. All tracker queries return `0.0.0.0`.
```bash
python valkyrie.py dns
```

#### Watch Mode — Connection monitor + firewall
Continuously scans live connections and injects firewall rules for trackers.
```bash
python valkyrie.py watch
```

#### Watch + DNS (combined)
```bash
python valkyrie.py watch --dns
```

#### Monitor Mode — Alerts only, no blocking
Logs tracking activity but does not block anything.
```bash
python valkyrie.py monitor
```

#### Live Scanner — one-shot audit
Scans current connections and shows per-app privacy scores.
```bash
python valkyrie.py scan
```

#### WiFi Security Check
One-shot check: detects open networks and DNS hijacking.
```bash
python valkyrie.py wifi-check
```

#### View alert history
```bash
python valkyrie.py alerts
python valkyrie.py alerts --hours 168
```

#### Update blocklists (~1M+ domains)
Downloads Steven Black, OISD, AdGuard DNS, HaGeZi Pro++, URLhaus malware, EasyPrivacy.
```bash
python valkyrie.py update
```

---

### Custom DNS port (if port 5353 is taken)
```bash
python valkyrie.py shield --dns-port 53
python valkyrie.py dns --dns-port 53
```

### LAN access (expose UI to other devices on your network)
```bash
python -m uvicorn valkyrie_api:app --host 0.0.0.0 --port 8000
python valkyrie.py shield --api-bind 0.0.0.0
```

---

### Build standalone .exe (Windows)
Packages everything into a single `dist/Valkyrie.exe` — no Python needed.
```bash
build.bat
```

### Start in dev mode (all terminals at once)
```bash
start.bat
```

---

## Quick Reference

| Command | What it does | Blocks? |
|---|---|---|
| `python valkyrie.py shield` | DNS + firewall + WiFi guard | Yes |
| `python valkyrie.py dns` | DNS sinkhole only | Yes (DNS) |
| `python valkyrie.py watch --dns` | Connections + DNS sinkhole | Yes |
| `python valkyrie.py watch` | Connection firewall only | Yes (FW) |
| `python valkyrie.py monitor` | Alerts with no blocking | No |
| `python valkyrie.py scan` | One-shot connection audit | No |
| `python valkyrie.py wifi-check` | WiFi security check | No |
| `python valkyrie.py update` | Download ~1M+ blocklist domains | — |
| `python valkyrie.py alerts` | View recent alert log | — |

> **All blocking modes require Administrator / sudo** — right-click the terminal and run as Administrator on Windows.

---

## What It Protects Against

- **DNS tracking** — returns `0.0.0.0`/`::` for 1M+ surveillance domains (IPv4 A and IPv6 AAAA) so requests never reach trackers
- **ISP/government DNS surveillance** — all upstream DNS queries travel over DoT (DNS-over-TLS) to Mullvad's no-log resolver; your ISP sees only encrypted TLS traffic, not your query content
- **App telemetry** — blocks Spotify, Steam, Discord, Epic Games, Sentry, and other app-level phone-home connections
- **Ad networks** — Google Ads, Meta Pixel, Twitter/X Ads, Snap, TikTok, LinkedIn Insight Tag, Bing Ads
- **Data brokers** — Segment, Amplitude, Mixpanel, Hotjar, FullStory, Datadog, New Relic
- **Malware C2** — URLhaus live threat feed of known command-and-control hosts
- **Open WiFi attacks** — detects unencrypted/WEP/WPA networks and DNS hijacking by rogue access points

---

## Requirements

- Python 3.8+
- Windows (firewall rules use `netsh`; DNS switching uses `netsh interface`)
- Node.js 18+ (for building the UI)
- Administrator rights (for DNS switching and firewall rules)

---

## Web Dashboard

Start the backend, then open `http://localhost:8000`.

| Section | What it shows |
|---|---|
| Overview | Status, Shield button, live protection stats |
| Live Activity | Real-time DNS events, tracker detections, firewall blocks |
| Applications | Per-app privacy score and flagged connections |
| Blocklist | Add/remove domains, download community lists |
| Devices | LAN device map |
| Settings | Config, log export |
| Terminal | Live log stream via WebSocket |

---

## Project Structure

```
valkyrie/
├── valkyrie.py          # Core engine — all modes (shield, dns, watch, scan, ...)
├── valkyrie_api.py      # FastAPI backend — serves the web UI and REST API
├── launcher.py          # PyInstaller entry point for the .exe bundle
├── valkyrie.spec        # PyInstaller build config
├── build.bat            # One-click .exe builder
├── start.bat            # Dev launcher (opens backend + UI terminals)
├── requirements.txt     # Python core dependencies
├── requirements_web.txt # Python web stack dependencies
├── blocklists/          # Downloaded and custom domain lists
├── logs/                # Per-session log files
├── ui/                  # React + TypeScript + Tailwind frontend
│   ├── src/components/  # Dashboard pages
│   ├── src/lib/api.ts   # API client
│   └── dist/            # Production build (auto-served by FastAPI)
└── valkyrie_events.db   # SQLite event log (auto-created)
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Access is denied` on firewall rules | Run terminal as Administrator |
| `dnslib not installed` | `pip install -r requirements.txt` |
| Port 5353 already in use | Add `--dns-port 53` (requires admin) |
| Port 8000 already in use | Change port: `--port 8001` |
| UI shows blank page | Run `cd ui && npm run build` first |
| DNS not switching | Must run as Administrator; check `netsh interface ip show dns` |
| `ECONNREFUSED` in browser | Backend isn't running — start `python -m uvicorn valkyrie_api:app` first |

---

## Roadmap

- [x] DNS sinkhole (dnslib)
- [x] Live connection scanner with process attribution
- [x] Windows Firewall active mitigation
- [x] OS DNS auto-switcher (Windows/macOS/Linux)
- [x] Shield Mode — all layers combined
- [x] WiFi Guard — open network + DNS hijack detection
- [x] REST API + React web dashboard
- [x] Real-time terminal log streaming (WebSocket)
- [x] Blocklist auto-update (6 sources, ~1M+ domains)
- [x] Standalone .exe via PyInstaller
- [ ] iptables/nftables for Linux/Pi gateway blocking
- [ ] Multi-device cloud dashboard with auth
- [ ] iOS/Android companion app
