# Valkyrie
**Enterprise Privacy Ecosystem — Prototype**

Stop corporate tracking at the gateway. Valkyrie is a local DNS sinkhole, connection scanner, and firewall mitigator that intercepts telemetry, data-broker traffic, and ad-tracking before it leaves your machine — or your entire home network.

## What It Does
- **DNS Sinkhole** — Intercepts DNS queries and returns `0.0.0.0` for known surveillance domains
- **Live Scanner** — Shows exactly which app/process is making every outbound connection
- **Active Mitigation** — Automatically injects Windows Firewall rules to block established tracker connections
- **OS DNS Switcher** — Automatically points your system DNS to 127.0.0.1 when in DNS/monitor mode
- **REST API** — JSON API on `localhost:8080` for dashboards and integrations
- **LAN Mapper** — Discovers devices on your local network via ARP + DHCP leases

## Requirements
- Python 3.8+
- `pip install -r requirements.txt`
- **Administrator / sudo** for DNS sinkhole on port 53, firewall mitigation, and OS DNS switching

## Quick Start
```bash
# Install dependencies
pip install -r requirements.txt

# One-shot scan: Wi-Fi check + live connections + privacy scores
python valkyrie.py scan

# Continuous monitor with DNS blocking
python valkyrie.py watch --dns

# DNS sinkhole only
python valkyrie.py dns

# Monitor mode: alerts only, no blocking
python valkyrie.py monitor

# View recent tracking alerts
python valkyrie.py alerts --hours 168
```

## Modes

| Mode | What It Does | Blocking? |
|------|-------------|-----------|
| `scan` | One-shot Wi-Fi check + live connection audit + per-app privacy scores | No |
| `watch` | Continuous monitoring, names and shames trackers | Yes (Windows firewall) |
| `watch --dns` | Watch + DNS sinkhole for domain-level blocking | Yes |
| `dns` | DNS sinkhole only, log queries | Yes |
| `monitor` | DNS monitor + connection alerts, no blocking | No |
| `alerts` | Print SQLite alert log | N/A |

## Dashboard
Open `index.html` in a browser while Valkyrie is running. It polls `http://127.0.0.1:8080/stats` every 2 seconds.

For LAN access from phones/tablets:
```bash
python valkyrie.py dns --api-bind 0.0.0.0
```
Then open `http://<your-pi-ip>:8080` from any device on the network.

## Blocklist Management
- Curated tracker domains are hardcoded in `valkyrie.py`
- Additional domains can be added as `.txt` files in `blocklists/`
- Hosts-format files are auto-imported on startup

## Pi / Hardware Gateway Deployment

### systemd Service
Create `/etc/systemd/system/valkyrie.service`:
```ini
[Unit]
Description=Valkyrie Privacy Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/valkyrie
ExecStart=/usr/bin/python3 /home/pi/valkyrie/valkyrie.py dns --api-bind 0.0.0.0 --dns-port 53
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable valkyrie
sudo systemctl start valkyrie
sudo systemctl status valkyrie
```

### Network Setup (Router Mode)
To use a Pi as a dedicated gateway:
1. Enable IP forwarding: `sudo sysctl -w net.ipv4.ip_forward=1`
2. Set up iptables NAT: `sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE`
3. Connect Pi WAN port to your modem, LAN port to your router/switch
4. Set Pi DNS (port 5353 default) or use port 53 with the systemd service above

## Troubleshooting
- **"Could not start API on 127.0.0.1:8080"** — Another process is using port 8080. Kill it or change `API_SERVER_PORT` in the script.
- **"dnslib not installed"** — Run `pip install -r requirements.txt`
- **DNS not switching on macOS** — Grant Terminal/iTerm Full Disk Access and try again with sudo.
- **"Access is denied" for firewall rules** — Run `python valkyrie.py watch` as Administrator on Windows.
- **No connections shown in scan** — Close/reopen an app or browse a website, then scan again.

## Web Dashboard (React + FastAPI)
The modern web control panel provides real-time monitoring, device management, and one-click mode switching.

### Setup
```bash
# From the valkyrie/ directory
pip install -r requirements_web.txt
cd ui && npm install && npm run build && cd ..

# Start the API server
python valkyrie_api.py
```

Open `http://localhost:8000/api/dashboard` in your browser.

### Features
- **Overview** — System status, protection stats, quick actions
- **Live Activity** — Real-time DNS events, tracker detections, firewall blocks
- **Devices** — LAN device map with privacy scores
- **Applications** — Per-app privacy scoring and flagged connections
- **Blocklist** — Add/remove domains, import hosts files, reload
- **Settings** — Service control, configuration, export logs
- **Terminal** — Live log streaming via WebSocket, auto-scroll, color-coded output

## Project Structure
```
valkyrie/
├── valkyrie.py              # Main CLI entry point
├── valkyrie_api.py          # FastAPI backend for web dashboard
├── requirements.txt         # Python dependencies (core)
├── requirements_web.txt     # Python dependencies (web stack)
├── valkyrie.service         # systemd unit for Pi deployment
├── index.html               # Legacy dashboard (replaced by React UI)
├── README.md                # This file
├── valkyrie_events.db       # SQLite event log (auto-created)
├── ui/                      # React + TypeScript + Tailwind frontend
│   ├── src/components/      # Dashboard sections
│   ├── src/lib/api.ts       # API client
│   └── dist/                # Production build (served by FastAPI)
└── blocklists/
    └── tracker-domains.txt  # Additional importable domains
```

## Roadmap
- [x] DNS sinkhole with dnslib
- [x] Live connection scanner with process attribution
- [x] Windows firewall active mitigation
- [x] OS DNS auto-switcher (Windows/macOS/Linux)
- [x] REST API + web dashboard
- [x] LAN device mapper (ARP/DHCP)
- [x] Web dashboard (React + FastAPI + WebSocket)
- [x] Real-time terminal log streaming
- [x] Blocklist auto-update (`valkyrie.py update`)
- [x] `--api-bind` flag for LAN access
- [ ] Cloud threat feed subscription
- [ ] systemd service + Pi router integration
- [ ] iptables/nftables network-layer blocking
- [ ] Multi-device cloud dashboard with auth
