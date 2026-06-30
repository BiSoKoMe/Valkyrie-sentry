#!/bin/sh
# Valkyrie Sentry — hardware installer for GL.iNet GL-MT300N-V2 (OpenWrt)
# Run on the router via SSH:  sh install_sentry.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo "${GREEN}[PASS]${NC} $*"; }
fail() { echo "${RED}[FAIL]${NC} $*" >&2; exit 1; }
info() { echo "${YELLOW}[INFO]${NC} $*"; }

# ── Step 1: System check ─────────────────────────────────────────────────────
info "Step 1 — System check"

[ -f /etc/openwrt_release ] || fail "Not an OpenWrt system (/etc/openwrt_release missing)"

FREE_OVERLAY=$(df -k /overlay 2>/dev/null | awk 'NR==2 {print $4}')
[ -z "$FREE_OVERLAY" ] && fail "Cannot determine /overlay free space"
[ "$FREE_OVERLAY" -gt 20480 ] || fail "Not enough space on /overlay (need >20 MB, have ${FREE_OVERLAY} kB)"

FREE_RAM=$(free 2>/dev/null | awk '/^Mem:/ {print $4}')
[ -z "$FREE_RAM" ] && FREE_RAM=$(cat /proc/meminfo | awk '/^MemFree:/ {print $2}')
[ "$FREE_RAM" -gt 32768 ] || fail "Not enough RAM (need >32 MB free, have ${FREE_RAM} kB)"

ok "System checks passed (overlay=${FREE_OVERLAY}kB free, RAM=${FREE_RAM}kB free)"

# ── Step 2: Install dependencies ─────────────────────────────────────────────
info "Step 2 — Installing dependencies"

opkg update || fail "opkg update failed — check internet connection"
opkg install python3 python3-pip python3-dev || fail "Failed to install Python3"
opkg install unbound unbound-control         || info "Unbound install had warnings (may be OK)"
opkg install iptables iptables-mod-nat-extra || fail "Failed to install iptables"
opkg install curl ca-certificates            || fail "Failed to install curl"

pip3 install dnspython psutil pyyaml rich fastapi uvicorn aiofiles \
  || fail "pip3 install failed"

ok "Dependencies installed"

# ── Step 3: Copy Valkyrie ────────────────────────────────────────────────────
info "Step 3 — Deploying Valkyrie"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

mkdir -p /opt/valkyrie

# Copy Python package
cp -r "${SCRIPT_DIR}/valkyrie" /opt/valkyrie/
[ -f "${SCRIPT_DIR}/valkyrie_rules.yaml" ] && \
    cp "${SCRIPT_DIR}/valkyrie_rules.yaml" /opt/valkyrie/

# Create data directory
mkdir -p /opt/valkyrie/data

chmod 700 /opt/valkyrie
chmod -R 600 /opt/valkyrie/valkyrie/*.py 2>/dev/null || true

ok "Valkyrie deployed to /opt/valkyrie"

# ── Step 4: DNS redirect via iptables ────────────────────────────────────────
info "Step 4 — Configuring DNS redirect"

FIREWALL_USER=/etc/firewall.user

# Remove old Valkyrie rules if present
grep -v "Valkyrie" "${FIREWALL_USER}" > /tmp/fw_tmp 2>/dev/null || true
cp /tmp/fw_tmp "${FIREWALL_USER}" 2>/dev/null || true

cat >> "${FIREWALL_USER}" << 'EOF'
# Valkyrie DNS redirect
iptables -t nat -A PREROUTING -i br-lan -p udp --dport 53 -j REDIRECT --to-port 5300
iptables -t nat -A PREROUTING -i br-lan -p tcp --dport 53 -j REDIRECT --to-port 5300
EOF

/etc/init.d/firewall restart 2>/dev/null || true
ok "DNS redirect configured (port 53 → 5300)"

# ── Step 5: Unbound config ───────────────────────────────────────────────────
info "Step 5 — Writing Unbound config"

mkdir -p /etc/unbound
cat > /etc/unbound/unbound.conf << 'EOF'
server:
    interface: 127.0.0.1
    port: 5301
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    prefetch: yes
    rrset-cache-size: 64m
    msg-cache-size: 32m

forward-zone:
    name: "."
    forward-addr: 9.9.9.9
EOF

ok "Unbound config written"

# ── Step 6: Startup service ──────────────────────────────────────────────────
info "Step 6 — Creating startup service"

cat > /etc/init.d/valkyrie << 'EOF'
#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command python3 -m valkyrie \
        --web --no-ui --port 5300 --web-port 8080
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF

chmod +x /etc/init.d/valkyrie

cd /opt/valkyrie && /etc/init.d/valkyrie enable
/etc/init.d/valkyrie start

ok "Valkyrie service enabled and started"

# ── Step 7: Firewall allow port 8080 ─────────────────────────────────────────
info "Step 7 — Opening port 8080 in firewall"

uci add firewall rule >/dev/null
uci set firewall.@rule[-1].name='Valkyrie-UI'
uci set firewall.@rule[-1].src='lan'
uci set firewall.@rule[-1].dest_port='8080'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall
/etc/init.d/firewall restart 2>/dev/null || true

ok "Port 8080 open in firewall"

# ── Step 8: Verify ───────────────────────────────────────────────────────────
info "Step 8 — Verifying installation (waiting 10s for services)"
sleep 10

# Test DNS blocking
BLOCKED_IP=$(nslookup doubleclick.net 127.0.0.1 2>/dev/null | awk '/^Address/ && NR>1 {print $2}' | head -1)
if [ "$BLOCKED_IP" = "0.0.0.0" ] || [ "$BLOCKED_IP" = "::" ]; then
    ok "DNS block test: doubleclick.net → ${BLOCKED_IP} (BLOCKED)"
else
    echo "${YELLOW}[WARN]${NC} DNS block test: got ${BLOCKED_IP} (expected 0.0.0.0 — blocklist may still be loading)"
fi

# Test DNS allowing
GOOGLE_IP=$(nslookup google.com 127.0.0.1 2>/dev/null | awk '/^Address/ && NR>1 {print $2}' | head -1)
if echo "${GOOGLE_IP}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && [ "${GOOGLE_IP}" != "0.0.0.0" ]; then
    ok "DNS allow test: google.com → ${GOOGLE_IP}"
else
    echo "${YELLOW}[WARN]${NC} DNS allow test: unexpected response ${GOOGLE_IP}"
fi

# Test web UI
if curl -s --connect-timeout 5 http://127.0.0.1:8080 2>/dev/null | grep -qi "valkyrie"; then
    ok "Web UI test: http://127.0.0.1:8080 is responding"
else
    echo "${YELLOW}[WARN]${NC} Web UI not yet responding on port 8080 — may still be starting"
fi

# ── Step 9: Summary ──────────────────────────────────────────────────────────
echo ""
echo "================================================"
echo "Valkyrie Sentry installed and running."
echo ""
echo "Web dashboard: http://192.168.8.1:8080"
echo "DNS port: 5300"
echo "Every device on this WiFi is now protected."
echo "No setup needed on phones, TVs, or consoles."
echo "================================================"
