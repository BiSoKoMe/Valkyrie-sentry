#!/bin/sh
# Valkyrie Sentry — hardware uninstaller for OpenWrt

set -e

echo "[INFO] Stopping Valkyrie service..."
/etc/init.d/valkyrie stop  2>/dev/null || true
/etc/init.d/valkyrie disable 2>/dev/null || true

echo "[INFO] Removing service file..."
rm -f /etc/init.d/valkyrie

echo "[INFO] Removing Valkyrie files..."
rm -rf /opt/valkyrie

echo "[INFO] Removing DNS redirect rules from /etc/firewall.user..."
if [ -f /etc/firewall.user ]; then
    grep -v "Valkyrie" /etc/firewall.user > /tmp/fw_tmp 2>/dev/null || true
    cp /tmp/fw_tmp /etc/firewall.user
fi

echo "[INFO] Reloading firewall..."
/etc/init.d/firewall restart 2>/dev/null || true

echo "[INFO] Removing firewall UI rule..."
# Remove the Valkyrie-UI rule from UCI
IDX=$(uci show firewall | grep "Valkyrie-UI" | sed "s/firewall\.@rule\[\([0-9]*\)\].*/\1/" | head -1)
if [ -n "$IDX" ]; then
    uci delete "firewall.@rule[${IDX}]" 2>/dev/null || true
    uci commit firewall
fi

echo "[INFO] Removing Unbound package..."
opkg remove unbound unbound-control 2>/dev/null || true

echo ""
echo "Valkyrie Sentry removed."
echo "DNS will fall back to the router's default resolver."
