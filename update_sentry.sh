#!/bin/sh
# Valkyrie Sentry — update script for OpenWrt

set -e

echo "[INFO] Updating blocklist and scanner cache..."
cd /opt/valkyrie && python3 -m valkyrie --update

echo "[INFO] Restarting Valkyrie service..."
/etc/init.d/valkyrie restart

echo "Valkyrie updated and restarted."
