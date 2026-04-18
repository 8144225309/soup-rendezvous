#!/usr/bin/env bash
# soup-rendezvous installer.
# Idempotent — safe to re-run on upgrades.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="/usr/local/bin/soup-rendezvous"
STATE_DIR="/var/lib/soup-rendezvous"
KEY_FILE="$STATE_DIR/coordinator.nsec"
SERVICE_FILE="/etc/systemd/system/soup-rendezvous.service"

if [ "$EUID" -ne 0 ]; then
  echo "must run as root (or with sudo)"
  exit 1
fi

echo "=== building release binary ==="
(cd "$REPO_ROOT" && cargo build --release)

echo "=== installing binary to $BINARY ==="
install -m 755 "$REPO_ROOT/target/release/soup-rendezvous" "$BINARY"

echo "=== preparing state dir $STATE_DIR ==="
install -d -m 700 -o root -g root "$STATE_DIR"

if [ ! -f "$KEY_FILE" ]; then
  echo "  FATAL: $KEY_FILE not found"
  echo "  copy your coordinator nsec there first, then re-run:"
  echo "    cp /path/to/coordinator.nsec $KEY_FILE"
  echo "    chmod 600 $KEY_FILE"
  echo "    chown root:root $KEY_FILE"
  exit 1
fi

# Enforce permissions even if the file already exists
chmod 600 "$KEY_FILE"
chown root:root "$KEY_FILE"

echo "=== installing systemd unit ==="
install -m 644 "$REPO_ROOT/deploy/soup-rendezvous.service" "$SERVICE_FILE"

echo "=== reloading systemd ==="
systemctl daemon-reload

echo "=== enabling + starting service ==="
systemctl enable soup-rendezvous.service
systemctl restart soup-rendezvous.service

sleep 2

echo "=== status ==="
systemctl status --no-pager soup-rendezvous.service || true

echo
echo "=== recent logs ==="
journalctl -u soup-rendezvous.service --no-pager -n 20

echo
echo "install complete. follow logs with:"
echo "  journalctl -u soup-rendezvous.service -f"
