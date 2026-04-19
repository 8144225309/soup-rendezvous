#!/usr/bin/env bash
# soup-rendezvous installer — builds the binary, installs the systemd
# template unit, and prepares the example config. Per-network state
# directories and nsecs are left for the operator to create (see below).
#
# Idempotent — safe to re-run on upgrades.

set -euo pipefail

# Ensure cargo is in PATH even when invoked by systemd/cron
export PATH="${HOME:-/root}/.cargo/bin:${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="/usr/local/bin/soup-rendezvous"
CONFIG_FILE="/etc/soup-rendezvous.toml"
TEMPLATE_UNIT="/etc/systemd/system/soup-rendezvous@.service"

if [ "$EUID" -ne 0 ]; then
  echo "must run as root (or with sudo)"
  exit 1
fi

echo "=== building release binary ==="
(cd "$REPO_ROOT" && cargo build --release)

echo "=== installing binary to $BINARY ==="
install -m 755 "$REPO_ROOT/target/release/soup-rendezvous" "$BINARY"

echo "=== installing systemd template unit to $TEMPLATE_UNIT ==="
install -m 644 "$REPO_ROOT/deploy/soup-rendezvous@.service" "$TEMPLATE_UNIT"

if [ ! -f "$CONFIG_FILE" ]; then
  echo "=== installing example config to $CONFIG_FILE ==="
  install -m 644 "$REPO_ROOT/deploy/soup-rendezvous.example.toml" "$CONFIG_FILE"
  echo "  EDIT $CONFIG_FILE before enabling any instance."
  echo "  Uncomment the networks you want to run, set the correct"
  echo "  lightning_dir / bitcoin_dir paths, and decide whether to"
  echo "  allow_peer_verification per network."
else
  echo "=== keeping existing $CONFIG_FILE (no overwrite) ==="
fi

echo "=== reloading systemd ==="
systemctl daemon-reload

echo
echo "=== install complete ==="
echo
echo "To light up a network (signet as example):"
echo
echo "  1. Create state dir + generate nsec:"
echo "       install -d -m 700 -o root -g root /var/lib/soup-rendezvous-signet"
echo "       $BINARY --key-file /var/lib/soup-rendezvous-signet/coordinator.nsec init"
echo
echo "  2. Ensure cln-signet and (optionally) bitcoind-signet are running."
echo
echo "  3. Verify the [networks.signet] section in $CONFIG_FILE points"
echo "     at the correct lightning_dir and bitcoin_dir."
echo
echo "  4. Enable the systemd instance:"
echo "       systemctl enable --now soup-rendezvous@signet.service"
echo
echo "  5. Publish the root thread (one-time):"
echo "       $BINARY --config $CONFIG_FILE --network signet publish-root \\"
echo "         \"<coordinator description>\""
echo
echo "  6. Back up the nsec off-VPS (encrypted) before accepting traffic."
echo
echo "Tail logs for an instance:  journalctl -u soup-rendezvous@<network> -f"
