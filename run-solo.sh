#!/bin/sh
# Convenience launcher for ergo-solo. Edit NODE_URL / NETWORK for your setup.
#
# Then point your GPU miner at this host on port 3055, e.g.:
#   rigel -a autolykos2 -o stratum+tcp://127.0.0.1:3055 -u rig1
set -e

NODE_URL="${NODE_URL:-http://127.0.0.1:9052}"
NETWORK="${NETWORK:-mainnet}"     # or: testnet
BIND="${BIND:-0.0.0.0:3055}"

BIN="$(dirname "$0")/target/release/ergo-solo"
[ -x "$BIN" ] || BIN="$(dirname "$0")/target/debug/ergo-solo"
[ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 1; }

exec "$BIN" --node-url "$NODE_URL" --network "$NETWORK" --bind "$BIND" "$@"
