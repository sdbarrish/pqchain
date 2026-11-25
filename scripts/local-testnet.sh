#!/usr/bin/env bash
# End-to-end test of a real multi-process PQ-Chain testnet on localhost.
#
#   4 validators + 1 full node, each a separate process with its own disk,
#   talking over ML-KEM-768 + X25519 encrypted, ML-DSA-65 authenticated links.
#
# Scenario: payments, cross-chain export/import, asset creation, a new
# validator staking and joining, delegation, a node crash + restart that
# recovers from disk and syncs, and a final check that every node holds the
# identical state root.
#
# Usage: scripts/local-testnet.sh [workdir]      (default: ./testnet-run)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$ROOT/testnet-run}"
BIN="$ROOT/target/release/pqchain"
P2P=9100
RPC=8100
PIDS=()

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✔\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✘ %s\033[0m\n' "$*"; exit 1; }

cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

rpc()    { curl -sf "http://127.0.0.1:$1$2"; }
jget()   { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
height() { rpc "$1" /status | jget "d['$2']['height']"; }
wallet() { "$BIN" wallet --rpc "http://127.0.0.1:$RPC" "$@"; }

start_node() { # name
  "$BIN" node --config "$WORK/$1/config.json" >>"$WORK/$1.log" 2>&1 &
  PIDS+=($!)
  eval "PID_${1//-/_}=$!"
}

wait_height() { # port chain height
  for _ in $(seq 1 150); do
    [ "$(height "$1" "$2" 2>/dev/null || echo 0)" -ge "$3" ] && return 0
    sleep 0.2
  done
  fail "port $1: $2 did not reach height $3"
}

wait_all() { # chain height ports...
  local c=$1 h=$2; shift 2
  for p in "$@"; do wait_height "$p" "$c" "$h"; done
}

native() { # port chain address
  rpc "$1" "/balance/$2/$3" | jget "d['assets'].get('native',0)"
}

say "Build"
(cd "$ROOT" && cargo build --release -q)
ok "built $BIN"

say "Create testnet (4 validators + 1 full node)"
rm -rf "$WORK"
"$BIN" testnet-init --dir "$WORK" --p2p-port $P2P --rpc-port $RPC | sed 's/^/  /'
ALL=(8100 8101 8102 8103 8104)

say "Start nodes"
for n in validator-0 validator-1 validator-2 validator-3 full-0; do start_node "$n"; done
sleep 2
for p in "${ALL[@]}"; do
  peers=$(rpc "$p" /status | jget "len(d['peers'])" 2>/dev/null || echo 0)
  [ "$peers" -ge 4 ] || { sleep 2; peers=$(rpc "$p" /status | jget "len(d['peers'])"); }
  [ "$peers" -ge 4 ] || fail "node on $p has only $peers peers"
done
ok "all 5 nodes connected (hybrid post-quantum handshake)"

say "Payments on the Atbash Chain"
wallet new --out "$WORK/alice.key" >/dev/null
wallet new --out "$WORK/bob.key" >/dev/null
ALICE=$(wallet show --key "$WORK/alice.key")
BOB=$(wallet show --key "$WORK/bob.key")
wallet send --key "$WORK/faucet.key" --to "$ALICE" --amount 100000 | sed 's/^/  /'
wait_all atbash 1 "${ALL[@]}"
wallet send --key "$WORK/alice.key" --to "$BOB" --amount 2500 | sed 's/^/  /'
wait_all atbash 2 "${ALL[@]}"
[ "$(native 8104 atbash "$BOB")" = 2500 ] || fail "bob should have 2500"
ok "faucet → alice 100000, alice → bob 2500 (confirmed on the full node)"

say "Create an asset"
wallet create-asset --key "$WORK/alice.key" --name QUBIT --supply 21000000 | sed 's/^/  /'
wait_all atbash 3 "${ALL[@]}"
ok "QUBIT asset minted: $(rpc 8104 "/balance/atbash/$ALICE" | jget "d['assets']")"

say "Cross-chain: Atbash → Kerckhoffs"
wallet export --key "$WORK/alice.key" --amount 20000 --from atbash --to kerckhoffs | sed 's/^/  /'
wait_all atbash 4 "${ALL[@]}"
wallet import --key "$WORK/alice.key" --chain kerckhoffs | sed 's/^/  /'
wait_all kerckhoffs 1 "${ALL[@]}"
ok "alice on Kerckhoffs: $(native 8104 kerckhoffs "$ALICE") native"

say "A new validator stakes and joins"
mkdir -p "$WORK/validator-4"
"$BIN" wallet new --out "$WORK/validator-4/node.key" >/dev/null
cat >"$WORK/validator-4/config.json" <<EOF
{ "name": "validator-4", "key": "node.key", "genesis": "../genesis.json", "data_dir": "data",
  "listen": "127.0.0.1:$((P2P + 5))", "rpc": "127.0.0.1:$((RPC + 5))",
  "peers": ["127.0.0.1:$P2P", "127.0.0.1:$((P2P + 1))", "127.0.0.1:$((P2P + 2))", "127.0.0.1:$((P2P + 3))", "127.0.0.1:$((P2P + 4))"] }
EOF
wallet stake --key "$WORK/alice.key" --node-key "$WORK/validator-4/node.key" --amount 5000 | sed 's/^/  /'
wait_all kerckhoffs 2 "${ALL[@]}"
start_node validator-4
ALL+=(8105)
wait_all kerckhoffs 2 8105
wait_all atbash 4 8105
ok "validator-4 registered (stake 5000), started, and synced from certified blocks"

V4=$(wallet show --key "$WORK/validator-4/node.key")
wallet export --key "$WORK/faucet.key" --amount 3000 --from atbash --to kerckhoffs | sed 's/^/  /'
wait_all atbash 5 "${ALL[@]}"
wallet import --key "$WORK/faucet.key" --chain kerckhoffs | sed 's/^/  /'
wait_all kerckhoffs 3 "${ALL[@]}"
wallet delegate --key "$WORK/faucet.key" --node "$V4" --amount 1000 | sed 's/^/  /'
wait_all kerckhoffs 4 "${ALL[@]}"
ok "faucet delegated 1000 to validator-4: $(rpc 8104 /validators | jget "[v['weight'] for v in d['validators'] if v['node_id']=='$V4']")"

say "Crash a validator, keep going, restart it"
kill "$PID_validator_2"
ok "validator-2 killed"
LIVE=(8100 8101 8103 8104 8105)
for i in 1 2 3; do
  wallet send --key "$WORK/alice.key" --to "$BOB" --amount 100 >/dev/null
  wait_all atbash $((5 + i)) "${LIVE[@]}"
done
ok "3 more blocks accepted while validator-2 was down"
start_node validator-2
wait_all atbash 8 8102
grep -q "replayed" "$WORK/validator-2.log" || fail "validator-2 did not replay its disk log"
ok "validator-2 restarted: $(grep replayed "$WORK/validator-2.log" | tail -1 | sed 's/^\[[^]]*\] //')"
ok "validator-2 synced the blocks it missed"

say "Final agreement check"
sleep 1
ROOTS=()
for p in "${ALL[@]}"; do
  s=$(rpc "$p" /status)
  printf '  %-12s kerckhoffs #%s  atbash #%s  state %s\n' "$(echo "$s" | jget "d['node']")" \
    "$(echo "$s" | jget "d['kerckhoffs']['height']")" "$(echo "$s" | jget "d['atbash']['height']")" \
    "$(echo "$s" | jget "d['state_root'][:16]")"
  ROOTS+=("$(echo "$s" | jget "d['state_root']")")
done
[ "$(printf '%s\n' "${ROOTS[@]}" | sort -u | wc -l)" = 1 ] || fail "state roots differ"
ok "all ${#ALL[@]} nodes hold identical state"
CERT=$(rpc 8104 /block/atbash/1 | jget "d['certificate']")
ok "finality certificate for Atbash #1: $CERT"
echo
echo "Logs: $WORK/*.log"
