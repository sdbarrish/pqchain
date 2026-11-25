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

zone_height() { # port zone-id
  rpc "$1" /status | jget "[z['height'] for z in d['zones'] if z['id']==$2][0]"
}

wait_zone() { # zone-id height ports...
  local z=$1 h=$2; shift 2
  for p in "$@"; do
    for _ in $(seq 1 150); do
      [ "$(zone_height "$p" "$z" 2>/dev/null || echo 0)" -ge "$h" ] && continue 2
      sleep 0.2
    done
    fail "port $p: zone $z did not reach height $h"
  done
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

say "Validator exit signed with an SLH-DSA cold key"
V3=$(wallet show --key "$WORK/validator-3/node.key")
python3 -c "import json;print('  withdrawal key algorithm:', json.load(open('$WORK/validator-3/withdrawal.key'))['algorithm'])"
wallet exit --withdrawal-key "$WORK/validator-3/withdrawal.key" --node "$V3" | sed 's/^/  /'
wait_all kerckhoffs 5 "${ALL[@]}"
EXIT_AT=$(rpc 8104 /validators | jget "[v['exit_at'] for v in d['validators'] if v['node_id']=='$V3'][0]")
[ "$EXIT_AT" != "None" ] || fail "validator-3 should be unbonding"
ok "validator-3 is unbonding (stake released at Kerckhoffs #$EXIT_AT); it no longer votes or proposes"
wallet send --key "$WORK/alice.key" --to "$BOB" --amount 100 >/dev/null
wait_all atbash 9 "${ALL[@]}"
ok "network keeps finalizing without validator-3"

say "Zones and relay messages"
M0=$(wallet show --key "$WORK/validator-0/node.key")
M1=$(wallet show --key "$WORK/validator-1/node.key")
M2=$(wallet show --key "$WORK/validator-2/node.key")
wallet create-zone --key "$WORK/faucet.key" --name games --members "$M0,$M1,$M2" | sed 's/^/  /'
wait_all kerckhoffs 6 "${ALL[@]}"
ok "zone-0 'games' registered; members: validator-0, validator-1, validator-2"
BOB_A0=$(native 8104 atbash "$BOB")
wallet export --key "$WORK/alice.key" --amount 4000 --from atbash --to zone-0 | sed 's/^/  /'
wait_all atbash 10 "${ALL[@]}"
INBOX=$(rpc 8104 "/inbox/zone-0/$ALICE" | jget "[(m['amount'], m['proof_bytes']) for m in d]")
ok "relay message waiting in alice's zone-0 inbox (amount, proof size): $INBOX"
wallet relay-import --key "$WORK/alice.key" --chain zone-0 | sed 's/^/  /'
wait_zone 0 1 "${ALL[@]}"
[ "$(native 8104 zone-0 "$ALICE")" = 3999 ] || fail "alice should hold 3999 on zone-0"
ok "alice claimed 3999 on zone-0 (proof checked against primary validators' certificate)"
wallet send --key "$WORK/alice.key" --to "$BOB" --amount 1500 --chain zone-0 | sed 's/^/  /'
wait_zone 0 2 "${ALL[@]}"
wallet export --key "$WORK/bob.key" --amount 1000 --from zone-0 --to atbash | sed 's/^/  /'
wait_zone 0 3 "${ALL[@]}"
wallet relay-import --key "$WORK/bob.key" --chain atbash | sed 's/^/  /'
wait_all atbash 11 "${ALL[@]}"
[ "$(native 8104 atbash "$BOB")" = $((BOB_A0 + 999)) ] || fail "bob should have received 999 on atbash"
ok "bob paid on zone-0, moved 1000 back to atbash (proof checked against zone members' certificate)"
if grep -h "proposing Zone 0" "$WORK"/validator-3.log "$WORK"/validator-4.log "$WORK"/full-0.log 2>/dev/null | grep -q .; then
  fail "a non-member proposed a zone block"
fi
ok "only zone members proposed zone-0 blocks: $(grep -h 'proposing Zone 0' "$WORK"/*.log | sed 's/^\[\([^]]*\)\].*/\1/' | sort | uniq -c | tr -s ' ' | paste -sd, -)"
FOLLOW=$(grep -h "accepted Zone 0" "$WORK"/full-0.log | head -1 | sed 's/.*via //; s/;.*//')
ok "non-members follow zone-0 by finality certificate (full-0: '$FOLLOW')"

say "Final agreement check"
sleep 1
ROOTS=()
for p in "${ALL[@]}"; do
  s=$(rpc "$p" /status)
  printf '  %-12s kerckhoffs #%s  atbash #%s  zone-0 #%s  state %s\n' "$(echo "$s" | jget "d['node']")" \
    "$(echo "$s" | jget "d['kerckhoffs']['height']")" "$(echo "$s" | jget "d['atbash']['height']")" \
    "$(echo "$s" | jget "d['zones'][0]['height'] if d['zones'] else '-'")" "$(echo "$s" | jget "d['state_root'][:16]")"
  ROOTS+=("$(echo "$s" | jget "d['state_root']")")
done
[ "$(printf '%s\n' "${ROOTS[@]}" | sort -u | wc -l)" = 1 ] || fail "state roots differ"
ok "all ${#ALL[@]} nodes hold identical state"
CERT=$(rpc 8104 /block/atbash/1 | jget "d['certificate']")
ok "finality certificate for Atbash #1: $CERT"
echo
echo "Logs: $WORK/*.log"
