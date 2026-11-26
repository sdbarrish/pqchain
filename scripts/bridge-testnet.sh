#!/usr/bin/env bash
# Two independent PQ-Chain networks (A and B, 3 validators each, separate
# genesis) bridged through their Playfair Chains: each runs an on-chain light
# client of the other. Tokens go A -> B (escrowed on A, minted as wrapped on B)
# and partly back (burned on B, released from escrow on A).
#
# Usage: scripts/bridge-testnet.sh [workdir]      (default: ./bridge-run)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$ROOT/bridge-run}"
BIN="$ROOT/target/release/pqchain"
PIDS=()
A=http://127.0.0.1:8100
B=http://127.0.0.1:8300

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✔\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✘ %s\033[0m\n' "$*"; exit 1; }
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
h()    { curl -sf "$1/status" | jget "d['$2']['height']"; }
w()    { local rpc=$1; shift; "$BIN" wallet --rpc "$rpc" "$@"; }
wait_h() { # rpc chain height
  for _ in $(seq 1 300); do [ "$(h "$1" "$2" 2>/dev/null || echo 0)" -ge "$3" ] && return 0; sleep 0.2; done
  fail "$1: $2 did not reach $3"
}
wait_until() { # description, command...
  local d=$1; shift
  for _ in $(seq 1 150); do "$@" >/dev/null 2>&1 && return 0; sleep 0.2; done
  fail "timed out waiting for: $d"
}
assets() { curl -sf "$1/balance/playfair/$2" | jget "d['assets']"; }

say "Build and create two networks"
(cd "$ROOT" && cargo build --release -q)
rm -rf "$WORK"
"$BIN" testnet-init --dir "$WORK/a" --validators 3 --full-nodes 0 --p2p-port 9100 --rpc-port 8100 >/dev/null
"$BIN" testnet-init --dir "$WORK/b" --validators 3 --full-nodes 0 --p2p-port 9300 --rpc-port 8300 >/dev/null
for net in a b; do
  for i in 0 1 2; do
    "$BIN" node --config "$WORK/$net/validator-$i/config.json" >>"$WORK/$net-$i.log" 2>&1 &
    PIDS+=($!)
  done
done
wait_until "network A up" curl -sf "$A/network"
wait_until "network B up" curl -sf "$B/network"
AID=$(curl -sf "$A/network" | jget "d['network_id']")
BID=$(curl -sf "$B/network" | jget "d['network_id']")
ok "network A ${AID:0:16}…  network B ${BID:0:16}…  (different genesis, different validators)"

say "Fund each faucet on its Playfair Chain"
for pair in "$A:a" "$B:b"; do
  rpc=${pair%:*}; net=${pair##*:}
  w "$rpc" export --key "$WORK/$net/faucet.key" --amount 50000 --from atbash --to playfair >/dev/null
  wait_h "$rpc" atbash 1
  w "$rpc" import --key "$WORK/$net/faucet.key" --chain playfair >/dev/null
  wait_h "$rpc" playfair 1
done
ok "both faucets hold Playfair funds"

say "Each network registers the other (approved by > 2/3 of its own validators)"
register() { # local-rpc local-dir remote-rpc name
  local k approvals=()
  k=$(curl -sf "$3/network" | jget "d['kerckhoffs_height']")
  for i in 0 1 2; do
    approvals+=(--approval "$(w "$1" bridge-approve --key "$2/validator-$i/node.key" --remote "$3" --name "$4" --k-height "$k")")
  done
  w "$1" bridge-register --key "$2/faucet.key" --remote "$3" --name "$4" --k-height "$k" "${approvals[@]}"
}
register "$A" "$WORK/a" "$B" network-b | sed 's/^/  A: /'
register "$B" "$WORK/b" "$A" network-a | sed 's/^/  B: /'
wait_h "$A" playfair 2
wait_h "$B" playfair 2
ok "A tracks B at Kerckhoffs #$(curl -sf "$A/status" | jget "d['counterparties'][0]['tracked_kerckhoffs_height']"); B tracks A"

say "B's validator set changes; A's light client follows"
# A delegation on B's Kerckhoffs Chain changes validator weights (and the set root).
w "$B" export --key "$WORK/b/faucet.key" --amount 3000 --from atbash --to kerckhoffs >/dev/null
wait_h "$B" atbash 2
w "$B" import --key "$WORK/b/faucet.key" --chain kerckhoffs >/dev/null
wait_h "$B" kerckhoffs 1
V0=$(w "$B" show --key "$WORK/b/validator-0/node.key")
w "$B" delegate --key "$WORK/b/faucet.key" --node "$V0" --amount 1000 >/dev/null
wait_h "$B" kerckhoffs 2
wait_until "B's Kerckhoffs #2 certified" curl -sf "$B/bridge/kheader/2"
w "$A" bridge-sync --remote "$B" | sed 's/^/  A: /'
wait_until "A synced to B's #2" sh -c "[ \"\$(curl -sf $A/status | python3 -c \"import json,sys; print(json.load(sys.stdin)['counterparties'][0]['tracked_kerckhoffs_height'])\")\" -ge 2 ]"
ok "A verified B's two Kerckhoffs headers against B's validators and adopted the new set"

say "A -> B: 1000 escrowed on A, minted as wrapped on B"
w "$A" new --out "$WORK/alice.key" >/dev/null
w "$B" new --out "$WORK/bob.key" >/dev/null
ALICE=$(w "$A" show --key "$WORK/alice.key")
BOB=$(w "$B" show --key "$WORK/bob.key")
P=$(h "$A" playfair)
w "$A" bridge-send --key "$WORK/a/faucet.key" --dest-network "$BID" --recipient "$BOB" --amount 1000 | sed 's/^/  A: /'
wait_h "$A" playfair $((P + 1))
wait_until "A's message certified" sh -c "curl -sf $A/bridge/outbox/$BID | grep -q proof"
P=$(h "$B" playfair)
w "$B" bridge-relay --remote "$A" | sed 's/^/  B: /'
wait_h "$B" playfair $((P + 1))
ok "bob on B: $(assets "$B" "$BOB")  (wrapped A tokens)"
ok "A escrow for B: $(curl -sf "$A/status" | jget "d['counterparties'][0]['escrowed']")"

say "Replay is refused"
w "$B" bridge-relay --remote "$A" | sed 's/^/  B: /'
ok "re-delivering the same message was rejected (already received)"

say "B -> A: bob sends 400 back (burned on B, released from escrow on A)"
P=$(h "$B" playfair)
w "$B" send --key "$WORK/b/faucet.key" --to "$BOB" --amount 10 --chain playfair >/dev/null   # fee money
wait_h "$B" playfair $((P + 1))
P=$(h "$B" playfair)
w "$B" bridge-send --key "$WORK/bob.key" --dest-network "$AID" --recipient "$ALICE" --amount 400 --wrapped-origin "$AID" | sed 's/^/  B: /'
wait_h "$B" playfair $((P + 1))
wait_until "B's message certified" sh -c "curl -sf $B/bridge/outbox/$AID | grep -q proof"
w "$A" bridge-sync --remote "$B" | sed 's/^/  A: /'
P=$(h "$A" playfair)
w "$A" bridge-relay --remote "$B" | sed 's/^/  A: /'
wait_h "$A" playfair $((P + 1))
[ "$(curl -sf "$A/balance/playfair/$ALICE" | jget "d['assets'].get('native', 0)")" = 400 ] || fail "alice should hold 400 native on A"
ok "alice on A: $(assets "$A" "$ALICE")  (native, released from escrow)"
ok "bob on B:   $(assets "$B" "$BOB")"
ESC=$(curl -sf "$A/status" | jget "d['counterparties'][0]['escrowed']")
[ "$ESC" = 600 ] || fail "A's escrow for B should be 600, got $ESC"
ok "A escrow for B: $ESC  (1000 sent - 400 returned)"

say "Each network agrees internally"
for rpc in "$A" "$B"; do
  base=${rpc##*:}; base=$((base))
  roots=$(for i in 0 1 2; do curl -sf "http://127.0.0.1:$((base + i))/status" | jget "d['state_root']"; done | sort -u | wc -l)
  [ "$roots" = 1 ] || fail "nodes of $rpc disagree"
done
ok "all 3 nodes of A and all 3 nodes of B hold identical state"
