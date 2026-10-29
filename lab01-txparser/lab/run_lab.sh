#!/bin/bash
set -e

LAB="$(cd "$1" && pwd)"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$HERE/results"
mkdir -p "$OUT"

dc() { docker compose -f "$LAB/docker-compose.yml" "$@"; }
cli() { dc exec -T bitcoind bitcoin-cli "$@"; }
w() { cli -rpcwallet=lab01 "$@"; }
get() { python3 -c "import json,sys; print(eval(sys.argv[1], {'d': json.load(sys.stdin)}))" "$1"; }

dc down -v
dc up -d
until cli getblockchaininfo > /dev/null 2>&1; do sleep 2; done

cli createwallet lab01
ADDR=$(w getnewaddress)
cli generatetoaddress 101 "$ADDR" > /dev/null
w getbalance > "$OUT/getbalance.txt"

echo "--- Part A"
w listunspent > "$OUT/A_listunspent.json"
w getbalances > "$OUT/A_getbalances.json"
cli gettxoutsetinfo > "$OUT/A_gettxoutsetinfo.json"

echo "--- Part B"
w listunspent 100 > "$OUT/B_listunspent100.json"
TXID_IN=$(get 'd[0]["txid"]' < "$OUT/B_listunspent100.json")
VOUT_IN=$(get 'd[0]["vout"]' < "$OUT/B_listunspent100.json")
DEST=$(w getnewaddress destination)
CHANGE=$(w getnewaddress change)
RAW=$(printf '%s\n%s\n' "[{\"txid\":\"$TXID_IN\",\"vout\":$VOUT_IN}]" "[{\"$DEST\":10.0},{\"$CHANGE\":39.9999}]" | w -stdin createrawtransaction)
echo "$RAW" | w -stdin signrawtransactionwithwallet > "$OUT/B_signed.json"
HEX=$(get 'd["hex"]' < "$OUT/B_signed.json")
echo "$HEX" > "$OUT/B_signed.hex"
echo "$HEX" | cli -stdin decoderawtransaction > "$OUT/B_decoderawtransaction.json"
TXID=$(echo "$HEX" | w -stdin sendrawtransaction)
echo "$TXID" > "$OUT/B_txid.txt"
w getrawmempool > "$OUT/B_mempool_before.json"
w -generate 1 > /dev/null
w getrawmempool > "$OUT/B_mempool_after.json"
w gettransaction "$TXID" > "$OUT/B_gettransaction.json"
w getbalance > "$OUT/B_getbalance.txt"

echo "--- Part C"
cd "$HERE"
uv sync -q
uv run python -m txparser "$HEX" > "$OUT/C_parser.txt"
uv run pytest -v > "$OUT/C_tests.txt" 2>&1 || true

echo "--- Part D"
w listunspent 100 > "$OUT/D_listunspent100.json"
TXID_IN=$(get 'd[0]["txid"]' < "$OUT/D_listunspent100.json")
VOUT_IN=$(get 'd[0]["vout"]' < "$OUT/D_listunspent100.json")
DEST=$(w getnewaddress destination2)
RAW=$(printf '%s\n%s\n' "[{\"txid\":\"$TXID_IN\",\"vout\":$VOUT_IN}]" "[{\"$DEST\":10.0}]" | w -stdin createrawtransaction)
HEXD=$(echo "$RAW" | w -stdin signrawtransactionwithwallet | get 'd["hex"]')
echo "$HEXD" > "$OUT/D_signed.hex"
(echo "$HEXD" | w -stdin sendrawtransaction 2>&1 || true) > "$OUT/D_refused.txt"
printf '%s\n0\n' "$HEXD" | w -stdin sendrawtransaction > "$OUT/D_txid.txt"
BLOCK=$(w -generate 1 | get 'd["blocks"][0]')
cli getblock "$BLOCK" 2 > "$OUT/D_getblock.json"

echo "done, results are in $OUT"
