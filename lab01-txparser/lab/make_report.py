import html
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "results"
sys.path.insert(0, str(ROOT))
from txparser.parser import parse_tx

name = sys.argv[1] if len(sys.argv) > 1 else "Name"
repo = sys.argv[2] if len(sys.argv) > 2 else "https://github.com/..."


def text(f):
    p = RES / f
    return p.read_text().strip() if p.exists() else "(missing)"


def data(f):
    try:
        return json.loads(text(f))
    except json.JSONDecodeError:
        return {}


def box(f):
    return "<pre>" + html.escape(text(f)) + "</pre>"


txo = data("A_gettxoutsetinfo.json")
dec = data("B_decoderawtransaction.json")
gtx = data("B_gettransaction.json")
blk = data("D_getblock.json")
tx = parse_tx(text("B_signed.hex"))

rows = [
    ("txid", tx.txid(), dec.get("txid")),
    ("wtxid / hash", tx.wtxid(), dec.get("hash")),
    ("version", tx.version, dec.get("version")),
    ("locktime", tx.locktime, dec.get("locktime")),
    ("size", tx.size(), dec.get("size")),
    ("vsize", tx.vsize(), dec.get("vsize")),
    ("weight", tx.weight(), dec.get("weight")),
]
table = "".join(f"<tr><td>{a}</td><td>{b}</td><td>{c}</td></tr>" for a, b, c in rows)

coinbase = blk.get("tx", [{}])[0].get("vout", [])
coinbase_values = [v.get("value") for v in coinbase]

page = f"""<!doctype html><html><head><meta charset="utf-8"><title>Lab 01</title>
<style>body{{font-family:sans-serif;max-width:850px;margin:30px auto;line-height:1.4}}
pre{{background:#eee;padding:8px;font-size:11px;white-space:pre-wrap;word-break:break-all}}
table{{border-collapse:collapse;font-size:12px}}td,th{{border:1px solid #999;padding:4px}}</style></head><body>

<h1>Lab 01 - Bitcoin Core in Regtest</h1>
<p>{html.escape(name)}<br>Repository: {html.escape(repo)}</p>

<h2>1. Part A - UTXO state</h2>
<p>listunspent after mining 101 blocks:</p>{box("A_listunspent.json")}
<p>getbalances:</p>{box("A_getbalances.json")}
<p>gettxoutsetinfo:</p>{box("A_gettxoutsetinfo.json")}
<p>Only 1 of the 101 coinbase outputs can be spent. A coinbase output needs 100 more blocks on top
of it before it can be spent (coinbase maturity). If a block gets orphaned in a reorg its reward
disappears, so without this rule coins that never existed could already be spent. After 101 blocks
only the reward of block 1 has 100+ confirmations, the other 100 rewards (5000 BTC) are immature.</p>
<p>The node shows txouts = {txo.get("txouts")} and total_amount = {txo.get("total_amount")} because it counts
every unspent output, no matter who owns it or if it is mature. The wallet only lists what it can spend
now. The OP_RETURN witness commitment output of each coinbase is unspendable so it is not in the UTXO set.
The balance is not stored anywhere, the wallet just adds up its UTXOs.</p>

<h2>2. Part B - raw transaction</h2>
<p>Input: 50 BTC. Send 10 BTC, fee 0.0001 BTC.<br>
change = 50 - 10 - 0.0001 = 39.9999 BTC</p>
<p>Signed hex:</p>{box("B_signed.hex")}
<p>decoderawtransaction:</p>{box("B_decoderawtransaction.json")}
<p>txid from sendrawtransaction:</p>{box("B_txid.txt")}
<p>Mempool before mining:</p>{box("B_mempool_before.json")}
<p>Mempool after mining:</p>{box("B_mempool_after.json")}
<p>gettransaction:</p>{box("B_gettransaction.json")}
<p>The node reports fee = {gtx.get("fee")} BTC. This is the same as my calculation (0.0001 BTC = 10000 sat).
It is negative because the wallet shows it as money I paid. Fee rate = 10000 / {dec.get("vsize")} vB
= {10000 / dec.get("vsize", 1):.1f} sat/vB.</p>
<p>Balance after: {text("B_getbalance.txt")} BTC. Both outputs are mine and block 102 made the reward of
block 2 mature. Only the fee left, and it went into the coinbase of block 102 which I also mined.</p>

<h2>3. Part C - my parser</h2>
{box("C_parser.txt")}
<table><tr><th>field</th><th>my parser</th><th>decoderawtransaction</th></tr>{table}</table>
<p>Differences: the node calls the second hash "hash", my parser calls it wtxid. txid is the hash of the
transaction without witness data, wtxid includes the witness, so for SegWit they are different.
The node shows values in BTC, the raw transaction stores satoshis. Txids are stored reversed
(little-endian) in the bytes and shown big-endian. The parser cannot print the fee because the
transaction does not contain the values of the inputs.</p>
<p>Tests:</p><pre>{html.escape(text("C_tests.txt")[-1500:])}</pre>

<h2>4. Part D - no change output</h2>
<p>First sendrawtransaction:</p>{box("D_refused.txt")}
<p>This error is not a consensus rule, it is a safety limit in the RPC (maxfeerate). With 0 as the
second argument it was accepted:</p>{box("D_txid.txt")}
<p>Coinbase of the next block has outputs {coinbase_values}: 50 BTC reward + 40 BTC fee = 90 BTC,
and 0 for the witness commitment.</p>
<p>The 40 BTC went to the miner of the block. Here I mined it with -generate so it came back to my wallet
(immature). On mainnet a random miner would get it. The transaction is valid because consensus only checks
that sum(inputs) &gt;= sum(outputs) (50 &gt;= 10) and that the coinbase is not more than reward + fees
(90 &lt;= 50 + 40). There is no limit on how big the fee can be.</p>
<p>In Ethereum this cannot happen because it uses accounts. The state transition is
balance[sender] -= value + gasUsed * gasPrice and balance[recipient] += value. The rest just stays
in the sender's account, there is no output that must be spent fully, so there is no change to forget.
The fee is limited by gasLimit * maxFeePerGas which the sender signs.</p>

<h2>5. Why is there no fee field?</h2>
<p>Every input points to an old output that already has a fixed value, and every output has its value.
So the fee is already known: fee = sum(inputs) - sum(outputs). A fee field would be redundant and it
could be different from the real difference, then another rule would be needed.</p>
<p>What it gives: checking a transaction is just one comparison (inputs &gt;= outputs). The miner gets
reward + all the leftovers, no extra accounting. The sender chooses the fee himself and miners pick
transactions by sat/vB, so there is a fee market without a fixed price. Transactions are also a bit smaller.</p>
<p>What it costs: if you forget the change output everything left becomes the fee (Part D, 40 BTC).
Also you cannot see the fee from the transaction alone, my parser cannot print it without looking up
the inputs. That is why wallets and the RPC have protections like maxfeerate.</p>
</body></html>"""

(ROOT / "report.html").write_text(page)
print("report.html created")
