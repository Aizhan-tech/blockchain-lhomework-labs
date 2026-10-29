import sys

from .parser import ParseError, parse_tx
from .script import address, classify, disassemble


def main():
    raw = sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read()
    try:
        tx = parse_tx(raw)
    except ParseError as e:
        print("error:", e)
        sys.exit(1)

    print("txid:     ", tx.txid())
    print("wtxid:    ", tx.wtxid())
    print("segwit:   ", tx.segwit)
    print("version:  ", tx.version)
    print("locktime: ", tx.locktime)
    print("size:     ", tx.size())
    print("stripped: ", tx.stripped_size())
    print("weight:   ", tx.weight(), f"(3 * {tx.stripped_size()} + {tx.size()})")
    print("vsize:    ", tx.vsize())
    print()

    for n, i in enumerate(tx.inputs):
        print(f"input {n} (offset {i['offset']})")
        print("  prev txid:", i["txid"])
        print("  vout:     ", i["vout"])
        print("  scriptSig:", i["scriptSig"].hex())
        print("  sequence: ", hex(i["sequence"]))
        if tx.segwit:
            print("  witness:  ", len(i["witness"]), "items")
            for w in i["witness"]:
                print(f"    {len(w)} bytes: {w.hex()}")
    print()

    for n, o in enumerate(tx.outputs):
        print(f"output {n} (offset {o['offset']})")
        print("  value:  ", o["value"], "sat =", o["value"] / 100_000_000, "BTC")
        print("  type:   ", classify(o["script"]))
        print("  asm:    ", disassemble(o["script"]))
        print("  address:", address(o["script"]))
    print()
    print("fee: cannot be computed, the transaction does not contain the input values")


main()
