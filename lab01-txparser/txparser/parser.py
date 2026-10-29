import hashlib


class ParseError(ValueError):
    pass


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def read_varint(data, pos=0):
    if pos >= len(data):
        raise ParseError("truncated varint")
    first = data[pos]
    if first < 0xFD:
        return first, pos + 1
    size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    if pos + 1 + size > len(data):
        raise ParseError("truncated varint")
    return int.from_bytes(data[pos + 1:pos + 1 + size], "little"), pos + 1 + size


def write_varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read(self, n):
        if self.pos + n > len(self.data):
            raise ParseError(f"truncated at offset {self.pos}")
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def int(self, n):
        return int.from_bytes(self.read(n), "little")

    def varint(self):
        n, self.pos = read_varint(self.data, self.pos)
        return n

    def bytes(self):
        return self.read(self.varint())


class Tx:
    def __init__(self):
        self.version = 0
        self.segwit = False
        self.inputs = []
        self.outputs = []
        self.locktime = 0
        self.raw = b""

    def serialize(self, witness=True):
        witness = witness and self.segwit
        b = self.version.to_bytes(4, "little")
        if witness:
            b += b"\x00\x01"
        b += write_varint(len(self.inputs))
        for i in self.inputs:
            b += bytes.fromhex(i["txid"])[::-1]
            b += i["vout"].to_bytes(4, "little")
            b += write_varint(len(i["scriptSig"])) + i["scriptSig"]
            b += i["sequence"].to_bytes(4, "little")
        b += write_varint(len(self.outputs))
        for o in self.outputs:
            b += o["value"].to_bytes(8, "little")
            b += write_varint(len(o["script"])) + o["script"]
        if witness:
            for i in self.inputs:
                b += write_varint(len(i["witness"]))
                for item in i["witness"]:
                    b += write_varint(len(item)) + item
        b += self.locktime.to_bytes(4, "little")
        return b

    def txid(self):
        return sha256d(self.serialize(witness=False))[::-1].hex()

    def wtxid(self):
        return sha256d(self.serialize())[::-1].hex()

    def size(self):
        return len(self.raw)

    def stripped_size(self):
        return len(self.serialize(witness=False))

    def weight(self):
        return 3 * self.stripped_size() + self.size()

    def vsize(self):
        return (self.weight() + 3) // 4


def parse_tx(data):
    if isinstance(data, str):
        try:
            data = bytes.fromhex(data.strip())
        except ValueError:
            raise ParseError("not hex")
    if not data:
        raise ParseError("empty")

    r = Reader(data)
    tx = Tx()
    tx.version = r.int(4)

    if data[4:6] == b"\x00\x01":
        tx.segwit = True
        r.pos += 2

    for _ in range(r.varint()):
        offset = r.pos
        txid = r.read(32)[::-1].hex()
        vout = r.int(4)
        script_sig = r.bytes()
        sequence = r.int(4)
        tx.inputs.append({"offset": offset, "txid": txid, "vout": vout,
                          "scriptSig": script_sig, "sequence": sequence, "witness": []})

    for _ in range(r.varint()):
        offset = r.pos
        value = r.int(8)
        script = r.bytes()
        tx.outputs.append({"offset": offset, "value": value, "script": script})

    if tx.segwit:
        for i in tx.inputs:
            i["witness"] = [r.bytes() for _ in range(r.varint())]

    tx.locktime = r.int(4)
    if r.pos != len(data):
        raise ParseError("extra bytes at the end")

    tx.raw = data
    return tx
