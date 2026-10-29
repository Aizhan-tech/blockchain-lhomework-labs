import hashlib

OPCODES = {
    0x00: "OP_0", 0x4F: "OP_1NEGATE", 0x61: "OP_NOP", 0x63: "OP_IF", 0x64: "OP_NOTIF",
    0x67: "OP_ELSE", 0x68: "OP_ENDIF", 0x69: "OP_VERIFY", 0x6A: "OP_RETURN",
    0x75: "OP_DROP", 0x76: "OP_DUP", 0x7C: "OP_SWAP", 0x82: "OP_SIZE",
    0x87: "OP_EQUAL", 0x88: "OP_EQUALVERIFY", 0x93: "OP_ADD", 0x94: "OP_SUB",
    0xA6: "OP_RIPEMD160", 0xA8: "OP_SHA256", 0xA9: "OP_HASH160", 0xAA: "OP_HASH256",
    0xAC: "OP_CHECKSIG", 0xAD: "OP_CHECKSIGVERIFY", 0xAE: "OP_CHECKMULTISIG",
    0xAF: "OP_CHECKMULTISIGVERIFY", 0xB1: "OP_CHECKLOCKTIMEVERIFY",
    0xB2: "OP_CHECKSEQUENCEVERIFY", 0xBA: "OP_CHECKSIGADD",
}
for n in range(1, 17):
    OPCODES[0x50 + n] = f"OP_{n}"


def disassemble(script):
    result = []
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if 1 <= op <= 75:
            size = op
        elif op == 0x4C:
            size = script[i]
            i += 1
        elif op == 0x4D:
            size = int.from_bytes(script[i:i + 2], "little")
            i += 2
        elif op == 0x4E:
            size = int.from_bytes(script[i:i + 4], "little")
            i += 4
        else:
            result.append(OPCODES.get(op, f"OP_UNKNOWN_{op:02x}"))
            continue
        result.append("<" + script[i:i + size].hex() + ">")
        i += size
    return " ".join(result)


def classify(s):
    if len(s) == 25 and s[0] == 0x76 and s[1] == 0xA9 and s[2] == 20 and s[23] == 0x88 and s[24] == 0xAC:
        return "p2pkh"
    if len(s) == 23 and s[0] == 0xA9 and s[1] == 20 and s[22] == 0x87:
        return "p2sh"
    if len(s) == 22 and s[0] == 0x00 and s[1] == 20:
        return "p2wpkh"
    if len(s) == 34 and s[0] == 0x00 and s[1] == 32:
        return "p2wsh"
    if len(s) == 34 and s[0] == 0x51 and s[1] == 32:
        return "p2tr"
    if (len(s) == 67 and s[0] == 65 or len(s) == 35 and s[0] == 33) and s[-1] == 0xAC:
        return "p2pk"
    if len(s) > 0 and s[0] == 0x6A:
        return "nulldata"
    return "nonstandard"


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check(version, payload):
    data = bytes([version]) + payload
    data += hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = B58[r] + s
    zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * zeros + s


CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def to_5bit(data):
    acc = 0
    bits = 0
    out = []
    for b in data:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    return out


def bech32(hrp, version, program):
    data = [version] + to_5bit(program)
    const = 1 if version == 0 else 0x2BC830A3
    hrp_exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = polymod(hrp_exp + data + [0] * 6) ^ const
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


NETWORKS = {
    "mainnet": ("bc", 0x00, 0x05),
    "testnet": ("tb", 0x6F, 0xC4),
    "regtest": ("bcrt", 0x6F, 0xC4),
}


def address(script, network="regtest"):
    hrp, pkh, sh = NETWORKS[network]
    t = classify(script)
    if t == "p2pkh":
        return base58check(pkh, script[3:23])
    if t == "p2sh":
        return base58check(sh, script[2:22])
    if t in ("p2wpkh", "p2wsh"):
        return bech32(hrp, 0, script[2:])
    if t == "p2tr":
        return bech32(hrp, 1, script[2:])
    return None
