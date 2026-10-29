import pytest

from txparser.parser import ParseError, parse_tx, read_varint, write_varint
from txparser.script import address, classify, disassemble

GENESIS = (
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d"
    "0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66"
    "207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe55"
    "48271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba"
    "0b8d578a4c702b6bf11d5fac00000000"
)

BLOCK170 = (
    "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e"
    "45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd1290"
    "9d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b"
    "99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6c"
    "d84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0"
    "eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
)

SEGWIT = (
    "02000000000101b2a0f8e6d4c2b0a8f6e4c2b0a8f6d4e2c0a8f6b4d2e1c3a7504f9e2b6d3c1f8a0000000000fdffffff"
    "0200ca9a3b0000000016001460d8f91f350d3f65a14b4889af4198c8f1c1407ef0006bee00000000160014930d55608b"
    "d4b9e716eb268077700142b0f54096024730440220354544cfd44a9aa19168d6ca44b536432d10d16a18609f597c0d5f"
    "e5705aa299022015ec8fd9ef8dc87e3e948c1cdadf381819d5686353a971d5f1c79f434c97e1b0012103dbc2c19158b7"
    "d46b711c5ab28ed9dbdcea06595aee328d1932991b277e20dfad00000000"
)


@pytest.mark.parametrize("n,size", [
    (0, 1), (252, 1), (253, 3), (65535, 3), (65536, 5), (2**32 - 1, 5), (2**32, 9),
])
def test_varint(n, size):
    b = write_varint(n)
    assert len(b) == size
    assert read_varint(b) == (n, size)


def test_varint_offset():
    data = b"\x00\x00" + write_varint(65536)
    assert read_varint(data, 2) == (65536, 7)


def test_genesis():
    tx = parse_tx(GENESIS)
    assert tx.txid() == "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    assert tx.wtxid() == tx.txid()
    assert tx.inputs[0]["offset"] == 5
    assert tx.outputs[0]["value"] == 5000000000
    assert classify(tx.outputs[0]["script"]) == "p2pk"
    assert address(tx.outputs[0]["script"]) is None
    assert tx.serialize().hex() == GENESIS


def test_block170():
    tx = parse_tx(BLOCK170)
    assert tx.txid() == "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
    assert tx.inputs[0]["txid"] == "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9"
    assert tx.inputs[0]["offset"] == 5
    assert [o["value"] for o in tx.outputs] == [1000000000, 4000000000]
    assert tx.serialize().hex() == BLOCK170


def test_segwit():
    tx = parse_tx(SEGWIT)
    assert tx.segwit
    assert tx.txid() == "795bd3e37ba060f0616d2651a088a8bda95c5c64de145f34382ae2ee36dd1a31"
    assert tx.wtxid() != tx.txid()
    assert tx.inputs[0]["offset"] == 7
    assert tx.inputs[0]["sequence"] == 0xFFFFFFFD
    assert len(tx.inputs[0]["witness"]) == 2
    assert len(tx.inputs[0]["witness"][1]) == 33
    assert tx.size() == 222
    assert tx.stripped_size() == 113
    assert tx.weight() == 561
    assert tx.vsize() == 141
    assert tx.serialize().hex() == SEGWIT


def test_segwit_addresses():
    tx = parse_tx(SEGWIT)
    assert address(tx.outputs[0]["script"]) == "bcrt1qvrv0j8e4p5lktg2tfzy67svcercuzsr773pr85"
    assert address(tx.outputs[1]["script"]) == "bcrt1qjvx42cyt6ju7w9hty6q8wuqpg2c02sykc9ewus"


def test_p2pkh():
    s = bytes.fromhex("76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac")
    assert classify(s) == "p2pkh"
    assert disassemble(s) == "OP_DUP OP_HASH160 <62e907b15cbf27d5425399ebf6f0fb50ebb88f18> OP_EQUALVERIFY OP_CHECKSIG"
    assert address(s, "mainnet") == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


def test_p2sh():
    s = bytes.fromhex("a914748284390f9e263a4b766a75d0633c50426eb87587")
    assert classify(s) == "p2sh"
    assert address(s, "mainnet") == "3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V"


def test_p2wpkh():
    s = bytes.fromhex("0014751e76e8199196d454941c45d1b3a323f1433bd6")
    assert classify(s) == "p2wpkh"
    assert address(s, "mainnet") == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"


def test_p2wsh():
    s = bytes.fromhex("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
    assert classify(s) == "p2wsh"
    assert address(s, "mainnet") == "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"


def test_p2tr():
    s = bytes.fromhex("512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    assert classify(s) == "p2tr"
    assert address(s, "mainnet").startswith("bc1p")


def test_nulldata():
    s = bytes.fromhex("6a0b68656c6c6f20776f726c64")
    assert classify(s) == "nulldata"
    assert address(s) is None


def test_errors():
    with pytest.raises(ParseError):
        parse_tx(GENESIS[:-2])
    with pytest.raises(ParseError):
        parse_tx(GENESIS + "00")
    with pytest.raises(ParseError):
        parse_tx("hello")
