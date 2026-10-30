#!/usr/bin/env python3
"""CC0-1.0. Public test fixtures only; not a production secret-handling API.

Run: python3 reference.py
Requires a Python hashlib provider with RIPEMD160 support.
"""
import hashlib
import hmac
import json
import unicodedata
from pathlib import Path


def mac(key, message, algorithm):
    return hmac.new(key, message, algorithm).digest()


def sha256(data):
    return hashlib.sha256(data).digest()


def integer(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("integer out of range")


def bip39_seed(mnemonic, passphrase=""):
    # Caller must separately validate mnemonic word count, words, and checksum.
    normalize = lambda s: unicodedata.normalize("NFKD", s).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", normalize(mnemonic),
                              b"mnemonic" + normalize(passphrase), 2048, 64)


def slip21_node(seed, labels):
    node = mac(b"Symmetric key seed", seed, "sha512")
    for label in labels:
        node = mac(node[:32], b"\x00" + label, "sha512")
    return node


def app_key(seed, seed_source):
    lengths = {"bip39": 64, "raw32": 32}
    if seed_source not in lengths or len(seed) != lengths[seed_source]:
        raise ValueError("unsupported seed source or length")
    return slip21_node(seed, [b"QSB-HORS"])[32:]


def secret(key, net, vault, round_index, index):
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    integer(net, 1)
    integer(vault, 0x7fffffff)
    integer(round_index, 1)
    integer(index, 149)
    message = (b"QSB-HORS-v1\x00" + bytes([net]) + vault.to_bytes(4, "big")
               + bytes([round_index]) + index.to_bytes(2, "big"))
    assert len(message) == 20
    return mac(key, message, "sha256")[:20]


def hash160(data):
    return hashlib.new("ripemd160", sha256(data)).digest()


def root(key, net, vault):
    return sha256(b"QSB-HORS-v1/root" + b"".join(
        hash160(secret(key, net, vault, r, i))
        for r in range(2) for i in range(150)))


def disclosure_digest(round0, round1, binding):
    if len(binding) != 32:
        raise ValueError("binding must be 32 bytes")
    for indices, size in [(round0, 8), (round1, 7)]:
        if len(indices) != size:
            raise ValueError("wrong disclosure cardinality")
        for i in indices:
            integer(i, 149)
        if len(set(indices)) != size:
            raise ValueError("duplicate index within a round")
    encoded = b"".join(i.to_bytes(2, "big") for i in list(round0) + list(round1))
    return sha256(b"QSB-HORS-v1/reveal" + encoded + binding)


def make_vectors():
    key = bytes(range(32))
    cases = [(0, 0, 0, 0), (0, 0, 1, 149), (0, 7, 0, 3),
             (1, 0x7fffffff, 1, 42)]
    mnemonic = " ".join(["all"] * 12)
    seeds = [("bip39", bip39_seed(mnemonic), dict(mnemonic=mnemonic, passphrase="")),
             ("raw32", bytes(range(32)), {})]
    return {
        "warning": "Public test fixtures. Never use for funds.",
        "seed_vectors": [dict(seed_source=source, **extra, seed=seed.hex(),
                              key=app_key(seed, source).hex())
                         for source, seed, extra in seeds],
        "key": key.hex(),
        "secrets": [dict(net=n, v=v, r=r, i=i,
                         secret=secret(key, n, v, r, i).hex(),
                         commitment=hash160(secret(key, n, v, r, i)).hex())
                    for n, v, r, i in cases],
        "roots": [dict(net=n, v=v, root=root(key, n, v).hex())
                  for n, v in [(0, 0), (0, 7), (1, 0)]],
        "disclosure": dict(round0=list(range(8)), round1=list(range(140, 147)),
                           binding=(b"\xab" * 32).hex(),
                           digest=disclosure_digest(list(range(8)), list(range(140, 147)),
                                                    b"\xab" * 32).hex())
    }


def check():
    seed = bip39_seed(" ".join(["all"] * 12))
    assert slip21_node(seed, [b"SLIP-0021"])[32:].hex() == (
        "1d065e3ac1bbe5c7fad32cf2305f7d709dc070d672044a19e610c77cdf33de0d")
    vectors = make_vectors()
    expected = [
        ("df83cf4950602d2d3b90041023b941271bc7c494", "887b040fb41eb3cf514e3bd63986f08697b943c4"),
        ("84f94456b5537fc0a7b922e056673e455d666c0a", "27567ff92caad5adb3484d58f93e4995262d78df"),
        ("47ddd932d497ec0a108ed395d9cb35830f1a984e", "e7e455fde8b2a8e66143447aa166e72a1010c603"),
        ("e6af8e17907e54ca6d210d39042ed0575ba6bab4", "2171b247eacdb5dcb343450fbb22987a4f2a8f92")]
    assert [(v["secret"], v["commitment"]) for v in vectors["secrets"]] == expected
    assert vectors["roots"][0]["root"] == "9b257b6acd00017b1488ed9d73d05bc8a5dbdd43c8aa54d1d37c7e807d65c515"
    assert vectors["roots"][1]["root"] == "8ea0f0b0ac0db4db0405bedf47bd3c54fe946e5d1ed3a158fb11a72580940e11"
    assert vectors["disclosure"]["digest"] == "498b1ea9b6c381e78fc76f0a9c2003b1d29ef25caf92d5a3b6a1d7dbc90f7d2c"
    assert vectors["roots"][0]["root"] != vectors["roots"][2]["root"]
    key = bytes(range(32))
    bad = [(2, 0, 0, 0), (0, -1, 0, 0), (0, 2**31, 0, 0),
           (0, 0, 2, 0), (0, 0, 0, 150), (False, 0, 0, 0)]
    for args in bad:
        try:
            secret(key, *args)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid tuple accepted")
    try:
        disclosure_digest([0] * 8, list(range(7)), b"\xab" * 32)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate indices accepted")
    assert disclosure_digest(list(reversed(range(8))), list(range(140, 147)), b"\xab" * 32).hex() != vectors["disclosure"]["digest"]
    # This fixture serializes one input with an empty scriptSig and one output.
    # It tests B's byte encoding; it is not a QSB spend or a consensus-valid fixture.
    tx = (bytes.fromhex("0200000001") + b"\x11" * 32 + bytes.fromhex("0000000000ffffffff01")
          + (1000).to_bytes(8, "little") + bytes.fromhex("015100000000"))
    binding = sha256(tx)
    round0, round1 = list(range(8)), list(range(140, 147))
    vectors["binding_encoding"] = dict(
        transaction=tx.hex(), binding=binding.hex(), round0=round0, round1=round1,
        digest=disclosure_digest(round0, round1, binding).hex())
    return vectors


if __name__ == "__main__":
    actual = check()
    target = Path(__file__).with_name("vectors.json")
    if target.exists():
        assert json.loads(target.read_text()) == actual, "vector file mismatch"
        print("PASS: SLIP-0021, upstream QSB vectors, boundaries, ordering, and vector file")
    else:
        target.write_text(json.dumps(actual, indent=2) + "\n")
        print("PASS: vectors checked against upstream constants; vectors.json created")
