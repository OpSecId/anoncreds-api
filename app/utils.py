from multiformats import multibase, multihash
import jcs
from cbor2 import dumps, loads, load

multibase_encodings = {"bls": "eb01"}


def digest_multibase(value):
    return multibase.encode(
        multihash.digest(jcs.canonicalize(value), "sha2-256"), "base58btc"
    )


def multibase_encode(value):
    return multibase.encode(jcs.canonicalize(value), "base58btc")


def public_key_multibase(key_hex, key_type):
    return multibase.encode(
        bytes.fromhex(f"{multibase_encodings[key_type]}{key_hex}"), "base58btc"
    )


def to_cbor(data):
    return dumps(data)


def from_cbor(data):
    return loads(data)
