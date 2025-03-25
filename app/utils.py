from multiformats import multibase, multihash
import jcs
import json
from cbor2 import dumps, loads, load
from app.plugins.askar import AskarStorage

multibase_encodings = {"bls": "eb01"}


def digest_multibase(value):
    return multibase.encode(
        multihash.digest(jcs.canonicalize(value), "sha2-256"), "base58btc"
    )


def multibase_encode(value):
    return multibase.encode(jcs.canonicalize(value), "base58btc")

def multibase_decode(value):
    return json.loads(multibase.decode(value))


def public_key_multibase(key_hex, key_type):
    return multibase.encode(
        bytes.fromhex(f"{multibase_encodings[key_type]}{key_hex}"), "base58btc"
    )


def to_encoded_cbor(data):
    return multibase.encode(dumps(data), "base58btc")


def from_encoded_cbor(data):
    return loads(multibase.decode(data))


def to_cbor(data):
    return dumps(data)


def from_cbor(data):
    return loads(data)


async def cred_def_id_from_verification_method(verification_method):
    askar = AskarStorage()
    issuer_id = verification_method.split("#")[0].split(":")[-1]
    did_document = await askar.fetch("didDocument", issuer_id)
    cred_def_id = next(
        (
            service.get("id").split("#")[-1]
            for service in did_document.get("service")
            if service["verificationMethod"] == verification_method
        ),
        None,
    )
    # cred_def = await askar.fetch('resource', cred_def_id)
    return cred_def_id
