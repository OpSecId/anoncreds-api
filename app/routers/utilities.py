"""Identifier endpoints for DIDWeb and DIDWebVH."""

import json

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse

from app.models.web_requests import (
    MessageGeneratorRequest,
    DecryptProofRequest,
    CreateCommitmentRequest,
    UnblindCredentialRequest,
)
from app.plugins import AskarStorage, AnonCredsV2
from config import settings

router = APIRouter(tags=["Utilities"])


@router.post("/test")
async def full_test():
    anoncreds = AnonCredsV2()
    value_1 = anoncreds.full_test()

    return JSONResponse(status_code=200, content={"value_1": value_1})


@router.post("/keys")
async def create_keypair():
    anoncreds = AnonCredsV2()
    encryption_key, decryption_key = anoncreds.create_keypair()

    return JSONResponse(
        status_code=200,
        content={
            "encryption_key": encryption_key,
            "decryption_key": decryption_key,
        },
    )


@router.post("/membership")
async def membership_registry():
    anoncreds = AnonCredsV2()
    signing_key, verification_key, registry = anoncreds.membership_registry()

    return JSONResponse(
        status_code=200,
        content={
            "signing_key": signing_key,
            "verification_key": verification_key,
            "registry": registry,
        },
    )


@router.post("/scalar")
async def create_scalar():
    anoncreds = AnonCredsV2()
    scalar = anoncreds.create_scalar()

    return JSONResponse(
        status_code=200,
        content={
            "scalar": scalar,
        },
    )


@router.post("/challenge")
async def create_challenge():
    anoncreds = AnonCredsV2()
    nonce = anoncreds.create_nonce()

    return JSONResponse(
        status_code=200,
        content={
            "nonce": nonce,
        },
    )


@router.post("/generator")
async def create_message_generator(request_body: MessageGeneratorRequest):
    request_body = request_body.model_dump()
    anoncreds = AnonCredsV2()
    generator = anoncreds.message_generator(request_body.get("domain"))

    return JSONResponse(
        status_code=200,
        content={"generator": generator, "domain": request_body.get("domain")},
    )


@router.post("/decrypt")
async def decrypt_proof(request_body: DecryptProofRequest):
    request_body = request_body.model_dump()

    proof = request_body.get("proof")
    options = request_body.get("options")

    anoncreds = AnonCredsV2()
    decrypted_proof = anoncreds.decrypt_proof(proof, options.get("decryptionKey"))

    return JSONResponse(
        status_code=201,
        content={
            "decrypted": decrypted_proof,
        },
    )


@router.post("/commitment")
async def create_commitment(request_body: CreateCommitmentRequest):
    request_body = request_body.model_dump()

    anoncreds = AnonCredsV2()
    commitment = anoncreds.create_commitment(
        request_body.get("value"), request_body.get("domain")
    )

    return JSONResponse(
        status_code=201,
        content={
            "commitment": commitment,
        },
    )


@router.post("/unblind")
async def reveal_blinded_credential(request_body: UnblindCredentialRequest):
    request_body = request_body.model_dump()
    
    credential = request_body.get('credential')
    options = request_body.get('options')
    
    askar = AskarStorage()
    cred_def = await askar.fetch('resource', options.get('verificationMethod'))
    if not cred_def:
        raise HTTPException(status_code=404, detail="No credential definition.")

    blind_bundle = {
        'credential': credential,
        'issuer': cred_def
    }
    blind_claims = {"linkSecret": {"Scalar": {"value": options.get('linkSecret')}}}
    
    anoncreds = AnonCredsV2()
    credential = anoncreds.unblind_credential(
        blind_bundle, blind_claims, options.get('blinder')
    )

    return JSONResponse(
        status_code=200,
        content={
            "credential": credential,
        },
    )
