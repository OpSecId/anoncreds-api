from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from app.plugins import AskarStorage, AnonCredsV2
from app.models.web_requests import (
    VerifyPresentationRequest,
    MessageGeneratorRequest,
    DecryptProofRequest
)

router = APIRouter(tags=["Verifiers"])
askar = AskarStorage()
anoncreds = AnonCredsV2()

@router.post("/verifiers/presentations/verify")
async def verify_presentation(request_body: VerifyPresentationRequest):
    request_body = request_body.model_dump()

    presentation = request_body.get("presentation")
    options = request_body.get("options")

    askar = AskarStorage()
    pres_schema = await askar.fetch("resource", options.get("presReqId"))

    anoncreds = AnonCredsV2()
    verification = anoncreds.verify_presentation(
        pres_schema, presentation, options.get("challenge")
    )

    return JSONResponse(
        status_code=200,
        content={
            "verification": verification,
        },
    )

@router.post("/verifiers/keys")
async def create_encryption_keypair():
    encryption_key, decryption_key = anoncreds.create_keypair()

    return JSONResponse(
        status_code=200,
        content={
            "encryption_key": encryption_key,
            "decryption_key": decryption_key,
        },
    )

@router.post("/verifiers/challenge")
async def create_challenge():
    return JSONResponse(
        status_code=200,
        content={
            "nonce": anoncreds.create_nonce(),
        },
    )

@router.post("/verifiers/generator")
async def create_message_generator(request_body: MessageGeneratorRequest):
    request_body = request_body.model_dump()
    return JSONResponse(
        status_code=200,
        content={
            "domain": request_body.get("domain"),
            "generator": anoncreds.message_generator(request_body.get("domain"))
        },
    )

@router.post("/verifiers/decrypt")
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