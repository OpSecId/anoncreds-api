"""Identifier endpoints for DIDWeb and DIDWebVH."""

import json
import uuid

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse

from app.models.web_requests import (
    VerifyPresentationRequest,
    CreatePresentationRequest,
    BlindCredentialRequest,
    SetupIssuerRequest,
    StoreCredentialRequest,
    IssueCredentialRequest,
)
from app.plugins import AskarStorage, AnonCredsV2
from app.utils import cred_def_id_from_verification_method
from config import settings

router = APIRouter(tags=["Operations"])


@router.post("/credentials/request")
async def request_credential(request_body: BlindCredentialRequest):
    """"""
    request_body = request_body.model_dump()

    subject_id = request_body.get("subjectId")
    cred_def_id = request_body.get("verificationMethod").split('#')[-1]

    askar = AskarStorage()
    cred_def = await askar.fetch("resource", cred_def_id)

    if not cred_def:
        raise HTTPException(status_code=404, detail="No credential definition.")

    anoncreds = AnonCredsV2()
    link_secret = anoncreds.create_scalar(subject_id)

    blind_claims = {"linkSecret": {"Scalar": {"value": link_secret}}}
    blind_claims, cred_request, blinder = anoncreds.credential_request(
        cred_def, blind_claims
    )

    return JSONResponse(
        status_code=201,
        content={
            # "link_secret": link_secret
            # "blindClaims": blind_claims,
            "requestProof": cred_request,
            # "blinder": blinder,
        },
    )


@router.post("/credentials/issuance")
async def issue_credential(request_body: IssueCredentialRequest):
    """"""
    request_body = request_body.model_dump()

    cred_subject = request_body.get("credentialSubject")

    options = request_body.get("options")
    cred_id = options.get("credentialId") or str(uuid.uuid4())
    # rev_id = options.get("revocationId") or str(uuid.uuid4())
    cred_def_id = options.get("verificationMethod").split('#')[-1]
    request_proof = options.get("requestProof")

    issuer = await AskarStorage().fetch("secret", cred_def_id)
    cred_def = await AskarStorage().fetch("resource", cred_def_id)

    if not cred_def or not issuer:
        raise HTTPException(status_code=404, detail="No issuer.")

    issuer = AnonCredsV2(issuer=issuer)
    claims_data = issuer.map_claims(cred_def, cred_subject, cred_id)
    if request_proof:
        claim_indices = cred_def["schema"].get("claim_indices")
        claim_indices.remove("linkSecret")
        claims_map = {}
        for idx, claim in enumerate(claims_data):
            claims_map[claim_indices[idx]] = claim
        signed_credential = issuer.issue_blind_credential(claims_map, request_proof)

    else:
        signed_credential = issuer.issue_credential(claims_data)

    return JSONResponse(status_code=201, content=signed_credential)


@router.post("/credentials/storage")
async def store_credential(request_body: StoreCredentialRequest):
    request_body = request_body.model_dump()
    credential = request_body.get('credential')
    if (
        not credential.get('id') 
        or not credential.get('credentialSubject')
        or not credential.get('credentialSubject').get('id')
    ):
        raise HTTPException(status_code=400, detail="Invalid Credential.")


@router.post("/presentations/creation")
async def create_presentation(request_body: CreatePresentationRequest):
    request_body = request_body.model_dump()
    credential = request_body.get("credential")
    options = request_body.get("options")
    challenge = options.get("challenge")

    askar = AskarStorage()
    pres_req = await askar.fetch("resource", options.get("presSchemaId"))

    anoncreds = AnonCredsV2()
    presentation = anoncreds.create_presentation(pres_req, credential, challenge)

    return JSONResponse(status_code=201, content={"presentation": presentation})


@router.post("/presentations/verification")
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
