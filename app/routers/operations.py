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
    IssueCredentialRequest,
)
from app.plugins import AskarStorage, AnonCredsV2
from config import settings

router = APIRouter(tags=["Operations"])


@router.post("/credentials/setup")
async def setup_credential(request_body: SetupIssuerRequest):
    """"""
    request_body = request_body.model_dump()

    cred_schema_id = request_body.get("credSchemaId")

    askar = AskarStorage()
    cred_schema = await askar.fetch("resource", cred_schema_id)

    if not cred_schema:
        raise HTTPException(status_code=404, detail="No schema found.")

    anoncreds = AnonCredsV2()
    issuer_pub, issuer_priv = anoncreds.setup_issuer(cred_schema)

    askar = AskarStorage()

    await askar.store("resource", issuer_pub.get("id"), issuer_pub)
    await askar.store("secret", issuer_priv.get("id"), issuer_priv)

    issuer_pub.pop("schema")
    issuer_priv.pop("schema")

    return JSONResponse(
        status_code=201, content={"public": issuer_pub, "private": issuer_priv}
    )


@router.post("/credentials/request")
async def request_credential(request_body: BlindCredentialRequest):
    """"""
    request_body = request_body.model_dump()

    cred_def_id = request_body.get("verificationMethod")
    link_secret = request_body.get("linkSecret")

    askar = AskarStorage()
    cred_def = await askar.fetch("resource", cred_def_id)
    if not cred_def:
        raise HTTPException(status_code=404, detail="No credential definition.")

    anoncreds = AnonCredsV2()

    blind_claims = {"linkSecret": {"Scalar": {"value": link_secret}}}
    blind_claims, cred_request, blinder = anoncreds.credential_request(cred_def, blind_claims)

    return JSONResponse(
        status_code=201,
        content={
            "blindClaims": blind_claims,
            "requestProof": cred_request,
            "blinder": blinder,
        },
    )


@router.post("/credentials/issuance")
async def issue_credential(request_body: IssueCredentialRequest):
    """"""
    request_body = request_body.model_dump()

    cred_subject = request_body.get("credentialSubject")
    
    options = request_body.get("options")
    cred_id = options.get("credentialId") or str(uuid.uuid4())
    cred_def_id = options.get("verificationMethod")
    request_proof = options.get("requestProof")
    
    issuer = await AskarStorage().fetch("secret", cred_def_id)
    cred_def = await AskarStorage().fetch("resource", cred_def_id)
    
    if not cred_def or not issuer:
        raise HTTPException(status_code=404, detail="No issuer.")

    issuer = AnonCredsV2(issuer=issuer)
    claims_data = issuer.map_claims(cred_def, cred_subject, cred_id)
    if request_proof:
        claim_indices = cred_def['schema'].get('claim_indices')
        claim_indices.remove('linkSecret')
        claims_map = {}
        for idx, claim in enumerate(claims_data):
            claims_map[claim_indices[idx]] = claim
        signed_credential = issuer.issue_blind_credential(claims_map, request_proof)
    
    else:
        signed_credential = issuer.issue_credential(claims_data)

    return JSONResponse(status_code=201, content=signed_credential)


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
