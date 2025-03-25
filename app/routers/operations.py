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

askar = AskarStorage()
anoncreds = AnonCredsV2()

@router.post("/credentials/request")
async def request_credential(request_body: BlindCredentialRequest):
    """"""
    request_body = request_body.model_dump()

    cred_def_id = request_body.get("verificationMethod").split('#')[-1]
    cred_def = await askar.fetch("credentialDefinition", cred_def_id)

    if not cred_def:
        raise HTTPException(status_code=404, detail="No credential definition.")

    link_secret = anoncreds.create_scalar(request_body.get("subjectId"))

    blind_claims, cred_request, blinder = anoncreds.credential_request(
        cred_def, {"linkSecret": {"Scalar": {"value": link_secret}}}
    )

    return JSONResponse(
        status_code=201,
        content={
            "blinder": blinder,
            # "blindClaims": blind_claims,
            "requestProof": cred_request,
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
    issuer_did = options.get("verificationMethod").split('#')[0]
    request_proof = options.get("requestProof")

    issuer = await askar.fetch("secret", cred_def_id)
    cred_def = await askar.fetch("credentialDefinition", cred_def_id)

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
        credential = issuer.issue_blind_credential(claims_map, request_proof)

    else:
        credential = issuer.issue_credential(claims_data)
        
    cred_def['issuer_did'] = issuer_did
    # credential = issuer.cred_to_w3c(cred_def, credential)
    # credential = issuer.w3c_to_cred(cred_def, credential)

    return JSONResponse(status_code=201, content={'credential': credential})
    # return JSONResponse(status_code=201, content={'credential': credential})


# @router.post("/credentials/storage")
# async def store_credential(request_body: StoreCredentialRequest):
#     request_body = request_body.model_dump()
#     credential = request_body.get('credential')
#     options = request_body.get('options')
#     subject_id = options.get('subjectId')
#     verification_method = options.get('verificationMethod').split('#')[-1]
#     askar = AskarStorage()
#     cred_def = await askar.fetch("resource", verification_method)
#     if not cred_def:
#         raise HTTPException(status_code=404, detail="No credential definition.")
    
#     anoncreds = AnonCredsV2()
#     if subject_id:
#         blind_bundle = {"credential": credential, "issuer": cred_def}
#         blind_claims = {"linkSecret": {"Scalar": {"value": anoncreds.create_scalar(subject_id)}}}
#         credential = anoncreds.unblind_credential(
#             blind_bundle, blind_claims, options.get("blinder")
#         )
    
#     wallet = await askar.fetch("wallet", subject_id)
#     if not wallet and wallet != []:
#         wallet = []
#         await askar.store("wallet", subject_id, wallet)
        
#     await askar.append("wallet", subject_id, credential)
#     return JSONResponse(status_code=200, content={})


@router.post("/wallets/{holder_id}/presentations")
async def create_presentation(holder_id: str, request_body: CreatePresentationRequest):
    request_body = request_body.model_dump()
    challenge = request_body.get("challenge")
    pres_schema_id = request_body.get("presSchemaId")

    wallet = await askar.fetch("wallet", holder_id)
    if not wallet:
        raise HTTPException(status_code=404, detail="No wallet found.")
    
    pres_req = await askar.fetch("presentationSchema", pres_schema_id)
    credentials = {}
    for statement_id, statement in pres_req.get('statements').items():
        if statement.get('Signature'):
            cred_match = next(
                (
                    cred for cred in wallet 
                    if cred.get('verificationMethod') == statement.get('Signature').get('issuer').get('id')
                ), None
            )
            credentials[statement.get('Signature').get('id')] = {
                'Signature': cred_match
            }

    presentation = anoncreds.create_presentation(pres_req, credentials, challenge)

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
