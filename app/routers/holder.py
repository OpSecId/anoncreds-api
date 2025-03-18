"""Identifier endpoints for DIDWeb and DIDWebVH."""

import json
import uuid

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse

from app.models.web_requests import BlindCredentialRequest, CreatePresentationRequest
from app.plugins import AskarStorage, AnonCredsV2
from config import settings

router = APIRouter(tags=["Holder"])


@router.post("/request-credential")
async def request_credential(request_body: BlindCredentialRequest):
    """"""
    request_body = request_body.model_dump()
    
    cred_def_id = request_body.get('credDefId')
    link_secret_id = request_body.get('linkSecretId')
    
    askar = AskarStorage()
    cred_def = await askar.fetch('resource', cred_def_id)
    if not cred_def:
        raise HTTPException(status_code=404, detail="No credential definition.")
    
    anoncreds = AnonCredsV2()
    
    blind_claims = {
        'linkSecret': {
            "Scalar": {
                "value": "5179bc1a7276e2d6dddca6915a57e7b8cd41326652f7760811d56de92a4fba86"
            }
        }
    }
    cred_request, blinder = anoncreds.credential_request(cred_def, blind_claims)
    # await askar.store('secret', issuer_priv.get('id'), issuer_priv)
    # await askar.store('secret', issuer_priv.get('id'), issuer_priv)
    # await askar.store('secret', issuer_priv.get('id'), issuer_priv)
    
    return JSONResponse(status_code=201, content={
        'request': cred_request,
        'blinder': blinder,
        # 'private': issuer_priv
    })



@router.post("/create-presentation")
async def create_presentation(request_body: CreatePresentationRequest):
    request_body = request_body.model_dump()
    credential = request_body.get('credential')
    options = request_body.get('options')
    challenge = options.get('challenge')
    
    askar = AskarStorage()
    pres_req = await askar.fetch('resource', options.get('presReqId'))
    
    anoncreds = AnonCredsV2()
    presentation = anoncreds.create_presentation(pres_req, credential, challenge)
    
    return JSONResponse(status_code=201, content={
        'presentation': presentation
    })