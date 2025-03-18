"""Identifier endpoints for DIDWeb and DIDWebVH."""

import json
import uuid

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse

from app.models.web_requests import CreatePresReqRequest, VerifyPresentationRequest
from app.plugins import AskarStorage, AnonCredsV2
from config import settings

router = APIRouter(tags=["Verifier"])


@router.post("/create-pres-schema")
async def create_pres_schema(request_body: CreatePresReqRequest):
    """"""
    request_body = request_body.model_dump()
    
    statements = request_body.get('statements')
    options = request_body.get('options')
    
    askar = AskarStorage()
    cred_def = await askar.fetch('resource', options.get('credDefId'))
    
    if not cred_def:
        raise HTTPException(status_code=404, detail="No Cred Def.")
    
    anoncreds = AnonCredsV2()
    statements = anoncreds.map_statements(cred_def, statements, options)
    pres_req = anoncreds.new_pres_req(statements)
    
    await askar.store('resource', pres_req.get('id'), pres_req)
    
    return JSONResponse(status_code=201, content={
        'presReq': pres_req,
    })


@router.post("/verify-presentation")
async def verify_presentation(request_body: VerifyPresentationRequest):
    request_body = request_body.model_dump()
    
    presentation = request_body.get('presentation')
    options = request_body.get('options')
    askar = AskarStorage()
    pres_schema = await askar.fetch('resource', options.get('presReqId'))
    anoncreds = AnonCredsV2()
    challenge = options.get('challenge')
    verification = anoncreds.verify_presentation(pres_schema, presentation, challenge)
    
    return JSONResponse(status_code=200, content={
        'verification': verification,
    })