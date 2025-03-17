"""Identifier endpoints for DIDWeb and DIDWebVH."""

import json

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse

from app.models.web_requests import MessageGeneratorRequest
from app.plugins import AskarStorage, AnonCredsV2
from config import settings

router = APIRouter(tags=["Utilities"])


@router.post("/keys")
async def create_keypair():
    anoncreds = AnonCredsV2()
    encryption_key, decryption_key = anoncreds.create_keypair()
    
    return JSONResponse(status_code=200, content={
        'encryption_key': encryption_key,
        'decryption_key': decryption_key,
    })

@router.post("/generator")
async def create_message_generator(request_body: MessageGeneratorRequest):
    request_body = request_body.model_dump()
    anoncreds = AnonCredsV2()
    generator = anoncreds.message_generator(request_body.get('domain'))
    
    return JSONResponse(status_code=200, content={
        'generator': generator,
        'domain': request_body.get('domain')
    })