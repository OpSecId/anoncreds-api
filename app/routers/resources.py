"""Identifier endpoints for DIDWeb and DIDWebVH."""

import json

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse

from app.models.web_requests import SetupIssuerRequest, IssueCredentialRequest
from app.plugins import AskarStorage, AnonCredsV2
from config import settings

router = APIRouter(tags=["Resources"])


@router.post("/{resource_id}")
async def fetch_resource(resource_id: str):
    askar = AskarStorage()
    resource = await askar.fetch('resource', resource_id)
    if not resource:
        return JSONResponse(status_code=404, content={})
    
    return JSONResponse(status_code=200, content=resource)