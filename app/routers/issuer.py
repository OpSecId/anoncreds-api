"""Identifier endpoints for DIDWeb and DIDWebVH."""

import json
import uuid

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse

from app.models.web_requests import CreateSchemaRequest, SetupIssuerRequest, IssueCredentialRequest
from app.plugins import AskarStorage, AnonCredsV2
from config import settings

router = APIRouter(tags=["Issuer"])


@router.post("/schema")
async def create_cred_schema(request_body: CreateSchemaRequest):
    """"""
    request_body = request_body.model_dump()
    
    json_schema = request_body.get('jsonSchema')
    options = request_body.get('options')
    
    if not json_schema or not options:
        raise HTTPException(status_code=400, detail="Missing input.")
    
    anoncreds = AnonCredsV2()
    schema = anoncreds.map_schema(json_schema, options)
    schema = anoncreds.create_schema(schema)
    
    askar = AskarStorage()
    
    try:
        await askar.store('resource', schema.get('id'), schema)
    except:
        pass
    
    return JSONResponse(status_code=201, content={
        'schema': schema,
    })


@router.post("/setup")
async def setup_issuer(request_body: SetupIssuerRequest):
    """"""
    request_body = request_body.model_dump()
    
    options = request_body.get('options')
    
    askar = AskarStorage()
    schema = await askar.fetch('resource', options.get('schemaId'))
    
    if not schema:
        raise HTTPException(status_code=404, detail="No schema.")
    
    anoncreds = AnonCredsV2()
    issuer_pub, issuer_priv = anoncreds.setup_issuer(schema)
    
    askar = AskarStorage()
    
    await askar.store('resource', issuer_pub.get('id'), issuer_pub)
    await askar.store('secret', issuer_priv.get('id'), issuer_priv)
    
    issuer_pub.pop('schema')
    issuer_priv.pop('schema')
    
    return JSONResponse(status_code=201, content={
        'public': issuer_pub,
        'private': issuer_priv
    })


@router.post("/issue")
async def issue_credential(request_body: IssueCredentialRequest):
    """"""
    request_body = request_body.model_dump()
    
    credential = request_body.get('credential')
    credential_request = request_body.get('credentialRequest')
    subject = request_body.get('credentialSubject')
    options = request_body.get('options')
    cred_id = options.get('credentialId') or str(uuid.uuid4())
    
    cred_def_id = options.get('credDefId')
    issuer = await AskarStorage().fetch('secret', cred_def_id)
    cred_def = await AskarStorage().fetch('resource', cred_def_id)
    if not cred_def or not issuer:
        raise HTTPException(status_code=404, detail="No issuer.")
    print(issuer)
    
    # if not credential or not options:
    #     raise HTTPException(status_code=400, detail="Missing input.")
    
    # if credential_request:
    #     pass
    
    issuer = AnonCredsV2(issuer=issuer)
    # cred_id = str(uuid.uuid4())
    claims_data = issuer.map_claims(cred_def, subject, cred_id)
    signed_credential = issuer.issue_credential(claims_data)
    # signed_credential = {}
    
    return JSONResponse(status_code=201, content=signed_credential)

