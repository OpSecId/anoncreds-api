"""Identifier endpoints for DIDWeb and DIDWebVH."""

import json
import uuid

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse

from app.models.vc_api import IssueCredentialRequest, DeriveCredentialRequest
from app.plugins import AskarStorage, AnonCredsV2
from config import settings

router = APIRouter(tags=["VC-API"])


@router.post("/credentials/issue")
async def credentials_issue(request_body: IssueCredentialRequest):
    """"""
    request_body = request_body.model_dump()
    
    credential = request_body.get('credential')
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
    claims_data = issuer.map_claims(cred_def, credential.get('credentialSubject'), cred_id)
    signed_credential = issuer.issue_credential(claims_data)
    vc = issuer.cred_to_w3c(cred_def, signed_credential)
    # signed_credential = {}
    
    return JSONResponse(status_code=201, content={
        'verifiableCredential': vc
    })