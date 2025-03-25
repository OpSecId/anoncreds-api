"""AnonCreds v2 resource creation."""

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse

from app.models.web_requests import NewCredSchema, NewPresSchema, SetupIssuerRequest, StoreCredentialRequest
from app.plugins import AskarStorage, AnonCredsV2
from app.utils import public_key_multibase
from config import settings

router = APIRouter(tags=["Resources"])
askar = AskarStorage()
anoncreds = AnonCredsV2()


@router.get("/{resource_id}")
async def fetch_public_resource(resource_id: str):
    askar = AskarStorage()
    resource = await askar.fetch("resource", resource_id)
    if not resource:
        return JSONResponse(status_code=404, content={})

    return JSONResponse(status_code=200, content=resource)


@router.post("/schemas/credentials")
async def new_cred_schema(request_body: NewCredSchema):
    request_body = request_body.model_dump()
    
    cred_schema = anoncreds.create_cred_schema(
        anoncreds.map_cred_schema(
            request_body.get("jsonSchema"), 
            request_body.get("options")
        )
    )
    cred_schema_id = cred_schema.get("id")

    if not await askar.fetch("credentialSchema", cred_schema_id):
        await askar.store("credentialSchema", cred_schema_id, cred_schema)

    return JSONResponse(
        status_code=201,
        content={
            "credentialSchemaId": cred_schema_id,
        },
    )


@router.get("/schemas/credentials/{cred_schema_id}")
async def get_cred_schema(cred_schema_id: str):
    cred_schema = await askar.fetch("credentialSchema", cred_schema_id)
    if not cred_schema:
        raise HTTPException(status_code=404, detail="No credential schema found.")
    return JSONResponse(status_code=200, content=cred_schema)


@router.post("/schemas/presentations")
async def new_pres_schema(request_body: NewPresSchema):
    request_body = request_body.model_dump()

    queries = request_body.get("query")
    challenge = request_body.get("challenge")

    for query in queries:
        if query.get("type") == "SignatureQuery":
            verification_method_id = query.pop("verificationMethod").split('#')[-1]
            query["issuer"] = await askar.fetch("credentialDefinition", verification_method_id)
            if not query.get("issuer"):
                raise HTTPException(status_code=404, detail="No issuer found.")

    pres_schema = anoncreds.create_pres_schema(
        anoncreds.map_pres_schema(queries, challenge)
    )
    pres_schema_id = pres_schema.get("id")

    if not await askar.fetch("presentationSchema", pres_schema_id):
        await askar.store("presentationSchema", pres_schema_id, pres_schema)

    return JSONResponse(
        status_code=201,
        content={
            "presentationSchemaId": pres_schema_id,
        },
    )


@router.get("/schemas/presentations/{pres_schema_id}")
async def get_pres_schema(pres_schema_id: str):
    pres_schema = await askar.fetch("presentationSchema", pres_schema_id)
    if not pres_schema:
        raise HTTPException(status_code=404, detail="No presentation schema found.")
    return JSONResponse(status_code=200, content=pres_schema)


@router.get("/issuers/{issuer_id}")
async def get_issuer_did_document(issuer_id: str):
    """Server status endpoint."""
    askar = AskarStorage()
    did_document = await askar.fetch("didDocument", issuer_id)
    if not did_document:
        raise HTTPException(status_code=404, detail="No issuer found.")
    return JSONResponse(status_code=200, content={"didDocument": did_document})


@router.post("/issuers/{issuer_id}")
async def setup_new_verification_method(
    request_body: SetupIssuerRequest, issuer_id: str
):
    request_body = request_body.model_dump()
    did = f"did:web:{settings.DOMAIN}:issuers:{issuer_id}"
    did_document = await askar.fetch("didDocument", issuer_id)
    if not did_document:
        did_document = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1",
                {
                    "credentialRegistry": "https://www.w3.org/ns/credentials/undefined-term#credentialRegistry"
                },
            ],
            "id": did,
            "assertionMethod": [],
            "verificationMethod": [],
            "service": [
                {
                    "type": "AnonCredsAPI",
                    "id": f'{did}#anoncreds-api',
                    "serviceEndpoint": "https://api.anoncreds.vc"
                }
            ],
        }
        await askar.store("didDocument", issuer_id, did_document)

    cred_schema_id = request_body.get("credSchemaId")
    cred_schema = await askar.fetch("credentialSchema", cred_schema_id)
    if not cred_schema:
        raise HTTPException(status_code=404, detail="No schema found.")

    cred_def, issuer_priv = anoncreds.setup_issuer(cred_schema)
    cred_def_digest = cred_def.get("id")
    cred_def['id'] = f'{did}#{cred_def_digest}'


    await askar.store("credentialDefinition", cred_def_digest, cred_def)
    await askar.store("secret", cred_def_digest, issuer_priv)
    
    verification_method = {
        "type": "Multikey",
        "id": cred_def.get("id"),
        "controller": did,
        "publicKeyMultibase": public_key_multibase(
            cred_def.get("verifying_key").get("w"), "bls"
        ),
        "credentialRegistry": f'https://{settings.DOMAIN}/resources/{cred_def_digest}',
    }
    did_document["assertionMethod"].append(verification_method.get('id'))
    did_document["verificationMethod"].append(verification_method)
    await askar.update("didDocument", issuer_id, did_document)

    return JSONResponse(status_code=201, content={"verificationMethod": verification_method})
    # return JSONResponse(status_code=201, content={"didDocument": did_document})


@router.delete("/issuers/{issuer_id}")
async def delete_issuer_did_document(issuer_id: str):
    """Server status endpoint."""
    did = f"did:web:{settings.DOMAIN}:issuers:{issuer_id}"
    did_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
            {
                "credentialRegistry": "https://www.w3.org/ns/credentials/undefined-term#credentialRegistry"
            },
        ],
        "id": did,
        "assertionMethod": [],
        "verificationMethod": [],
        "service": [
            {
                "type": "AnonCredsAPI",
                "id": f'{did}#anoncreds-api',
                "serviceEndpoint": "https://api.anoncreds.vc"
            }
        ],
    }
    await askar.update("didDocument", issuer_id, did_document)
    return JSONResponse(status_code=200, content={})



@router.get("/wallets/{holder_id}")
async def get_wallet_content(holder_id: str):
    """Server status endpoint."""
    askar = AskarStorage()
    wallet = await askar.fetch("wallet", holder_id)
    if not wallet and wallet != []:
        raise HTTPException(status_code=404, detail="No wallet found.")
    
    # credential = issuer.w3c_to_cred(cred_def, credential)
    return JSONResponse(status_code=200, content={"credentials": wallet})



@router.post("/wallets/{holder_id}")
async def add_credential_to_wallet(holder_id: str, request_body: StoreCredentialRequest):
    request_body = request_body.model_dump()
    credential = request_body.get('credential')
    options = request_body.get('options')
    cred_def_id = options.get('verificationMethod').split('#')[-1]
    
    askar = AskarStorage()
    cred_def = await askar.fetch("credentialDefinition", cred_def_id)
    if not cred_def:
        raise HTTPException(status_code=404, detail="No credential definition.")
    
    anoncreds = AnonCredsV2()
    if credential.get('revocation_label'):
        credential = anoncreds.unblind_credential(
            blinder=options.get("blinder"),
            blind_bundle={"credential": credential, "issuer": cred_def}, 
            blind_claims={"linkSecret": {"Scalar": {"value": anoncreds.create_scalar(holder_id)}}}
        )
    
    wallet = await askar.fetch("wallet", holder_id)
    if not wallet and wallet != []:
        wallet = []
        await askar.store("wallet", holder_id, wallet)
    
    credential['verificationMethod'] = options.get('verificationMethod')
    await askar.append("wallet", holder_id, credential)
    
    return JSONResponse(status_code=200, content={})

@router.delete("/wallets/{holder_id}")
async def delete_wallet_content(holder_id: str):
    """Server status endpoint."""
    await askar.update("wallet", holder_id, [])
    return JSONResponse(status_code=200, content={})