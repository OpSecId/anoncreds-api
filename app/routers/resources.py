"""AnonCreds v2 resource creation."""

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse

from app.models.web_requests import NewCredSchema, NewPresSchema, SetupIssuerRequest
from app.plugins import AskarStorage, AnonCredsV2
from app.utils import public_key_multibase
from config import settings

router = APIRouter(tags=["Resources"])


@router.get("/{resource_id}")
async def fetch_resource(resource_id: str):
    askar = AskarStorage()
    resource = await askar.fetch("resource", resource_id)
    if not resource:
        return JSONResponse(status_code=404, content={})

    return JSONResponse(status_code=200, content=resource)


@router.post("/schemas/credentials")
async def new_cred_schema(request_body: NewCredSchema):
    request_body = request_body.model_dump()

    json_schema = request_body.get("jsonSchema")
    options = request_body.get("options")

    anoncreds = AnonCredsV2()
    schema = anoncreds.map_cred_schema(json_schema, options)
    schema = anoncreds.create_cred_schema(schema)

    askar = AskarStorage()
    if not await askar.fetch("resource", schema.get("id")):
        await askar.store("resource", schema.get("id"), schema)

        return JSONResponse(
            status_code=201,
            content={
                "schema": schema,
            },
        )
    return JSONResponse(
        status_code=200,
        content={
            "credentialSchema": schema,
        },
    )


@router.post("/schemas/presentations")
async def new_pres_schema(request_body: NewPresSchema):
    request_body = request_body.model_dump()

    queries = request_body.get("query")
    challenge = request_body.get("challenge")

    askar = AskarStorage()
    for query in queries:
        print(query)
        if query.get("type") == "SignatureQuery":
            query["issuer"] = await askar.fetch(
                "resource", query.pop("verificationMethod")
            )
            if not query.get("issuer"):
                raise HTTPException(status_code=404, detail="No issuer found.")

    anoncreds = AnonCredsV2()
    statements = anoncreds.map_pres_schema(queries, challenge)
    pres_schema = anoncreds.create_pres_schema(statements)

    if not await askar.fetch("resource", pres_schema.get("id")):
        await askar.store("resource", pres_schema.get("id"), pres_schema)

    return JSONResponse(
        status_code=201,
        content={
            "presentationSchema": pres_schema,
        },
    )


@router.get("/issuers/{issuer_id}")
async def get_issuer_did_document(issuer_id: str = 'demo'):
    """Server status endpoint."""
    askar = AskarStorage()
    did_document = await askar.fetch('didDocument', issuer_id)
    if not did_document:
        raise HTTPException(status_code=404, detail="No issuer found.")
    return JSONResponse(status_code=200, content={'didDocument', did_document})


@router.post("/issuers/{issuer_id}")
async def setup_new_verification_method(request_body: SetupIssuerRequest, issuer_id: str = 'demo'):
    request_body = request_body.model_dump()
    
    askar = AskarStorage()
    did = f'did:web:{settings.DOMAIN}:issuers:{issuer_id}'
    did_document = await askar.fetch('didDocument', issuer_id)
    if not did_document:
        did_document = {
            '@context': [
                'https://www.w3.org/ns/did/v1'
            ],
            'id': did,
            'verificationMethod': [],
            'service': [],
        }
        await askar.store('didDocument', issuer_id, did_document)
        
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

    public_key_multi = public_key_multibase(
        issuer_pub.get("verifying_key").get("w"), "bls"
    )
    did_document['verificationMethod'].append({
        'type': 'Multikey',
        'id': f'{did}#{public_key_multi}',
        'controller': did,
        'publicKeyMultibase': public_key_multi
    })
    did_document['service'].append({
        'type': 'AnonCredsRegistry',
        'id': f'{did}#{issuer_pub.get("id")}',
        'serviceEndpoint': f'https://{settings.DOMAIN}/resources/{issuer_pub.get("id")}',
        'verificationMethod': f'{did}#key-{public_key_multi}'
    })
    await askar.update("didDocument", issuer_id, did_document)

    return JSONResponse(
        status_code=201, content={"didDocument": did_document}
    )
