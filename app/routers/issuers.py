from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from app.plugins import AskarStorage, AnonCredsV2
from app.models.web_requests import (
    SetupIssuerRequest,
    IssueCredentialRequest
)
from config import settings
from app.utils import public_key_multibase
import uuid

router = APIRouter(tags=["Issuers"])
askar = AskarStorage()
anoncreds = AnonCredsV2()

@router.get("/issuers/{issuer_id}", tags=["Issuers"])
async def get_did_document(issuer_id: str):
    did_document = await askar.fetch("didDocument", issuer_id)
    if not did_document:
        raise HTTPException(status_code=404, detail="No issuer found.")
    return JSONResponse(status_code=200, content={'didDocument': did_document})

@router.delete("/issuers/{issuer_id}", tags=["Issuers"])
async def clear_issuer_did_document(issuer_id: str):
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
                "id": f"{did}#anoncreds-api",
                "serviceEndpoint": "https://api.anoncreds.vc",
            }
        ],
    }
    await askar.update("didDocument", issuer_id, did_document)
    return JSONResponse(status_code=200, content={})

@router.post("/issuers/{issuer_id}/credentials", tags=["Issuers"])
async def new_credential_definition(
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
                    "id": f"{did}#anoncreds-api",
                    "serviceEndpoint": "https://api.anoncreds.vc",
                }
            ],
        }
        await askar.store("didDocument", issuer_id, did_document)

    cred_schema_id = request_body.get("credSchemaId")
    cred_schema = await askar.fetch("credentialSchema", cred_schema_id)
    if not cred_schema:
        raise HTTPException(status_code=404, detail="No schema found.")

    cred_def, issuer_priv = anoncreds.setup_issuer(cred_schema)
    cred_def_id = cred_def.get("id")
    cred_def["id"] = f"{did}#{cred_def_id}"

    await askar.store("credentialDefinition", cred_def_id, cred_def)
    await askar.store("secret", cred_def_id, issuer_priv)

    verification_method = {
        "type": "Multikey",
        "id": cred_def.get("id"),
        "controller": did,
        "publicKeyMultibase": public_key_multibase(
            cred_def.get("verifying_key").get("w"), "bls"
        ),
        "credentialRegistry": f"https://{settings.DOMAIN}/resources/{cred_def_id}",
    }
    did_document["assertionMethod"].append(verification_method.get("id"))
    did_document["verificationMethod"].append(verification_method)
    await askar.update("didDocument", issuer_id, did_document)

    return JSONResponse(
        status_code=201, content={
            "credentialDefinitionId": cred_def_id,
            "verificationMethod": verification_method
        }
    )


@router.get("/issuers/{issuer_id}/credentials/{cred_def_id}", tags=["Issuers"])
async def get_credential_definition(issuer_id: str, cred_def_id: str):
    """Server status endpoint."""
    askar = AskarStorage()
    cred_def = await askar.fetch("credentialDefinition", cred_def_id)
    if not cred_def:
        raise HTTPException(status_code=404, detail="No issuer found.")
    return JSONResponse(status_code=200, content=cred_def)


@router.post("/issuers/{issuer_id}/credentials/{cred_def_id}/issue", tags=["Issuers"])
async def issue_credential(request_body: IssueCredentialRequest):
    """"""
    request_body = request_body.model_dump()

    cred_subject = request_body.get("credentialSubject")

    options = request_body.get("options")
    cred_id = options.get("credentialId") or str(uuid.uuid4())
    # rev_id = options.get("revocationId") or str(uuid.uuid4())
    cred_def_id = options.get("verificationMethod").split("#")[-1]
    issuer_did = options.get("verificationMethod").split("#")[0]
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

    cred_def["issuer_did"] = issuer_did
    # credential = issuer.cred_to_w3c(cred_def, credential)
    # credential = issuer.w3c_to_cred(cred_def, credential)

    return JSONResponse(status_code=201, content={"credential": credential})
    # return JSONResponse(status_code=201, content={'credential': credential})




@router.get("/issuers/{issuer_id}/did.json", tags=["Issuers"], include_in_schema=False)
async def resolve_issuer_did(issuer_id: str = "demo"):
    did_document = await askar.fetch("didDocument", issuer_id)
    if not did_document:
        raise HTTPException(status_code=404, detail="No issuer found.")
    return JSONResponse(status_code=200, content=did_document)
