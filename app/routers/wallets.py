from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from app.plugins import AskarStorage, AnonCredsV2
from app.models.web_requests import (
    BlindCredentialRequest,
    StoreCredentialRequest,
    CreatePresentationRequest,
)

router = APIRouter(tags=["Wallets"])
askar = AskarStorage()
anoncreds = AnonCredsV2()

@router.get("/wallets/{holder_id}", tags=["Wallets"])
async def get_wallet_content(holder_id: str):
    """Server status endpoint."""
    wallet = await askar.fetch("wallet", holder_id)
    if not wallet and wallet != []:
        raise HTTPException(status_code=404, detail="No wallet found.")

    # credential = issuer.w3c_to_cred(cred_def, credential)
    return JSONResponse(status_code=200, content={"credentials": wallet})


@router.delete("/wallets/{holder_id}", tags=["Wallets"])
async def delete_wallet_content(holder_id: str):
    """Server status endpoint."""
    await askar.update("wallet", holder_id, [])
    return JSONResponse(status_code=200, content={})


@router.post("/wallets/{holder_id}/requests", tags=["Wallets"])
async def request_credential(holder_id: str, request_body: BlindCredentialRequest):
    """"""
    request_body = request_body.model_dump()

    cred_def_id = request_body.get("verificationMethod").split("#")[-1]
    cred_def = await askar.fetch("credentialDefinition", cred_def_id)

    if not cred_def:
        raise HTTPException(status_code=404, detail="No credential definition.")

    link_secret = anoncreds.create_scalar(holder_id)

    blind_claims, cred_request, blinder = anoncreds.credential_request(
        cred_def, {"linkSecret": {"Scalar": {"value": link_secret}}}
    )

    return JSONResponse(
        status_code=201,
        content={
            "blinder": blinder,
            "blindClaims": blind_claims,
            "requestProof": cred_request,
        },
    )


@router.post("/wallets/{holder_id}/credentials", tags=["Wallets"])
async def add_credential_to_wallet(
    holder_id: str, request_body: StoreCredentialRequest
):
    request_body = request_body.model_dump()
    credential = request_body.get("credential")
    options = request_body.get("options")
    cred_def_id = options.get("verificationMethod").split("#")[-1]

    askar = AskarStorage()
    cred_def = await askar.fetch("credentialDefinition", cred_def_id)
    if not cred_def:
        raise HTTPException(status_code=404, detail="No credential definition.")

    anoncreds = AnonCredsV2()
    if credential.get("revocation_label"):
        credential = anoncreds.unblind_credential(
            blinder=options.get("blinder"),
            blind_bundle={"credential": credential, "issuer": cred_def},
            blind_claims={
                "linkSecret": {"Scalar": {"value": anoncreds.create_scalar(holder_id)}}
            },
        )

    wallet = await askar.fetch("wallet", holder_id)
    if not wallet and wallet != []:
        wallet = []
        await askar.store("wallet", holder_id, wallet)

    credential["verificationMethod"] = options.get("verificationMethod")
    await askar.append("wallet", holder_id, credential)

    return JSONResponse(status_code=200, content={})


@router.post("/wallets/{holder_id}/presentations", tags=["Wallets"])
async def create_presentation(holder_id: str, request_body: CreatePresentationRequest):
    request_body = request_body.model_dump()
    challenge = request_body.get("challenge")
    pres_schema_id = request_body.get("presSchemaId")

    wallet = await askar.fetch("wallet", holder_id)
    if not wallet:
        raise HTTPException(status_code=404, detail="No wallet found.")

    pres_req = await askar.fetch("presentationSchema", pres_schema_id)
    credentials = {}
    for statement_id, statement in pres_req.get("statements").items():
        if statement.get("Signature"):
            cred_match = next(
                (
                    cred
                    for cred in wallet
                    if cred.get("verificationMethod")
                    == statement.get("Signature").get("issuer").get("id")
                ),
                None,
            )
            credentials[statement.get("Signature").get("id")] = {
                "Signature": cred_match
            }

    presentation = anoncreds.create_presentation(pres_req, credentials, challenge)

    return JSONResponse(status_code=201, content={"presentation": presentation})
