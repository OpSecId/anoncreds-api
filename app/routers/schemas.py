from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from app.plugins import AskarStorage, AnonCredsV2
from app.models.web_requests import (
    NewCredSchema,
    NewPresSchema,
)

router = APIRouter(tags=["Schemas"])
askar = AskarStorage()
anoncreds = AnonCredsV2()

@router.post("/schemas/credentials")
async def new_credential_schema(request_body: NewCredSchema):
    request_body = request_body.model_dump()

    cred_schema = anoncreds.create_cred_schema(
        anoncreds.map_cred_schema(
            request_body.get("jsonSchema"), request_body.get("options")
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
async def get_credential_schema(cred_schema_id: str):
    cred_schema = await askar.fetch("credentialSchema", cred_schema_id)
    if not cred_schema:
        raise HTTPException(status_code=404, detail="No credential schema found.")
    return JSONResponse(status_code=200, content=cred_schema)


@router.post("/schemas/presentations")
async def new_presentation_schema(request_body: NewPresSchema):
    request_body = request_body.model_dump()

    queries = request_body.get("query")
    challenge = request_body.get("challenge")

    for query in queries:
        if query.get("type") == "SignatureQuery":
            verification_method_id = query.pop("verificationMethod").split("#")[-1]
            query["issuer"] = await askar.fetch(
                "credentialDefinition", verification_method_id
            )
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
async def get_presentation_schema(pres_schema_id: str):
    pres_schema = await askar.fetch("presentationSchema", pres_schema_id)
    if not pres_schema:
        raise HTTPException(status_code=404, detail="No presentation schema found.")
    return JSONResponse(status_code=200, content=pres_schema)
