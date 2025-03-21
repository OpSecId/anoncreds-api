"""AnonCreds v2 resource creation."""

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse

from app.models.web_requests import NewCredSchema, NewPresSchema
from app.plugins import AskarStorage, AnonCredsV2
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
