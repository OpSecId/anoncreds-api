from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import JSONResponse

from app.routers import resources, utilities, vc_api, operations
from app.plugins import AskarStorage

from config import settings

app = FastAPI(title=settings.APP_TITLE, version=settings.APP_VERSION)

api_router = APIRouter()


@api_router.get("/server/status", tags=["Server"], include_in_schema=False)
async def server_status():
    """Server status endpoint."""
    return JSONResponse(status_code=200, content={"status": "ok"})

@api_router.get("/issuers/{issuer_id}/did.json", include_in_schema=False)
async def resolve_issuer_did(issuer_id: str = 'demo'):
    """Server status endpoint."""
    askar = AskarStorage()
    did_document = await askar.fetch('didDocument', issuer_id)
    if not did_document:
        raise HTTPException(status_code=404, detail="No issuer found.")
    return JSONResponse(status_code=200, content=did_document)


api_router.include_router(resources.router, prefix="/resources")
api_router.include_router(operations.router, prefix="/operations")
# api_router.include_router(vc_api.router)
api_router.include_router(utilities.router, prefix="/utilities")

app.include_router(api_router)
