from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import JSONResponse

from app.routers import schemas, issuers, wallets, utilities, vc_api, verifiers

from config import settings

app = FastAPI(title=settings.APP_TITLE, version=settings.APP_VERSION)

api_router = APIRouter()


@api_router.get("/server/status", tags=["Server"], include_in_schema=False)
async def server_status():
    """Server status endpoint."""
    return JSONResponse(status_code=200, content={"status": "ok"})


api_router.include_router(schemas.router)
api_router.include_router(issuers.router)
api_router.include_router(wallets.router)
api_router.include_router(verifiers.router)
# api_router.include_router(vc_api.router)
api_router.include_router(utilities.router, prefix="/utilities")

app.include_router(api_router)
