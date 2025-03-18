from fastapi import APIRouter, FastAPI
from fastapi.responses import JSONResponse

from app.routers import issuer, holder, verifier, resources, utilities

from config import settings

app = FastAPI(title=settings.APP_TITLE, version=settings.APP_VERSION)

api_router = APIRouter()

@api_router.get("/server/status", tags=["Server"], include_in_schema=False)
async def server_status():
    """Server status endpoint."""
    return JSONResponse(status_code=200, content={"status": "ok"})

api_router.include_router(issuer.router)
api_router.include_router(holder.router)
api_router.include_router(verifier.router)
api_router.include_router(resources.router, prefix="/resources")
api_router.include_router(utilities.router, prefix="/utilities")

app.include_router(api_router)