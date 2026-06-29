"""Control Plane - OAuth 2.1 + RFC 8693 Authorization Server."""
import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .config import config
from .db import get_pool, close_pool
from .routes import jwks, authorize, token, userinfo, introspect

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("control-plane")

app = FastAPI(
    title="Identity Demo - Control Plane",
    description="OAuth 2.1 + RFC 8693 Authorization Server",
    version="1.0.0",
)


# OAuth 2.1 spec requires error responses to be flat JSON: {"error": "...", "error_description": "..."}
# FastAPI's default HTTPException wraps in {"detail": ...}; override for OAuth endpoints.
@app.exception_handler(HTTPException)
async def oauth_exception_handler(request: Request, exc: HTTPException):
    detail = exc.detail
    if isinstance(detail, dict) and "error" in detail:
        # Already in OAuth format
        return JSONResponse(status_code=exc.status_code, content=detail)
    return JSONResponse(status_code=exc.status_code, content={"detail": detail})


app.include_router(jwks.router)
app.include_router(authorize.router)
app.include_router(token.router)
app.include_router(userinfo.router)
app.include_router(introspect.router)


@app.on_event("startup")
async def startup():
    log.info(f"Control Plane starting; issuer={config.ISSUER} audience={config.AUDIENCE}")
    # Force pool init (validates DB connection)
    pool = get_pool()
    pool.wait(timeout=10)
    log.info("DB pool ready")


@app.on_event("shutdown")
async def shutdown():
    close_pool()


@app.get("/health")
def health():
    return {"status": "ok", "issuer": config.ISSUER}
