"""Authorization Code endpoint with login form (GET /authorize, POST /authorize)."""
import urllib.parse
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..config import config
from ..services import users, clients
from ..services.codes import create_code
from ..jwt_utils import generate_pkce_verifier, pkce_challenge_s256

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/authorize", response_class=HTMLResponse)
async def authorize_get(
    request: Request,
    response_type: str = "code",
    client_id: str = "",
    redirect_uri: str = "",
    scope: str = "",
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "",
):
    if response_type != "code":
        return HTMLResponse("unsupported_response_type", status_code=400)
    if not client_id or not redirect_uri or not code_challenge:
        return HTMLResponse("invalid_request", status_code=400)
    if code_challenge_method != "S256":
        return HTMLResponse("unsupported PKCE method (must be S256)", status_code=400)

    client = clients.get_client(client_id)
    if client is None or client["client_type"] != "user_app":
        return HTMLResponse("unknown client", status_code=400)
    if redirect_uri not in (client.get("redirect_uris") or []):
        return HTMLResponse("redirect_uri not registered", status_code=400)

    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
        },
    )


@router.post("/authorize", response_class=HTMLResponse)
async def authorize_post(
    request: Request,
    user_id: str = Form(...),
    password: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(""),
    state: str = Form(""),
    code_challenge: str = Form(...),
):
    user = users.verify_user(user_id, password)
    if user is None:
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Invalid credentials",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "state": state,
                "code_challenge": code_challenge,
            },
            status_code=401,
        )

    requested_scopes = [s for s in scope.split() if s] if scope else []
    code = create_code(
        client_id=client_id,
        user_id=user["user_id"],
        redirect_uri=redirect_uri,
        scope=requested_scopes,
        code_challenge=code_challenge,
        ttl_seconds=config.AUTH_CODE_TTL_SECONDS,
    )

    redirect_params = {"code": code}
    if state:
        redirect_params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    target = f"{redirect_uri}{sep}{urllib.parse.urlencode(redirect_params)}"
    return RedirectResponse(url=target, status_code=302)
