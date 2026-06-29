"""UI routes: login, callback, dashboard."""
import json
import secrets
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from .. import db
from .. import jwt_verify
from .. import oauth_client
from ..config import config
from ..db import run_with_identity
from ..session import (
    CSRF_COOKIE,
    CSRF_FIELD,
    SESSION_COOKIE,
    create_csrf_token,
    create_session,
    load_session,
    set_session_cookie,
    verify_csrf,
)
from ..tools import call_tool

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _set_session_cookie(response: Response, data: dict):
    cookie = create_session(data)
    response.set_cookie(
        SESSION_COOKIE, cookie,
        max_age=8*3600, httponly=True, samesite="lax", path="/",
    )


def _set_csrf_cookie(response: Response):
    token = create_csrf_token()
    response.set_cookie(
        CSRF_COOKIE, token,
        max_age=8*3600, httponly=False, samesite="lax", path="/",
    )
    token = create_csrf_token()
    response.set_cookie(
        CSRF_COOKIE, token,
        max_age=8*3600, httponly=False, samesite="lax", path="/",
    )


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    sess = load_session(request)
    if "tokens" in sess:
        return RedirectResponse(url="/dashboard", status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    # Generate the CSRF token once, put it in BOTH the cookie and the form
    csrf_token = create_csrf_token()
    response = templates.TemplateResponse("login.html", {"request": request, "csrf_token": csrf_token})
    response.set_cookie(
        CSRF_COOKIE, csrf_token,
        max_age=8*3600, httponly=False, samesite="lax", path="/",
    )
    return response


@router.post("/login", response_class=HTMLResponse)
def login_start(request: Request, csrf_token: str = Form(...)):
    verify_csrf(request, csrf_token)
    state = secrets.token_urlsafe(16)
    code_verifier = oauth_client.generate_pkce_verifier()
    code_challenge = oauth_client.pkce_challenge_s256(code_verifier)
    authorize_url = oauth_client.build_authorize_url(state, code_challenge)

    response = RedirectResponse(url=authorize_url, status_code=302)
    _set_session_cookie(response, {
        "oauth_state": state,
        "pkce_verifier": code_verifier,
    })
    return response


@router.get("/callback", response_class=HTMLResponse)
def callback(request: Request, code: str, state: str):
    sess = load_session(request)
    expected_state = sess.get("oauth_state")
    code_verifier = sess.get("pkce_verifier")

    if not expected_state or expected_state != state:
        raise HTTPException(status_code=400, detail="state mismatch")
    if not code_verifier:
        raise HTTPException(status_code=400, detail="no pkce verifier in session")

    try:
        tokens = oauth_client.exchange_code_for_tokens(code, code_verifier)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"token exchange failed: {e}")

    # Merge tokens into session
    sess.update({
        "tokens": {
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token"),
            "scope": tokens.get("scope"),
            "expires_in": tokens.get("expires_in"),
        },
        "agent_tokens": {},  # populated when copilot actions are taken
    })

    response = RedirectResponse(url="/dashboard", status_code=302)
    _set_session_cookie(response, sess)
    _set_csrf_cookie(response)
    return response


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    sess = load_session(request)
    if "tokens" not in sess:
        return RedirectResponse(url="/login", status_code=302)

    access_token = sess["tokens"]["access_token"]
    try:
        user_claims = jwt_verify.decode_unverified(access_token)
    except Exception:
        return RedirectResponse(url="/login", status_code=302)

    # Generate a fresh CSRF token; use it in BOTH the cookie and the template
    csrf_token = create_csrf_token()
    response = templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user_claims,
            "human_jwt": access_token,
            "agent_jwt": sess.get("agent_token"),
            "csrf_token": csrf_token,
        },
    )
    response.set_cookie(
        CSRF_COOKIE, csrf_token,
        max_age=8*3600, httponly=False, samesite="lax", path="/",
    )
    return response


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    verify_csrf(request, csrf_token)
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(SESSION_COOKIE)
    return response
