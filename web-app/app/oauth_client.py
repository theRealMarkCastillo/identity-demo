"""OAuth client operations: PKCE, code exchange, token exchange, client credentials."""
import base64
import hashlib
import secrets

import httpx

from .config import config


def generate_pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def pkce_challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def build_authorize_url(state: str, code_challenge: str) -> str:
    # Use the PUBLIC URL (browser-reachable) for the redirect, not the internal Docker URL.
    # We request the `.full` variants alongside the base scopes. If the user's role
    # supports `.full` (senior_analyst), the effective scope will include it and the
    # umask will be 'raw'. If not (junior_analyst, auditor), the role mapping drops
    # `.full` at the token layer and umask stays 'masked'.
    params = {
        "response_type": "code",
        "client_id": config.CLIENT_ID,
        "redirect_uri": config.REDIRECT_URI,
        "scope": "read:transactions write:transactions read:transactions.full write:transactions.full",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{config.CP_PUBLIC_URL}/authorize?{qs}"


def exchange_code_for_tokens(code: str, code_verifier: str) -> dict:
    with httpx.Client() as client:
        r = client.post(
            f"{config.CONTROL_PLANE_URL}/oauth/token",
            auth=(config.CLIENT_ID, config.CLIENT_SECRET),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": code_verifier,
                "redirect_uri": config.REDIRECT_URI,
            },
            timeout=10.0,
        )
        r.raise_for_status()
        return r.json()


def exchange_for_agent_token(subject_jwt: str, agent_id: str) -> dict:
    """RFC 8693 token exchange: subject_token = human JWT, actor_token = agent:<id>"""
    with httpx.Client() as client:
        r = client.post(
            f"{config.CONTROL_PLANE_URL}/oauth/token",
            auth=(config.CLIENT_ID, config.CLIENT_SECRET),
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": subject_jwt,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "audience": "target-api",
                "actor_token": f"agent:{agent_id}",
                "actor_token_type": "urn:example:params:oauth:token-type:agent-id",
            },
            timeout=10.0,
        )
        r.raise_for_status()
        return r.json()


def get_client_credentials_token_for_headless() -> dict:
    """Authenticate as a headless agent via Client Credentials.
    The web-app does this on behalf of the demo button (in production, cli-agent
    would do this itself; we expose it via the web for one-click demo)."""
    with httpx.Client() as client:
        r = client.post(
            f"{config.CONTROL_PLANE_URL}/oauth/token",
            auth=("agent_etl_nightly", "agent_etl_secret_change_me"),
            data={
                "grant_type": "client_credentials",
                "scope": "read:transactions",
            },
            timeout=10.0,
        )
        r.raise_for_status()
        return r.json()


def revoke_token(token: str) -> None:
    with httpx.Client() as client:
        r = client.post(
            f"{config.CONTROL_PLANE_URL}/oauth/revoke",
            auth=(config.CLIENT_ID, config.CLIENT_SECRET),
            data={"token": token},
            timeout=10.0,
        )
        r.raise_for_status()
