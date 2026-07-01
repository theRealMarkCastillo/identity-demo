"""Test OAuth 2.1 flows: client_credentials, authorization_code, token_exchange, introspect, revoke."""
import base64
import hashlib
import secrets

import requests
from conftest import (
    CONTROL_PLANE,
    WEB_APP_CLIENT_SECRET,
    ETL_AGENT_SECRET,
    ORCHESTRATOR_AGENT_SECRET,
    SPECIALIST_AGENT_SECRET,
)


def test_health():
    r = requests.get(f"{CONTROL_PLANE}/health")
    assert r.status_code == 200
    assert r.json()["issuer"] == "identity-control-plane"


def test_jwks_endpoint():
    r = requests.get(f"{CONTROL_PLANE}/jwks.json")
    assert r.status_code == 200
    keys = r.json()["keys"]
    assert len(keys) == 1
    assert keys[0]["kid"] == "cp-1"
    assert keys[0]["alg"] == "RS256"


def test_client_credentials_happy_path():
    """agent_etl_nightly gets a token via Client Credentials."""
    r = requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=("agent_etl_nightly", ETL_AGENT_SECRET),
        data={"grant_type": "client_credentials", "scope": "read:transactions"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "Bearer"
    assert body["scope"] == "read:transactions"
    assert body["issued_token_type"] == "urn:ietf:params:oauth:token-type:jwt"
    assert "access_token" in body


def test_client_credentials_bad_secret():
    r = requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=("agent_etl_nightly", "wrong-secret"),
        data={"grant_type": "client_credentials", "scope": "read:transactions"},
    )
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_client"


def test_client_credentials_unknown_client():
    r = requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=("nonexistent", "anything"),
        data={"grant_type": "client_credentials", "scope": "read:transactions"},
    )
    assert r.status_code == 401


def test_client_credentials_write_scope_rejected():
    """Headless agent tries to get write scope - should be rejected."""
    r = requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=("agent_etl_nightly", ETL_AGENT_SECRET),
        data={"grant_type": "client_credentials", "scope": "write:transactions"},
    )
    # write:transactions is not in client.allowed_scopes for the agent
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_scope"


def test_authorization_code_full_flow():
    """user_123 logs in via Auth Code + PKCE and gets a token."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()

    # 1. POST credentials to /authorize
    r = requests.post(
        f"{CONTROL_PLANE}/authorize",
        data={
            "user_id": "user_123",
            "password": "pw123",
            "client_id": "web-app",
            "redirect_uri": "http://localhost:13000/callback",
            "scope": "read:transactions write:transactions",
            "state": "test123",
            "code_challenge": challenge,
        },
        allow_redirects=False,
    )
    assert r.status_code == 302
    location = r.headers["location"]
    assert "code=" in location
    assert "state=test123" in location
    code = location.split("code=")[1].split("&")[0]

    # 2. Exchange code for tokens
    r2 = requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=("web-app", WEB_APP_CLIENT_SECRET),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "http://localhost:13000/callback",
        },
    )
    assert r2.status_code == 200
    body = r2.json()
    assert body["scope"] == "read:transactions write:transactions"  # senior_analyst gets both
    assert "access_token" in body
    assert "refresh_token" in body


def test_authorization_code_bad_password():
    """Wrong password returns 401."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    r = requests.post(
        f"{CONTROL_PLANE}/authorize",
        data={
            "user_id": "user_123",
            "password": "wrong",
            "client_id": "web-app",
            "redirect_uri": "http://localhost:13000/callback",
            "scope": "read:transactions",
            "state": "x",
            "code_challenge": challenge,
        },
    )
    assert r.status_code == 401


def test_authorization_code_pkce_mismatch():
    """Tampered code_verifier fails PKCE check."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    r = requests.post(
        f"{CONTROL_PLANE}/authorize",
        data={
            "user_id": "user_123",
            "password": "pw123",
            "client_id": "web-app",
            "redirect_uri": "http://localhost:13000/callback",
            "scope": "read:transactions",
            "state": "x",
            "code_challenge": challenge,
        },
        allow_redirects=False,
    )
    code = r.headers["location"].split("code=")[1].split("&")[0]

    # Exchange with wrong verifier
    r2 = requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=("web-app", WEB_APP_CLIENT_SECRET),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": "wrong-verifier",
            "redirect_uri": "http://localhost:13000/callback",
        },
    )
    assert r2.status_code == 400
    assert r2.json()["error"] == "invalid_grant"


def test_junior_analyst_has_no_write_scope():
    """user_456 is junior_analyst - should not get write:transactions."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    r = requests.post(
        f"{CONTROL_PLANE}/authorize",
        data={
            "user_id": "user_456",
            "password": "pw123",
            "client_id": "web-app",
            "redirect_uri": "http://localhost:13000/callback",
            "scope": "read:transactions write:transactions",
            "state": "x",
            "code_challenge": challenge,
        },
        allow_redirects=False,
    )
    code = r.headers["location"].split("code=")[1].split("&")[0]
    r2 = requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=("web-app", WEB_APP_CLIENT_SECRET),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "http://localhost:13000/callback",
        },
    )
    body = r2.json()
    # junior_analyst only has read:transactions in role_scopes
    assert "write:transactions" not in body["scope"]
    assert "read:transactions" in body["scope"]


def test_token_exchange_downscopes():
    """Token exchange for a delegated agent should downscope the token."""
    # Get human token first
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    r = requests.post(
        f"{CONTROL_PLANE}/authorize",
        data={
            "user_id": "user_123",
            "password": "pw123",
            "client_id": "web-app",
            "redirect_uri": "http://localhost:13000/callback",
            "scope": "read:transactions write:transactions",
            "state": "x",
            "code_challenge": challenge,
        },
        allow_redirects=False,
    )
    code = r.headers["location"].split("code=")[1].split("&")[0]
    r2 = requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=("web-app", WEB_APP_CLIENT_SECRET),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "http://localhost:13000/callback",
        },
    )
    human_token = r2.json()["access_token"]

    # Exchange for agent token
    r3 = requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=("web-app", WEB_APP_CLIENT_SECRET),
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": human_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "audience": "target-api",
            "actor_token": "agent:agent_copilot_99",
            "actor_token_type": "urn:example:params:oauth:token-type:agent-id",
        },
    )
    assert r3.status_code == 200
    body = r3.json()
    # Scope is downscoped to read-only (agent's default scope is read only)
    assert body["scope"] == "read:transactions"
    assert "write:transactions" not in body["scope"]


def test_token_exchange_unknown_agent():
    r = requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=("web-app", WEB_APP_CLIENT_SECRET),
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "fake.jwt.token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "audience": "target-api",
            "actor_token": "agent:does_not_exist",
            "actor_token_type": "urn:example:params:oauth:token-type:agent-id",
        },
    )
    # Subject token is fake, so invalid_grant
    assert r.status_code == 400


def test_introspect_active_token():
    """Introspect a valid headless token."""
    # Get a token
    r = requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=("agent_etl_nightly", ETL_AGENT_SECRET),
        data={"grant_type": "client_credentials", "scope": "read:transactions"},
    )
    token = r.json()["access_token"]

    # Introspect
    r2 = requests.post(
        f"{CONTROL_PLANE}/oauth/introspect",
        auth=("agent_etl_nightly", ETL_AGENT_SECRET),
        data={"token": token},
    )
    assert r2.status_code == 200
    body = r2.json()
    assert body["active"] is True
    assert body["sub"] == "agent_etl_nightly"
    assert body["scope"] == "read:transactions"
    # No act claim for headless
    assert "act" not in body


def test_introspect_revoked_token():
    """Introspect returns active=false after revocation."""
    r = requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=("agent_etl_nightly", ETL_AGENT_SECRET),
        data={"grant_type": "client_credentials", "scope": "read:transactions"},
    )
    token = r.json()["access_token"]

    # Revoke
    requests.post(
        f"{CONTROL_PLANE}/oauth/revoke",
        auth=("agent_etl_nightly", ETL_AGENT_SECRET),
        data={"token": token},
    )

    # Introspect
    r2 = requests.post(
        f"{CONTROL_PLANE}/oauth/introspect",
        auth=("agent_etl_nightly", ETL_AGENT_SECRET),
        data={"token": token},
    )
    body = r2.json()
    assert body["active"] is False


def test_userinfo_for_human_token():
    """Userinfo returns role + scopes for a human user."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    r = requests.post(
        f"{CONTROL_PLANE}/authorize",
        data={
            "user_id": "user_123",
            "password": "pw123",
            "client_id": "web-app",
            "redirect_uri": "http://localhost:13000/callback",
            "scope": "read:transactions write:transactions",
            "state": "x",
            "code_challenge": challenge,
        },
        allow_redirects=False,
    )
    code = r.headers["location"].split("code=")[1].split("&")[0]
    r2 = requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=("web-app", WEB_APP_CLIENT_SECRET),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "http://localhost:13000/callback",
        },
    )
    token = r2.json()["access_token"]

    r3 = requests.get(
        f"{CONTROL_PLANE}/oauth/userinfo",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r3.status_code == 200
    body = r3.json()
    assert body["sub"] == "user_123"
    assert body["role"] == "senior_analyst"
    assert "read:transactions" in body["scopes"]
    assert "write:transactions" in body["scopes"]


def test_userinfo_for_delegated_token_shows_act():
    """Userinfo for a delegated token should show the act claim."""
    # Get human token
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    r = requests.post(
        f"{CONTROL_PLANE}/authorize",
        data={
            "user_id": "user_123",
            "password": "pw123",
            "client_id": "web-app",
            "redirect_uri": "http://localhost:13000/callback",
            "scope": "read:transactions write:transactions",
            "state": "x",
            "code_challenge": challenge,
        },
        allow_redirects=False,
    )
    code = r.headers["location"].split("code=")[1].split("&")[0]
    r2 = requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=("web-app", WEB_APP_CLIENT_SECRET),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "http://localhost:13000/callback",
        },
    )
    human_token = r2.json()["access_token"]

    # Exchange
    r3 = requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=("web-app", WEB_APP_CLIENT_SECRET),
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": human_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "audience": "target-api",
            "actor_token": "agent:agent_copilot_99",
            "actor_token_type": "urn:example:params:oauth:token-type:agent-id",
        },
    )
    agent_token = r3.json()["access_token"]

    r4 = requests.get(
        f"{CONTROL_PLANE}/oauth/userinfo",
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    body = r4.json()
    assert body["sub"] == "user_123"
    assert "act" in body
    assert body["act"]["sub"] == "agent_copilot_99"


def test_userinfo_no_token():
    r = requests.get(f"{CONTROL_PLANE}/oauth/userinfo")
    assert r.status_code == 401


def _get_human_token(user_id="user_123", password="pw123", scope="read:transactions write:transactions"):
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    r = requests.post(
        f"{CONTROL_PLANE}/authorize",
        data={
            "user_id": user_id,
            "password": password,
            "client_id": "web-app",
            "redirect_uri": "http://localhost:13000/callback",
            "scope": scope,
            "state": "x",
            "code_challenge": challenge,
        },
        allow_redirects=False,
    )
    code = r.headers["location"].split("code=")[1].split("&")[0]
    r2 = requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=("web-app", WEB_APP_CLIENT_SECRET),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "http://localhost:13000/callback",
        },
    )
    return r2.json()["access_token"]


def _exchange(subject_token, agent_id, auth):
    return requests.post(
        f"{CONTROL_PLANE}/oauth/token",
        auth=auth,
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "audience": "target-api",
            "actor_token": f"agent:{agent_id}",
            "actor_token_type": "urn:example:params:oauth:token-type:agent-id",
        },
    )


def test_three_hop_delegation_chain_nests_act():
    """user -> orchestrator_main -> research_specialist -> browser_browser_agent.

    Each hop is minted by whoever currently holds the authority: the
    web-app starts the chain, then each agent extends it using its own
    client credentials. The final act claim nests newest-actor-first.
    """
    human_token = _get_human_token()

    r1 = _exchange(human_token, "orchestrator_main", auth=("web-app", WEB_APP_CLIENT_SECRET))
    assert r1.status_code == 200
    hop1_token = r1.json()["access_token"]

    # orchestrator_main (using its own credentials) delegates further to
    # research_specialist, presenting hop1's token as the subject.
    r2 = _exchange(hop1_token, "research_specialist", auth=("orchestrator_main", ORCHESTRATOR_AGENT_SECRET))
    assert r2.status_code == 200
    hop2_token = r2.json()["access_token"]

    r3 = _exchange(hop2_token, "browser_browser_agent", auth=("research_specialist", SPECIALIST_AGENT_SECRET))
    assert r3.status_code == 200
    hop3_token = r3.json()["access_token"]

    # Inspect the final act chain via /oauth/userinfo (avoids hand-decoding
    # the JWT payload in the test itself).
    r4 = requests.get(
        f"{CONTROL_PLANE}/oauth/userinfo",
        headers={"Authorization": f"Bearer {hop3_token}"},
    )
    body = r4.json()
    assert body["sub"] == "user_123"  # root principal never changes across hops
    assert body["act"] == {
        "sub": "browser_browser_agent",
        "act": {
            "sub": "research_specialist",
            "act": {"sub": "orchestrator_main"},
        },
    }


def test_agent_cannot_extend_chain_it_is_not_the_actor_in():
    """Confused-deputy check: research_specialist can't hijack a chain where
    orchestrator_main is the current actor, even with valid credentials of
    its own -- an agent may only extend a chain it is CURRENTLY the actor in.
    """
    human_token = _get_human_token()
    hop1_token = _exchange(human_token, "orchestrator_main", auth=("web-app", WEB_APP_CLIENT_SECRET)).json()["access_token"]

    r2 = _exchange(hop1_token, "browser_browser_agent", auth=("research_specialist", SPECIALIST_AGENT_SECRET))
    assert r2.status_code == 400
    assert r2.json()["error"] == "unauthorized_client"


def test_delegation_depth_cap_enforced():
    """A chain longer than MAX_DELEGATION_DEPTH (4) is rejected."""
    human_token = _get_human_token()
    token = _exchange(human_token, "orchestrator_main", auth=("web-app", WEB_APP_CLIENT_SECRET)).json()["access_token"]
    token = _exchange(token, "research_specialist", auth=("orchestrator_main", ORCHESTRATOR_AGENT_SECRET)).json()["access_token"]
    token = _exchange(token, "browser_browser_agent", auth=("research_specialist", SPECIALIST_AGENT_SECRET)).json()["access_token"]
    # Chain is now 3 deep. A 4th hop is still within MAX_DELEGATION_DEPTH;
    # the web-app can always extend a chain regardless of current actor
    # (it's the trusted root of the OAuth flow), so use it to push to depth
    # 4, then depth 5, which must be rejected.
    hop4 = _exchange(token, "agent_copilot_99", auth=("web-app", WEB_APP_CLIENT_SECRET))
    assert hop4.status_code == 200
    hop4_token = hop4.json()["access_token"]
    hop5 = _exchange(hop4_token, "agent_etl_nightly", auth=("web-app", WEB_APP_CLIENT_SECRET))
    assert hop5.status_code == 400
    assert "max depth" in hop5.json()["error_description"]


def test_revoked_subject_token_cannot_be_exchanged():
    """RFC 7009 revocation must stop a token from being exchanged for a new
    delegated token, not just from being used directly -- otherwise
    revoking a compromised or unwanted grant doesn't stop new chain hops
    from being minted downstream of it.
    """
    human_token = _get_human_token()
    hop1 = _exchange(human_token, "orchestrator_main", auth=("web-app", WEB_APP_CLIENT_SECRET))
    assert hop1.status_code == 200
    hop1_token = hop1.json()["access_token"]

    requests.post(
        f"{CONTROL_PLANE}/oauth/revoke",
        auth=("web-app", WEB_APP_CLIENT_SECRET),
        data={"token": hop1_token},
    )

    r2 = _exchange(hop1_token, "research_specialist", auth=("orchestrator_main", ORCHESTRATOR_AGENT_SECRET))
    assert r2.status_code == 400
    assert r2.json()["error"] == "invalid_grant"
