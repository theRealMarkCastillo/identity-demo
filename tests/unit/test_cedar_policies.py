"""Unit tests for Cedar policy logic.

Two layers:
  - Pure Cedar tests (test_cedar_*.py): no DB, no stack. Parse .cedar files
    from the repo and run is_authorized() against fixture entities.
  - Engine integration tests (test_cedar_engine.py): boot the engine against
    the live stack and verify behavior end-to-end.

The pure tests act as the 'policy lint' that CI runs without docker compose.
"""
import json
import pathlib
import sys
from pathlib import Path

import cedarpy
import pytest

# Make the control-plane's `app` package importable without booting it.
# Same trick as tests/test_masking.py:172-192.
_CP_ROOT = Path(__file__).resolve().parent.parent.parent / "control-plane"
_APP_PKG = _CP_ROOT / "app"
if str(_CP_ROOT) not in sys.path:
    sys.path.insert(0, str(_CP_ROOT))
import types  # noqa: E402
if "app" not in sys.modules:
    _fake_app = types.ModuleType("app")
    _fake_app.__path__ = [str(_APP_PKG)]
    sys.modules["app"] = _fake_app
if "app.db" not in sys.modules:
    _fake_db = types.ModuleType("app.db")
    def _fake_get_pool(): raise RuntimeError("not used in unit tests")
    _fake_db.get_pool = _fake_get_pool
    sys.modules["app.db"] = _fake_db
if "app.config" not in sys.modules:
    _fake_config = types.ModuleType("app.config")
    class _FakeConfig:
        pass
    _fake_config.config = _FakeConfig()
    sys.modules["app.config"] = _fake_config
# Now we can import cedar_engine
from app.services.cedar_engine import CedarEngine  # noqa: E402


POLICIES_DIR = Path(__file__).resolve().parent.parent.parent / "control-plane" / "policies"


# ---- fixtures -------------------------------------------------------------

@pytest.fixture(scope="module")
def token_issuance_policies():
    """Parse the token_issuance.cedar file at module load."""
    text = (POLICIES_DIR / "token_issuance.cedar").read_text()
    return cedarpy.PolicySet.from_str(text)


@pytest.fixture(scope="module")
def masking_compare_policies():
    """Parse the masking_compare.cedar file at module load."""
    text = (POLICIES_DIR / "masking_compare.cedar").read_text()
    return cedarpy.PolicySet.from_str(text)


def _entities(*defs) -> cedarpy.Entities:
    return cedarpy.Entities.from_json_str(json.dumps(list(defs)))


def _is_authorized(ps, entities, principal_id, action_id, resource_id,
                   principal_type="User", resource_type="User",
                   grant_type=None, requested_scopes=None,
                   subject_scopes=None, client_type=None):
    """Build a TokenRequest resource entity on the fly and call is_authorized."""
    requested = requested_scopes if requested_scopes is not None else []
    subject = subject_scopes if subject_scopes is not None else []
    token_req = {
        "uid": {"type": "TokenRequest", "id": resource_id},
        "attrs": {
            "grant_type": grant_type or "authorization_code",
            "requested_scopes": requested,
            "subject_scopes": subject,
            "client_type": client_type or "user_app",
        },
        "parents": [],
    }
    ents = _entities(
        {"uid": {"type": principal_type, "id": principal_id},
         "attrs": _user_attrs(principal_id),
         "parents": []},
        token_req,
    )
    req = {
        "principal": {"type": principal_type, "id": principal_id},
        "action": {"type": "Action", "id": action_id},
        "resource": {"type": "TokenRequest", "id": resource_id},
    }
    return cedarpy.is_authorized(req, ps, ents).allowed


def _user_attrs(user_id: str) -> dict:
    """Return the role + scopes fixture attrs for a known test user."""
    fixtures = {
        "user_123": ("senior_analyst",
                     ["read:transactions", "read:transactions.full", "write:transactions"]),
        "user_456": ("junior_analyst", ["read:transactions"]),
        "user_789": ("auditor", ["read:transactions"]),
    }
    role, scopes = fixtures[user_id]
    return {"role": role, "scopes": scopes}


def _agent_attrs(agent_id: str) -> dict:
    fixtures = {
        "agent_copilot_99": (True,
                             ["read:transactions", "read:transactions.full"],
                             ["read:transactions"]),
        "agent_etl_nightly": (False,
                               ["read:transactions"],
                               ["read:transactions"]),
    }
    delegatable, defaults, allowed = fixtures[agent_id]
    return {"is_delegatable": delegatable,
            "default_scopes": defaults,
            "allowed_scopes": allowed}


# ---- token_issuance policy tests -----------------------------------------

class TestTokenIssuanceHumans:
    """Tests for the authorization_code + refresh_token permit rule (User)."""

    def test_senior_with_full_scope_allowed(self, token_issuance_policies):
        allowed = _is_authorized(
            token_issuance_policies, None, "user_123", "IssueToken", "r1",
            principal_type="User",
            grant_type="authorization_code",
            requested_scopes=["read:transactions.full"],
        )
        assert allowed is True

    def test_junior_with_write_scope_denied(self, token_issuance_policies):
        allowed = _is_authorized(
            token_issuance_policies, None, "user_456", "IssueToken", "r2",
            grant_type="authorization_code",
            requested_scopes=["write:transactions"],
        )
        assert allowed is False

    def test_junior_with_read_scope_allowed(self, token_issuance_policies):
        allowed = _is_authorized(
            token_issuance_policies, None, "user_456", "IssueToken", "r3",
            grant_type="authorization_code",
            requested_scopes=["read:transactions"],
        )
        assert allowed is True

    def test_junior_empty_request_allowed(self, token_issuance_policies):
        allowed = _is_authorized(
            token_issuance_policies, None, "user_456", "IssueToken", "r4",
            grant_type="authorization_code",
            requested_scopes=[],
        )
        assert allowed is True

    def test_senior_refresh_token_allowed(self, token_issuance_policies):
        allowed = _is_authorized(
            token_issuance_policies, None, "user_123", "IssueToken", "r5",
            grant_type="refresh_token",
            requested_scopes=["read:transactions"],
        )
        assert allowed is True


class TestTokenIssuanceDelegatedAgents:
    """Tests for the token_exchange permit rule (delegated Agent)."""

    def test_delegatable_agent_with_matching_subject_scope_allowed(self, token_issuance_policies):
        ps = token_issuance_policies
        ents = _entities(
            {"uid": {"type": "Agent", "id": "agent_copilot_99"},
             "attrs": _agent_attrs("agent_copilot_99"), "parents": []},
            {"uid": {"type": "TokenRequest", "id": "r6"},
             "attrs": {"grant_type": "token_exchange", "requested_scopes": [],
                       "subject_scopes": ["read:transactions.full"],
                       "client_type": "user_app"}, "parents": []},
        )
        result = cedarpy.is_authorized(
            {"principal": {"type": "Agent", "id": "agent_copilot_99"},
             "action": {"type": "Action", "id": "IssueToken"},
             "resource": {"type": "TokenRequest", "id": "r6"}},
            ps, ents,
        )
        assert result.allowed is True

    def test_non_delegatable_agent_denied(self, token_issuance_policies):
        ps = token_issuance_policies
        ents = _entities(
            {"uid": {"type": "Agent", "id": "agent_etl_nightly"},
             "attrs": _agent_attrs("agent_etl_nightly"), "parents": []},
            {"uid": {"type": "TokenRequest", "id": "r7"},
             "attrs": {"grant_type": "token_exchange", "requested_scopes": [],
                       "subject_scopes": ["read:transactions"],
                       "client_type": "user_app"}, "parents": []},
        )
        result = cedarpy.is_authorized(
            {"principal": {"type": "Agent", "id": "agent_etl_nightly"},
             "action": {"type": "Action", "id": "IssueToken"},
             "resource": {"type": "TokenRequest", "id": "r7"}},
            ps, ents,
        )
        assert result.allowed is False

    def test_delegatable_agent_no_intersection_denied(self, token_issuance_policies):
        ps = token_issuance_policies
        ents = _entities(
            {"uid": {"type": "Agent", "id": "agent_copilot_99"},
             "attrs": _agent_attrs("agent_copilot_99"), "parents": []},
            {"uid": {"type": "TokenRequest", "id": "r8"},
             "attrs": {"grant_type": "token_exchange", "requested_scopes": [],
                       "subject_scopes": ["write:transactions"],
                       "client_type": "user_app"}, "parents": []},
        )
        result = cedarpy.is_authorized(
            {"principal": {"type": "Agent", "id": "agent_copilot_99"},
             "action": {"type": "Action", "id": "IssueToken"},
             "resource": {"type": "TokenRequest", "id": "r8"}},
            ps, ents,
        )
        assert result.allowed is False


class TestTokenIssuanceHeadlessAgents:
    """Tests for the client_credentials permit rule (headless Agent)."""

    def test_headless_agent_with_allowed_scope(self, token_issuance_policies):
        ps = token_issuance_policies
        ents = _entities(
            {"uid": {"type": "Agent", "id": "agent_etl_nightly"},
             "attrs": _agent_attrs("agent_etl_nightly"), "parents": []},
            {"uid": {"type": "TokenRequest", "id": "r9"},
             "attrs": {"grant_type": "client_credentials", "requested_scopes": ["read:transactions"],
                       "subject_scopes": [], "client_type": "agent"}, "parents": []},
        )
        result = cedarpy.is_authorized(
            {"principal": {"type": "Agent", "id": "agent_etl_nightly"},
             "action": {"type": "Action", "id": "IssueToken"},
             "resource": {"type": "TokenRequest", "id": "r9"}},
            ps, ents,
        )
        assert result.allowed is True

    def test_headless_agent_requesting_write_denied(self, token_issuance_policies):
        ps = token_issuance_policies
        ents = _entities(
            {"uid": {"type": "Agent", "id": "agent_etl_nightly"},
             "attrs": _agent_attrs("agent_etl_nightly"), "parents": []},
            {"uid": {"type": "TokenRequest", "id": "r10"},
             "attrs": {"grant_type": "client_credentials", "requested_scopes": ["write:transactions"],
                       "subject_scopes": [], "client_type": "agent"}, "parents": []},
        )
        result = cedarpy.is_authorized(
            {"principal": {"type": "Agent", "id": "agent_etl_nightly"},
             "action": {"type": "Action", "id": "IssueToken"},
             "resource": {"type": "TokenRequest", "id": "r10"}},
            ps, ents,
        )
        assert result.allowed is False

    def test_headless_agent_empty_request_allowed(self, token_issuance_policies):
        ps = token_issuance_policies
        ents = _entities(
            {"uid": {"type": "Agent", "id": "agent_etl_nightly"},
             "attrs": _agent_attrs("agent_etl_nightly"), "parents": []},
            {"uid": {"type": "TokenRequest", "id": "r11"},
             "attrs": {"grant_type": "client_credentials", "requested_scopes": [],
                       "subject_scopes": [], "client_type": "agent"}, "parents": []},
        )
        result = cedarpy.is_authorized(
            {"principal": {"type": "Agent", "id": "agent_etl_nightly"},
             "action": {"type": "Action", "id": "IssueToken"},
             "resource": {"type": "TokenRequest", "id": "r11"}},
            ps, ents,
        )
        assert result.allowed is True


# ---- masking_compare policy tests -----------------------------------------

class TestMaskingCompare:
    def test_senior_allowed(self, masking_compare_policies):
        ents = _entities(
            {"uid": {"type": "User", "id": "user_123"},
             "attrs": {"role": "senior_analyst"}, "parents": []},
        )
        result = cedarpy.is_authorized(
            {"principal": {"type": "User", "id": "user_123"},
             "action": {"type": "Action", "id": "ViewMaskingComparison"},
             "resource": {"type": "User", "id": "user_123"}},
            masking_compare_policies, ents,
        )
        assert result.allowed is True

    def test_junior_denied(self, masking_compare_policies):
        ents = _entities(
            {"uid": {"type": "User", "id": "user_456"},
             "attrs": {"role": "junior_analyst"}, "parents": []},
        )
        result = cedarpy.is_authorized(
            {"principal": {"type": "User", "id": "user_456"},
             "action": {"type": "Action", "id": "ViewMaskingComparison"},
             "resource": {"type": "User", "id": "user_456"}},
            masking_compare_policies, ents,
        )
        assert result.allowed is False

    def test_auditor_denied(self, masking_compare_policies):
        ents = _entities(
            {"uid": {"type": "User", "id": "user_789"},
             "attrs": {"role": "auditor"}, "parents": []},
        )
        result = cedarpy.is_authorized(
            {"principal": {"type": "User", "id": "user_789"},
             "action": {"type": "Action", "id": "ViewMaskingComparison"},
             "resource": {"type": "User", "id": "user_789"}},
            masking_compare_policies, ents,
        )
        assert result.allowed is False


# ---- validation ----------------------------------------------------------

class TestPolicyValidation:
    """Test that validate_policy_text catches common errors."""

    def test_valid_passes(self):
        from app.services.cedar_engine import CedarEngine
        engine = CedarEngine()
        v = engine.validate_policy_text('permit(principal, action, resource);')
        assert v["valid"] is True
        assert v["policy_count"] == 1

    def test_invalid_rejected(self):
        from app.services.cedar_engine import CedarEngine
        engine = CedarEngine()
        v = engine.validate_policy_text('this is not valid cedar')
        assert v["valid"] is False
        assert len(v["errors"]) > 0


# ---- preview sandbox -----------------------------------------------------

class TestPreview:
    """The preview endpoint should parse + evaluate without persisting."""

    def test_preview_with_loaded_policy(self):
        from app.services.cedar_engine import CedarEngine
        engine = CedarEngine()
        policy_text = '''
            permit(principal is User, action == Action::"test", resource)
            when { principal.role == "senior_analyst" };
        '''
        result = engine.preview(
            policy_text=policy_text,
            entities_json=json.dumps([
                {"uid": {"type": "User", "id": "u1"},
                 "attrs": {"role": "senior_analyst"}, "parents": []},
            ]),
            request={
                "principal": {"type": "User", "id": "u1"},
                "action": {"type": "Action", "id": "test"},
                "resource": {"type": "Resource", "id": "r1"},
            },
        )
        assert result["valid"] is True
        assert result["allowed"] is True

    def test_preview_invalid_policy_returns_errors(self):
        from app.services.cedar_engine import CedarEngine
        engine = CedarEngine()
        result = engine.preview(
            policy_text='bad cedar',
            entities_json="[]",
            request={"principal": {"type": "User", "id": "u1"},
                     "action": {"type": "Action", "id": "test"},
                     "resource": {"type": "Resource", "id": "r1"}},
        )
        assert result["valid"] is False
        assert len(result["errors"]) > 0
        assert result["allowed"] is False