"""Cedar policy engine wrapper.

Loads Cedar policies from platform.cedar_policies at startup and on explicit
reload. Builds User + Agent entities from platform.* via entity_builder. The
engine is a module-level singleton initialized in main.py.

API:
  engine.load_from_db()           - rebuild PolicySet from DB
  engine.load_entities_from_db()  - rebuild base Entities from DB
  engine.decide(...)              - call is_authorized with a per-request delta
  engine.validate_policy_text()   - parse check (UI preview-before-save)
  engine.preview(...)             - dry-run with arbitrary inputs (UI sandbox)
"""
from __future__ import annotations

import json
import logging

import cedarpy

from ..db import get_pool
from . import entity_builder

log = logging.getLogger("control-plane.cedar")

_engine: "CedarEngine | None" = None


class CedarEngine:
    def __init__(self):
        self._policy_set: cedarpy.PolicySet | None = None
        self._base_entities: cedarpy.Entities | None = None
        self._enabled_count: int = 0

    # -- loading ------------------------------------------------------------

    def load_from_db(self) -> dict:
        """Build PolicySet from enabled rows in platform.cedar_policies.

        Returns {ok, count, errors}.
        Raises ValueError on parse failure (caller decides whether to crash).
        """
        with get_pool().connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT policy_id, policy_text
                       FROM platform.cedar_policies
                       WHERE enabled = TRUE
                       ORDER BY policy_id"""
                )
                rows = cur.fetchall()
        if not rows:
            log.warning("platform.cedar_policies has no enabled rows; "
                        "is_authorized() will deny everything")
        combined = "\n\n".join(r[1] for r in rows)
        try:
            self._policy_set = cedarpy.PolicySet.from_str(combined)
        except ValueError as e:
            errors = [str(line) for line in str(e).splitlines() if line.strip()]
            return {"ok": False, "count": 0, "errors": errors}
        self._enabled_count = len(rows)
        log.info(f"Cedar: loaded {len(rows)} policy row(s), parsed {len(self._policy_set)} policies")
        return {"ok": True, "count": len(rows), "errors": []}

    def load_entities_from_db(self) -> dict:
        """Build base Entities (Users + Agents) from platform.* tables."""
        entities_list = entity_builder.build_all()
        json_str = json.dumps(entities_list)
        self._base_entities = cedarpy.Entities.from_json_str(json_str)
        users = sum(1 for e in entities_list if e["uid"]["type"] == "User")
        agents = sum(1 for e in entities_list if e["uid"]["type"] == "Agent")
        log.info(f"Cedar: loaded {len(entities_list)} entities "
                 f"({users} users, {agents} agents)")
        return {"count": len(entities_list)}

    def reload(self) -> dict:
        """Reload both policies and entities from DB."""
        load_result = self.load_from_db()
        if not load_result["ok"]:
            return load_result
        ent_result = self.load_entities_from_db()
        return {**load_result, "entities": ent_result["count"]}

    # -- decisions ----------------------------------------------------------

    def decide(
        self,
        action: str,
        principal_uid: str,
        resource_uid: str,
        extra_entities_json: str | None = None,
        context: dict | None = None,
    ) -> cedarpy.AuthzResult:
        """Evaluate is_authorized with optional per-request entity delta.

        principal_uid / resource_uid are Cedar surface-syntax strings like
        'User::"user_123"' OR dicts like {'type': 'User', 'id': 'user_123'}.

        extra_entities_json is a JSON list of Cedar entity dicts (e.g., a
        per-request TokenRequest). Appended to the base entity set via
        with_added_json_str() so the base handle isn't reparsed.
        """
        if self._policy_set is None or self._base_entities is None:
            raise RuntimeError("Cedar engine not initialized; call load_from_db() first")

        entities = self._base_entities
        if extra_entities_json:
            entities = entities.with_added_json_str(extra_entities_json)

        request: dict = {
            "principal": _to_uid_dict(principal_uid),
            "action": {"type": "Action", "id": action},
            "resource": _to_uid_dict(resource_uid),
        }
        if context is not None:
            request["context"] = context

        return cedarpy.is_authorized(request, self._policy_set, entities)

    # -- validation / preview (used by admin_policies router) --------------

    def validate_policy_text(self, text: str) -> dict:
        """Try parsing the policy text. Return {valid, errors, policy_count}.

        Does not require the engine to be loaded -- safe to call from the UI
        before any DB activity.
        """
        try:
            ps = cedarpy.PolicySet.from_str(text)
            return {"valid": True, "errors": [], "policy_count": len(ps)}
        except ValueError as e:
            errors = [line for line in str(e).splitlines() if line.strip()]
            return {"valid": False, "errors": errors, "policy_count": 0}

    def preview(
        self,
        policy_text: str,
        entities_json: str,
        request: dict,
    ) -> dict:
        """Dry-run: parse + evaluate arbitrary inputs.

        Used by the UI's 'Preview' sandbox to test a draft policy against
        sample entities + a sample request without persisting anything.

        Returns {valid, allowed, errors, reasons, diagnostics}.
        """
        try:
            ps = cedarpy.PolicySet.from_str(policy_text)
        except ValueError as e:
            return {
                "valid": False,
                "errors": [line for line in str(e).splitlines() if line.strip()],
                "allowed": False,
                "reasons": [],
            }
        try:
            entities = cedarpy.Entities.from_json_str(entities_json)
        except (ValueError, json.JSONDecodeError) as e:
            return {
                "valid": True,
                "entities_parse_error": str(e),
                "allowed": False,
                "errors": [f"entities parse failed: {e}"],
                "reasons": [],
            }
        result = cedarpy.is_authorized(request, ps, entities)
        return {
            "valid": True,
            "allowed": result.allowed,
            "errors": list(result.diagnostics.errors or []),
            "reasons": list(result.diagnostics.reasons or []),
        }

    # -- introspection ------------------------------------------------------

    @property
    def enabled_count(self) -> int:
        return self._enabled_count


# -- module-level singleton ------------------------------------------------

def get_engine() -> CedarEngine:
    global _engine
    if _engine is None:
        _engine = CedarEngine()
    return _engine


def _to_uid_dict(uid: str | dict) -> dict:
    """Accept either a Cedar surface-syntax string ('User::"alice"') or a
    pre-built dict ({'type': 'User', 'id': 'alice'}). Return the dict form.
    """
    if isinstance(uid, dict):
        return uid
    # Parse "Type::\"id\"" -- type is unquoted before ::, id is quoted with "
    if "::" not in uid:
        raise ValueError(f"invalid Cedar UID: {uid!r}")
    type_part, id_part = uid.split("::", 1)
    if id_part.startswith('"') and id_part.endswith('"'):
        id_part = id_part[1:-1]
    return {"type": type_part, "id": id_part}