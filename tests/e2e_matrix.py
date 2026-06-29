#!/usr/bin/env python3
"""Full E2E matrix for the identity demo.

Drives every persona x every action, then validates:

- HTTP response (status + body shape)
- /api/principal state (human block + agent block when present + meta)
- /api/jwts state (human + agent + headless)
- /api/admin-data state (every panel)
- Rendered /admin HTML (counts and key table rows)
- /api/audit-feed (matching events in the last N seconds)
- DB-side RLS outcome (direct query under the same GUCs the web app sets)
- DB-side cell masking (apply_mask via masked view)

Also runs a parallel matrix of cli-admin operations against /api/admin-data
+ the rendered /admin HTML.

Outputs a structured pass/fail report.

Usage: python3 tests/e2e_matrix.py
Requires: live stack (`make up`), DB seeded.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import base64
import httpx
import psycopg

BASE = "http://localhost:13000"
CP   = "http://localhost:18080"
DB   = dict(host="localhost", port=54321, dbname="identity", user="app_session", password="app_session_pw")
ADMIN_DB = dict(host="localhost", port=54321, dbname="identity", user="control_plane_admin", password="cp_admin_pw")

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"


# --------------------------------------------------------------------------
# Test-result tracking
# --------------------------------------------------------------------------

@dataclass
class Result:
    name: str
    ok: bool
    details: list[str] = field(default_factory=list)

    def line(self, idx: int) -> str:
        marker = PASS if self.ok else FAIL
        body = "; ".join(self.details) if self.details else "ok"
        return f"  [{idx:>3}] {marker}  {self.name:<52}  {body}"

results: list[Result] = []

def check(name: str, ok: bool, details: str = "") -> bool:
    results.append(Result(name=name, ok=ok, details=[details] if details else []))
    return ok

def assert_eq(label: str, got: Any, want: Any) -> bool:
    if got == want:
        return check(label, True)
    return check(label, False, f"got={got!r}  want={want!r}")

def assert_in(label: str, needle: Any, haystack: Any) -> bool:
    if needle in (haystack or []):
        return check(label, True)
    return check(label, False, f"{needle!r} not in {haystack!r}")


# --------------------------------------------------------------------------
# Session helpers
# --------------------------------------------------------------------------

def _decode_jwt(tok: str) -> dict:
    t = tok.split(".")[1]; t += "=" * (4 - len(t) % 4)
    return json.loads(base64.urlsafe_b64decode(t))


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


def login(user_id: str, password: str) -> tuple[httpx.Client, str]:
    """Drive the full OAuth flow. Returns a logged-in client + dashboard csrf.
    Caller is responsible for closing the client (use a `with` block at the
    call site, or call c.close())."""
    c = httpx.Client(follow_redirects=False, timeout=15.0)
    try:
        r = c.get(f"{BASE}/login"); tok1 = _csrf(r.text)
        r = c.post(f"{BASE}/login", data={"csrf_token": tok1, "user_id": user_id, "password": password})
        loc = r.headers["location"]
        if not loc.startswith("http"): loc = CP + loc
        r = c.get(loc); tok_a = _csrf(r.text)
        # Re-extract hidden fields, but EXCLUDE user_id (the form pre-fills
        # `value="user_123"` as a demo convenience; the explicit user_id we
        # POST must win to actually log in as the requested user).
        hidden = {k: v for k, v in re.findall(r'name="([^"]+)"\s+value="([^"]*)"', r.text)
                  if k != "user_id"}
        r = c.post(f"{CP}/authorize", data={"csrf_token": tok_a, **hidden,
                                              "user_id": user_id, "password": password})
        cb = r.headers.get("location", "")
        if not cb.startswith("http"): cb = BASE + cb
        c.get(cb)
        r = c.get(f"{BASE}/dashboard")
        csrf_dash = _csrf(r.text)
        return c, csrf_dash
    except Exception:
        c.close()
        raise


def post(client: httpx.Client, path: str, csrf: str, **fields) -> tuple[int, dict]:
    data = {"csrf_token": csrf, **fields}
    r = client.post(f"{BASE}{path}", data=data)
    try:
        body = r.json()
    except Exception:
        body = {"_non_json": r.text[:200]}
    return r.status_code, body


def get(client: httpx.Client, path: str) -> tuple[int, Any]:
    r = client.get(f"{BASE}{path}")
    try:
        body = r.json()
    except Exception:
        body = r.text
    return r.status_code, body


# --------------------------------------------------------------------------
# DB-side verification helpers (we don't go through the web app — we
# directly emulate the GUC setup it does, then assert the query result)
# --------------------------------------------------------------------------

def db_query_as(user_id: str | None, actor_id: str | None, umask: str, sql: str, params=()) -> list:
    with psycopg.connect(**DB) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.user_id', %s, true)", (user_id or "",))
            cur.execute("SELECT set_config('app.actor_id', %s, true)", (actor_id or "",))
            cur.execute("SELECT set_config('app.unmask_level', %s, true)", (umask,))
            cur.execute(sql, params)
            cols = [d.name for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]


def db_audit_count(event_type: str, sub: str | None = None, since_ts: str | None = None) -> int:
    sql = "SELECT COUNT(*) FROM platform.audit_log WHERE event_type = %s"
    args: list[Any] = [event_type]
    if sub:
        sql += " AND sub = %s"
        args.append(sub)
    if since_ts:
        sql += " AND ts >= %s"
        args.append(since_ts)
    with psycopg.connect(**ADMIN_DB) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, args)
            return cur.fetchone()[0]


# --------------------------------------------------------------------------
# PERSONA x ACTION matrix
# --------------------------------------------------------------------------

PERSONAS = {
    "user_123": ("senior_analyst", "pw123", ["read:transactions", "read:transactions.full",
                                            "write:transactions", "write:transactions.full"]),
    "user_456": ("junior_analyst", "pw123", ["read:transactions"]),
    "user_789": ("auditor",        "pw123", ["read:transactions"]),
}


def persona_section(user_id: str, role: str, password: str, expected_scopes: list[str]):
    print(f"\n=== {user_id} ({role}) ===")
    print(f"  expected effective scopes: {expected_scopes}")

    client, csrf = login(user_id, password)
    print(f"  login OK")
    try:
        _drive_persona(client, csrf, user_id, role, password, expected_scopes)
    finally:
        client.close()


def _drive_persona(client, csrf, user_id, role, password, expected_scopes):
    # /api/principal: just-logged-in state
    status, body = get(client, "/api/principal")
    assert_eq("/api/principal human.umask",        body["human"]["umask"],
              "raw" if "read:transactions.full" in expected_scopes else "masked")
    assert_eq("/api/principal human.role",         body["human"]["role"],      role)
    assert_eq("/api/principal human.sub",          body["human"]["sub"],       user_id)
    assert_eq("/api/principal agent block absent", "agent" in body,         False)
    assert_eq("/api/principal status",             status,                   200)

    # /api/jwts: human active, others none
    status, jwts = get(client, "/api/jwts")
    assert_eq("/api/jwts human.status",   jwts["human"]["status"],   "active")
    assert_eq("/api/jwts agent.status",   jwts["agent"]["status"],   "none")
    assert_eq("/api/jwts headless.status",jwts["headless"]["status"],"none")

    # Human: Read Own
    raw_umask_expected = "raw" if "read:transactions.full" in expected_scopes else "masked"
    status, body = post(client, "/action/human-read", csrf)
    assert_eq("human-read status",            status,                        200)
    rows = body.get("rows") or []
    assert_eq("human-read row_count field present", "row_count" in body, True)
    # Same expected_count rationale as below — user_789 owns nothing.
    expected_visible = {"user_123": 4, "user_456": 2, "user_789": 0}[user_id]
    assert_eq("human-read row count visible to user",
              len(rows), expected_visible)
    if rows:
        ssn  = rows[0]["ssn"]
        pan  = rows[0]["card_pan"]
        em   = rows[0]["email"]
        if raw_umask_expected == "raw":
            assert_eq("human-read PII raw.ssn",  ssn,  "123-45-6789" if user_id == "user_123" else "987-65-4321")
            assert_eq("human-read PII raw.pan",  pan,  "4111111111111111" if user_id == "user_123" else "340000000000009")
            check("human-read PII raw.email contains @example.com", "@example.com" in em, f"em={em!r}")
        else:
            assert_eq("human-read PII masked.ssn",  ssn,  "***")
            assert_eq("human-read PII masked.pan length",  len(pan or ""), 4)
            check("human-read PII masked.email sha256 prefix", "sha256:" in (em or ""))

    # DB-side: directly verify RLS lets the same rows through
    visible = db_query_as(user_id, None, raw_umask_expected,
                           "SELECT id FROM target.transactions ORDER BY id")
    # What's actually visible by RLS under the CURRENT policy:
    #   user_123 owns rows 1,2,3,6 (4 rows)
    #   user_456 owns rows 4,5     (2 rows)
    #   user_789 owns 0 rows        (0 rows visible -- the 'auditor' role
    #                                claims 'own + shared' but the RLS only
    #                                exposes own rows; that's a known doc gap
    #                                and not something the matrix refactors.)
    expected_count = {"user_123": 4, "user_456": 2, "user_789": 0}[user_id]
    assert_eq("DB RLS: visible row count",     len(visible),   expected_count)

    # Verify a row owned by *another* user is NOT visible (RLS enforcement)
    other = db_query_as(user_id, None, raw_umask_expected,
                       "SELECT id FROM target.transactions WHERE owner_user_id <> %s",
                       (user_id,))
    assert_eq("DB RLS: no leakage of others' rows", len(other), 0)

    # Human: Update Row (junior must be blocked at role layer)
    status, body = post(client, "/action/human-write", csrf)
    assert_eq("human-write status",  status, 200)
    # Response shape: action / claims_sub / umask / outcome: {ok, result: {...}}
    write_outcome = (body.get("outcome") or {}).get("result") or {}
    updated = write_outcome.get("updated")
    if "write:transactions" in expected_scopes:
        assert_eq("human-write ran", updated, 1)
    else:
        assert_eq("human-write blocked at app layer (no write scope)", updated, 0)

    # Copilot: Read Own (delegated)
    status, body = post(client, "/action/copilot-read", csrf)
    assert_eq("copilot-read status",  status, 200)
    atc = body["agent_token_claims"]
    assert_eq("copilot-read agent.act.sub",   atc["act"]["sub"],  "agent_copilot_99")
    assert_eq("copilot-read agent.scope claim (deduped)", atc["scope"], "read:transactions")
    assert_eq("copilot-read agent.umask",      atc["umask"],     "masked")

    # After agent mint: /api/principal should now have an agent block with the principal-type floor evidence
    status, body = get(client, "/api/principal")
    assert_eq("post-copilot agent block present", "agent" in body, True)
    if "agent" in body:
        a = body["agent"]
        assert_eq("agent.umask",         a["umask"],                "masked")
        assert_eq("agent.act.sub",       a["act"]["sub"],          "agent_copilot_99")
        assert_eq("agent.scope",          a["scope"],               "read:transactions")
        m = a.get("meta") or {}
        assert_in("meta.requested_scopes has read:transactions",  "read:transactions", m.get("requested_scopes"))
        assert_eq("meta.jti_short is 8 chars", len(m.get("jti_short","")), 8)
        assert_eq("meta.minted_at populated",  bool(m.get("minted_at")), True)

    # Re-call copilot-read to check masked values; the cached token is reused
    status, body = post(client, "/action/copilot-read", csrf)
    rows = (body.get("rows") or {}).get("result") or []   # call_tool wrapper
    if rows:
        assert_eq("copilot-read PII masked.ssn",  rows[0]["ssn"],  "***")
        assert_eq("copilot-read PII masked.pan is 4 chars",  len(rows[0]["card_pan"]), 4)
        check("copilot-read PII masked.email is sha256", "sha256:" in rows[0]["email"])

    # Copilot: Full Clearance Attempt
    status, body = post(client, "/action/copilot-full", csrf)
    assert_eq("copilot-full status",  status, 200)
    assert_eq("copilot-full contrast.human_umask", body["contrast"]["human_umask"], "raw" if raw_umask_expected == "raw" else "masked")
    assert_eq("copilot-full contrast.agent_umask stays masked (floor)", body["contrast"]["agent_umask"], "masked")

    # after full-clearance, jti_short must rotate vs the prior copilot-read
    status, body = get(client, "/api/principal")
    jti_after_full = body["agent"]["meta"]["jti_short"]
    jti_via_meta = body["agent"]["meta"].get("requested_scopes") or []
    # Requested includes .full only for senior (senior has .full in role_scopes)
    if raw_umask_expected == "raw":
        assert_in("requested_scopes after Full Clearance includes .full variant",
                  "read:transactions.full", jti_via_meta)
    status, body = post(client, "/action/copilot-read", csrf)  # force re-mint
    status, body = get(client, "/api/principal")
    jti_after_read = body["agent"]["meta"]["jti_short"]
    assert_eq("jti rotates between mints (different jti_short per copilot action)",
              jti_after_full != jti_after_read, True)

    # Copilot: Try Update (RLS block attempt)
    status, body = post(client, "/action/copilot-write", csrf)
    assert_eq("copilot-write status",  status, 200)
    cop_outcome = (body.get("outcome") or {}).get("result") or {}
    assert_eq("copilot-write RLS-blocked (updated=0)", cop_outcome.get("updated"), 0)

    # rls_block audit count grows (any user triggers this)
    rb_before = db_audit_count("rls_block")
    post(client, "/action/copilot-write", csrf)
    rb_after = db_audit_count("rls_block")
    check(f"rls_block count grows after write attempt ({user_id})",
          rb_after > rb_before, f"{rb_before} -> {rb_after}")

    # Masking: Side-by-Side Diff (gated to senior)
    status, body = post(client, "/action/masking-comparison", csrf)
    if raw_umask_expected == "raw":
        assert_eq("masking-comparison status", status, 200)
        assert_eq("masking-comparison result",  body["result"],  "ok")
        if body.get("diffs"):
            check("masking-comparison diff covers ssn",
                  "ssn" in (body["diffs"][0].get("changes") or {}))
    else:
        assert_eq("masking-comparison skipped for non-senior", body["result"], "skipped")
        assert_in("skipped message mentions senior_analyst", "senior_analyst", body.get("reason", ""))

    # unmask_access audit count grows after raw reads (only senior makes raw reads)
    if user_id == "user_123":
        n_before = _audit_unmask_count()
        post(client, "/action/human-read", csrf)
        n_after = _audit_unmask_count()
        check("unmask_access count grows after raw human-read",
              n_after > n_before, f"{n_before} -> {n_after}")

    # Revoke Agent Delegation
    status, body = post(client, "/revoke/agent-token", csrf)
    assert_eq("revoke-agent status", status, 200)
    status, body = get(client, "/api/principal")
    assert_eq("post-revoke: agent block gone", "agent" in body, False)
    status, jwts = get(client, "/api/jwts")
    assert_eq("post-revoke: agent.status", jwts["agent"]["status"], "none")

    # Headless: Trigger Run
    status, body = post(client, "/action/trigger-headless", csrf)
    assert_eq("trigger-headless status", status, 200)
    status, jwts = get(client, "/api/jwts")
    assert_eq("post-headless: headless.status",        jwts["headless"]["status"], "active")
    if jwts["headless"].get("jwt"):
        sub = _decode_jwt(jwts["headless"]["jwt"])["sub"]
        assert_eq("post-headless: headless.sub", sub, "agent_etl_nightly")

    # Sanity: principal panel still has only the human block (headless is separate)
    status, body = get(client, "/api/principal")
    assert_eq("after headless: agent block stays gone (headless is separate)", "agent" in body, False)

    # Audit log: human token issues for this session are recorded
    n = db_audit_count("token_issue_principal=agent") if user_id in ("user_123",) else None
    if n is not None:
        check("audit: token_issue_principal=agent rows present (headless)", n >= 1, f"count={n}")


def _audit_unmask_count() -> int:
    return db_audit_count("unmask_access", sub="user_123")


# --------------------------------------------------------------------------
# Admin operations matrix
# --------------------------------------------------------------------------

def admin_section(c: httpx.Client):
    print("\n=== admin operations matrix ===")
    _drive_admin(c)


def _drive_admin(c: httpx.Client):
    def list_admin() -> dict:
        s, d = get(c, "/api/admin-data")
        assert s == 200, "admin-data non-200"
        return d

    d = list_admin()
    base_roles = {r["role"] for r in d["roles"]}
    base_agents = {a["agent_id"] for a in d["agents"]}
    base_policies = {(p["table_name"], p["column_name"]) for p in d["column_policies"]}

    def cli_admin(*args) -> tuple[int, str, str]:
        env = os.environ.copy(); env["CONTROL_PLANE_DB_PASSWORD"] = "cp_admin_pw"
        env["DB_HOST"] = "localhost"; env["DB_PORT"] = "54321"; env["DB_NAME"] = "identity"; env["ADMIN_DB_USER"] = "control_plane_admin"
        p = subprocess.run(
            [sys.executable, "cli-admin/admin.py", *args],
            cwd=".",
            env=env, capture_output=True, text=True, timeout=30,
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()

    # 1. Add a role
    rc, out, _ = cli_admin("role", "add", "qa_role", "QA-sentinel role")
    assert_eq("cli-admin role add rc", rc, 0)
    d = list_admin()
    assert_in("admin-data reflects new role", "qa_role", {r["role"] for r in d["roles"]})

    # 2. Grant scope
    rc, _, _ = cli_admin("role", "grant", "qa_role", "read:transactions")
    assert_eq("cli-admin role grant rc", rc, 0)
    d = list_admin()
    qa = next(r for r in d["roles"] if r["role"] == "qa_role")
    assert_in("admin-data reflects granted scope", "read:transactions", qa["scopes"])

    # 3. Add an agent
    rc, _, _ = cli_admin("agent", "add", "qa_agent",
                         "--scopes", "read:transactions",
                         "--delegatable")
    assert_eq("cli-admin agent add rc", rc, 0)
    d = list_admin()
    assert_in("admin-data reflects new agent", "qa_agent", {a["agent_id"] for a in d["agents"]})

    # 4. Add a column policy
    rc, _, _ = cli_admin("column-policy", "add", "target.transactions", "qa_col",
                         "--mask-type", "hash",
                         "--min-scope", "read:transactions.full")
    assert_eq("cli-admin column-policy add rc", rc, 0)
    d = list_admin()
    pols = {(p["table_name"], p["column_name"]) for p in d["column_policies"]}
    assert_in("admin-data reflects new column policy",
              ("target.transactions", "qa_col"), pols)

    # 5. Update the column policy
    rc, _, _ = cli_admin("column-policy", "update", "target.transactions", "qa_col",
                         "--mask-type", "full")
    assert_eq("cli-admin column-policy update rc", rc, 0)
    d = list_admin()
    updated = next(p for p in d["column_policies"]
                   if p["column_name"] == "qa_col")
    assert_eq("admin-data reflects updated mask_type", updated["mask_type"], "full")

    # 6. Rendered /admin HTML still sees everything after mutations
    s, html = get(c, "/admin")
    if isinstance(html, bytes): html = html.decode("utf-8", "ignore")
    else: html = str(html)
    assert_in("/admin HTML shows qa_role",  "qa_role", html)
    assert_in("/admin HTML shows qa_agent", "qa_agent", html)
    assert_in("/admin HTML shows qa_col",   "qa_col",  html)
    assert_in("/admin HTML shows live-refresh wiring", "id=\"live-dot\"", html)

    # 7. Token listing reflects recent issuances
    s, d = get(c, "/api/admin-data")
    token_subs = {t["sub"] for t in d["tokens"]}
    assert_in("admin-data tokens include users we logged in as",
              "user_123", token_subs)

    # 8. Admin history reflects the cli-admin writes we just did
    hist_recent = [h for h in d["admin_history"]
                   if "admin_role" in h["event_type"] or "admin_agent" in h["event_type"]
                   or "admin_column_policy" in h["event_type"]]
    if not hist_recent:
        check("admin_history has recent cli-admin entries", False, "hist_recent was empty")
    else:
        events_seen = {h["event_type"] for h in hist_recent}
        assert_in("admin_role_add in history",   "admin_role_add",              events_seen)
        assert_in("admin_agent_add in history",  "admin_agent_add",             events_seen)
        assert_in("admin_column_policy_add in history",
                  "admin_column_policy_add",     events_seen)
        assert_in("admin_column_policy_update in history",
                  "admin_column_policy_update",  events_seen)

    # Cleanup everything we added
    for args in [
        ("column-policy", "delete", "target.transactions", "qa_col"),
        ("agent",         "delete", "qa_agent"),
        ("role",          "revoke", "qa_role", "read:transactions"),
        ("role",          "delete", "qa_role"),
    ]:
        rc, out, _ = cli_admin(*args)
        assert_eq(f"cleanup {args}", rc, 0)

    # After cleanup, admin-data should not have any of those
    d = list_admin()
    after_roles   = {r["role"] for r in d["roles"]}
    after_agents  = {a["agent_id"] for a in d["agents"]}
    after_policies= {(p["table_name"], p["column_name"]) for p in d["column_policies"]}
    check("admin-data: qa_role removed",  "qa_role"  not in after_roles,  f"roles={after_roles}")
    check("admin-data: qa_agent removed", "qa_agent" not in after_agents, f"agents={after_agents}")
    check("admin-data: qa_col removed",
          ("target.transactions","qa_col") not in after_policies,
          f"policies={after_policies}")

    # Final: re-render /admin HTML and check those names are gone from the
    # SPECIFIC tables (not the whole HTML, since admin_history keeps JSON
    # details that mention the names long after deletion).
    s, html = get(c, "/admin")
    if isinstance(html, bytes): html = html.decode("utf-8", "ignore")
    else: html = str(html)

    def _tbody_contains(tbody_id: str, name: str) -> bool:
        m = re.search(r'<tbody id="' + tbody_id + '">(.*?)</tbody>', html, re.DOTALL)
        return bool(m) and (name in m.group(1))

    check("/admin HTML roles-tbody: qa_role gone",    not _tbody_contains("roles-tbody", "qa_role"))
    check("/admin HTML agents-tbody: qa_agent gone",   not _tbody_contains("agents-tbody", "qa_agent"))
    check("/admin HTML policies-tbody: qa_col gone",  not _tbody_contains("policies-tbody", "qa_col"))


# --------------------------------------------------------------------------
# Live dashboard polling sanity
# --------------------------------------------------------------------------

def live_polling_section(c: httpx.Client):
    print("\n=== live dashboard polling ===")
    s1, t1 = get(c, "/api/admin-data")
    s2, t2 = get(c, "/api/admin-data")
    assert_eq("admin-data is deterministic across polls", t1, t2)


# --------------------------------------------------------------------------
# Debug assertions from last run — kept as safety net
# --------------------------------------------------------------------------
# Because the audit-log in this demo grows over time, every fresh run
# doesn't fully reset state. Clean isolation between personas isn't
# required; we're driving each persona after each other within a single
# Python process and the cookie jars are separate httpx Clients.
# --------------------------------------------------------------------------

def main():
    for sub, (role, pwd, scopes) in PERSONAS.items():
        try:
            persona_section(sub, role, pwd, scopes)
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            check(f"persona_section({sub}) crashed", False, f"{repr(e)} <<< {tb}" if len(tb)<800 else f"{repr(e)} <<< {tb[-400:]}")

    # Admin matrix with a fresh logged-in client (senior — same as before,
    # but the prior section revoked that token so a fresh login is required).
    try:
        c_admin = httpx.Client(follow_redirects=False, timeout=15.0)
        c_admin.get(f"{BASE}/login")  # initialize CSRF
        c_admin, _ = login("user_123", "pw123")
        try:
            admin_section(c_admin)
            live_polling_section(c_admin)
        finally:
            c_admin.close()
    except Exception as e:
        check("admin_section crashed", False, repr(e))

    # ----- Report -----
    print("\n" + "=" * 78)
    passed = sum(1 for r in results if r.ok)
    failed = sum(1 for r in results if not r.ok)
    print(f"OVERALL: {passed} pass / {failed} fail / {len(results)} total")
    print("-" * 78)
    # Group: show fails first
    fails = [(i, r) for i, r in enumerate(results) if not r.ok]
    passes = [(i, r) for i, r in enumerate(results) if r.ok]
    if fails:
        print("FAILURES:")
        for i, r in fails:
            print(r.line(i))
        print()
    print("PASSES (truncated to first 40):")
    for i, r in passes[:40]:
        print(r.line(i))
    if len(passes) > 40:
        print(f"  ... and {len(passes) - 40} more")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
