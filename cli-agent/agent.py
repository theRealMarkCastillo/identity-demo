"""CLI agent entry point."""
import argparse
import json
import sys
import time

import httpx
from jose import jwt

import config
import tools
from llm import LLMClient, log_turns_to_db

DEFAULT_PROMPT = "Check the shared transactions and report anything unusual."


def get_client_credentials_token() -> dict:
    """Get a token via OAuth 2.1 Client Credentials."""
    with httpx.Client() as client:
        r = client.post(
            f"{config.CONTROL_PLANE_URL}/oauth/token",
            auth=(config.AGENT_ID, config.AGENT_SECRET),
            data={
                "grant_type": "client_credentials",
                "scope": "read:transactions",
            },
            timeout=10.0,
        )
        r.raise_for_status()
        return r.json()


def introspect_token(token: str) -> dict:
    with httpx.Client() as client:
        r = client.post(
            f"{config.CONTROL_PLANE_URL}/oauth/introspect",
            auth=(config.AGENT_ID, config.AGENT_SECRET),
            data={"token": token},
            timeout=10.0,
        )
        r.raise_for_status()
        return r.json()


def run_once(args):
    if args.deterministic:
        rows = tools.list_shared_transactions()
        print(f"[cli-agent] deterministic read: {len(rows)} shared row(s)")
        for r in rows:
            print(f"  id={r['id']} account={r['account_id']} amount={r['amount']} owner={r['owner_user_id']} shared={r['is_shared']}")
        return

    print("[cli-agent] getting client_credentials token...")
    token_response = get_client_credentials_token()
    access_token = token_response["access_token"]

    if args.introspect:
        info = introspect_token(access_token)
        print(f"[cli-agent] introspect: {json.dumps(info, indent=2, default=str)}")

    # Show claims for the demo
    claims = jwt.get_unverified_claims(access_token)
    print(f"[cli-agent] token sub={claims.get('sub')} scope={claims.get('scope')} act={'YES' if 'act' in claims else 'no'}")

    prompt = args.prompt or DEFAULT_PROMPT
    print(f"[cli-agent] prompt: {prompt}")

    print("[cli-agent] calling LLM...")
    client = LLMClient()
    turns = client.run_agent_loop(
        system_prompt=(
            "You are an autonomous background agent that periodically checks shared "
            "transaction data. You have access to four tools. Proactively check the "
            "data and report anything noteworthy. If a tool returns an error, note it "
            "in your summary."
        ),
        user_message=prompt,
    )

    # Print turn summary
    for t in turns:
        if t.content:
            print(f"[cli-agent] LLM: {t.content[:200]}{'...' if len(t.content) > 200 else ''}")
        for tr in t.tool_results:
            status = "OK" if tr["ok"] else "BLOCKED"
            detail = tr.get("result") if tr["ok"] else tr.get("error")
            print(f"[cli-agent]   tool={tr['name']} {status} ({tr['elapsed_ms']}ms): {_short(detail)}")

    # Persist for the web UI feed
    try:
        log_turns_to_db(turns)
        print(f"[cli-agent] logged {len(turns)} turn(s) to platform.llm_log")
    except Exception as e:
        print(f"[cli-agent] warning: failed to log to db: {e}")


def _short(v) -> str:
    s = str(v) if v is not None else ""
    return s if len(s) < 120 else s[:120] + "..."


def loop_mode(args):
    runs = 0
    while True:
        runs += 1
        print(f"\n===== cli-agent run {runs} =====")
        try:
            run_once(args)
        except KeyboardInterrupt:
            print("\n[cli-agent] interrupted")
            return
        except Exception as e:
            print(f"[cli-agent] error: {e}")
        if args.max_runs and runs >= args.max_runs:
            break
        time.sleep(args.interval)


def main():
    p = argparse.ArgumentParser(description="Headless CLI agent for identity demo")
    p.add_argument("command", choices=["run", "loop"], help="run once or loop")
    p.add_argument("--prompt", help="Custom user prompt (default: audit shared data)")
    p.add_argument("--interval", type=int, default=15, help="Loop interval in seconds")
    p.add_argument("--iterations", type=int, default=5, help="Max LLM iterations per run")
    p.add_argument("--deterministic", action="store_true", help="Skip LLM, just read shared rows")
    p.add_argument("--introspect", action="store_true", help="Call /oauth/introspect before running")
    p.add_argument("--max-runs", type=int, help="Stop after N runs (loop mode)")
    args = p.parse_args()

    if args.command == "run":
        run_once(args)
    else:
        loop_mode(args)


if __name__ == "__main__":
    main()
