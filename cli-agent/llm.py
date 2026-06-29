"""LLM client for the CLI agent. Reuses pattern from web-app/llm.py."""
import json
import time
from dataclasses import dataclass, field
from typing import Any

from openai import OpenAI

import config
import tools

# Re-declare tools here (OpenAI tool-calling format)
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_my_transactions",
            "description": "List transactions owned by the current user.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_shared_transactions",
            "description": "List all transactions marked as shared across the organization.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_transaction",
            "description": "Update the amount of a specific transaction by id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer", "description": "Transaction id"},
                    "amount": {"type": "number", "description": "New amount"},
                },
                "required": ["id", "amount"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_transaction",
            "description": "Delete a transaction by id.",
            "parameters": {
                "type": "object",
                "properties": {"id": {"type": "integer", "description": "Transaction id"}},
                "required": ["id"],
            },
        },
    },
]


@dataclass
class Turn:
    role: str
    content: str | None = None
    tool_calls: list[dict] = field(default_factory=list)
    tool_results: list[dict] = field(default_factory=list)


class LLMClient:
    def __init__(self):
        if not config.LLM_BASE_URL or not config.LLM_API_KEY or not config.LLM_MODEL:
            raise RuntimeError(
                "LLM_BASE_URL, LLM_API_KEY, and LLM_MODEL are required (no defaults). "
                "Set them in .env or your environment."
            )
        self.client = OpenAI(base_url=config.LLM_BASE_URL, api_key=config.LLM_API_KEY)
        self.model = config.LLM_MODEL
        self.temperature = config.LLM_TEMPERATURE
        self.max_tokens = config.LLM_MAX_TOKENS
        self.max_iterations = config.LLM_MAX_ITERATIONS

    def run_agent_loop(self, system_prompt: str, user_message: str) -> list[Turn]:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]
        turns: list[Turn] = []

        for _ in range(self.max_iterations):
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=TOOLS,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            msg = resp.choices[0].message

            assistant_dict: dict[str, Any] = {"role": "assistant"}
            if msg.content:
                assistant_dict["content"] = msg.content
            if msg.tool_calls:
                assistant_dict["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                    }
                    for tc in msg.tool_calls
                ]
            messages.append(assistant_dict)

            turn = Turn(role="assistant", content=msg.content)
            if msg.tool_calls:
                turn.tool_calls = [
                    {"name": tc.function.name, "arguments": tc.function.arguments}
                    for tc in msg.tool_calls
                ]

            if not msg.tool_calls:
                turns.append(turn)
                break

            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                except json.JSONDecodeError:
                    args = {}

                start = time.time()
                outcome = tools.call_tool(tc.function.name, args)
                elapsed_ms = int((time.time() - start) * 1000)

                tool_result = {
                    "name": tc.function.name,
                    "ok": outcome.get("ok", False),
                    "elapsed_ms": elapsed_ms,
                }
                if outcome.get("ok"):
                    tool_result["result"] = outcome.get("result")
                else:
                    tool_result["error"] = outcome.get("error")

                turn.tool_results.append(tool_result)

                content = json.dumps(
                    tool_result["result"] if outcome.get("ok") else {"error": tool_result["error"]}
                )
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": content})

            turns.append(turn)
        else:
            turns.append(Turn(role="assistant", content="[max iterations reached]"))

        return turns


def log_turns_to_db(turns: list[Turn]):
    """Persist headless agent's LLM turns to platform.llm_log for the web UI feed."""
    import psycopg
    dsn = f"host={config.DB_HOST} port={config.DB_PORT} dbname={config.DB_NAME} user={config.DB_USER} password={config.APP_DB_PASSWORD}"
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            for t in turns:
                cur.execute(
                    """INSERT INTO platform.llm_log
                       (principal, role, content) VALUES (%s, %s, %s)""",
                    ("cli-agent", t.role, t.content),
                )
                for tr in t.tool_results:
                    cur.execute(
                        """INSERT INTO platform.llm_log
                           (principal, role, tool_name, tool_result, tool_ok)
                           VALUES (%s, %s, %s, %s, %s)""",
                        ("cli-agent", "tool", tr["name"],
                         json.dumps(tr.get("result") or {"error": tr.get("error")}),
                         tr["ok"]),
                    )
        conn.commit()
