"""LLM tool-calling loop. Used by web-app (for Copilot chat) and cli-agent (for headless)."""
import json
import time
from dataclasses import dataclass, field
from typing import Any

from openai import OpenAI

# Tools exposed to the LLM. No scope hints - the LLM discovers constraints via RLS errors.
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
    """Wraps OpenAI client + config. Fails fast if LLM env vars are missing."""

    def __init__(self, base_url: str, api_key: str, model: str, temperature: float, max_tokens: int, max_iterations: int):
        if not base_url or not api_key or not model:
            raise RuntimeError(
                "LLM_BASE_URL, LLM_API_KEY, and LLM_MODEL are required for chat. "
                "Set them in .env or your environment, then restart the web-app."
            )
        self.client = OpenAI(base_url=base_url, api_key=api_key)
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.max_iterations = max_iterations

    def run_agent_loop(
        self,
        system_prompt: str,
        user_message: str,
        tool_executor,  # callable(name, args) -> {"ok": bool, "result"?, "error"?}
        history: list[dict] | None = None,
    ) -> list[Turn]:
        """Run an LLM tool-calling loop. Returns the full turn log."""
        messages: list[dict] = [{"role": "system", "content": system_prompt}]
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": user_message})

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
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
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

            # Execute each tool call
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                except json.JSONDecodeError:
                    args = {}

                start = time.time()
                outcome = tool_executor(tc.function.name, args)
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

                # Add to messages for next LLM iteration
                content = json.dumps(
                    tool_result["result"] if outcome.get("ok") else {"error": tool_result["error"]}
                )
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": content,
                })

            turns.append(turn)
        else:
            # Loop exhausted without final assistant message
            turns.append(Turn(role="assistant", content="[max iterations reached]"))

        return turns
