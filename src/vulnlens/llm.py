"""LLM factory (Claude via langchain-anthropic, or Ollama) plus provider-neutral helpers:

* ``invoke_structured`` - get a Pydantic object back. Uses JSON-in-text + validation + one repair
  retry instead of LangChain's tool-forcing ``with_structured_output``: current Claude models reject
  forced ``tool_choice`` and small local models are unreliable at it, while JSON text works for both.
* ``run_react`` - a bounded tool-calling loop (tool_choice=auto) that ends in a structured answer.
"""

from __future__ import annotations

import asyncio
import time
import json
import os
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Sequence, TypeVar

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import BaseTool
from pydantic import BaseModel, ValidationError

from .config import LLMSpec, Settings
from .skills.select import current_playbooks, record as _record

log = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)


@dataclass
class LLMHandle:
    profile: str
    spec: LLMSpec
    model: BaseChatModel

    @property
    def ident(self) -> str:
        return f"{self.spec.provider}:{self.spec.model}"

    @property
    def is_anthropic(self) -> bool:
        return self.spec.provider == "anthropic"


def build_chat_model(spec: LLMSpec) -> BaseChatModel:
    if spec.provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        kwargs: dict[str, Any] = {}
        # Top-level cache_control = automatic caching: the breakpoint follows the end of the growing ReAct
        # history, on top of the explicit breakpoint on the frozen system prompt (see system_message).
        kwargs["model_kwargs"] = {"cache_control": {"type": "ephemeral"}}
        if spec.effort:
            kwargs["output_config"] = {"effort": spec.effort}
        # No temperature: sampling params are rejected by current Claude models.
        return ChatAnthropic(
            model=spec.model,
            max_tokens=spec.max_tokens,
            timeout=spec.timeout,
            max_retries=3,
            **kwargs,
        )
    if spec.provider == "ollama":
        from langchain_ollama import ChatOllama

        kwargs = {}
        if spec.temperature is not None:
            kwargs["temperature"] = spec.temperature
        if spec.num_ctx:
            kwargs["num_ctx"] = spec.num_ctx
        if spec.reasoning is not None:
            kwargs["reasoning"] = spec.reasoning
        if spec.keep_alive:
            kwargs["keep_alive"] = spec.keep_alive
        return ChatOllama(model=spec.model, base_url=spec.base_url, num_predict=spec.max_tokens,
                          client_kwargs={"timeout": spec.timeout}, **kwargs)
    if spec.provider == "deepseek":
        try:
            from langchain_deepseek import ChatDeepSeek
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("DeepSeek provider needs: pip install 'vulnlens[deepseek]'") from e
        if not os.environ.get("DEEPSEEK_API_KEY"):
            raise RuntimeError("DEEPSEEK_API_KEY is not set")
        kwargs = {"temperature": spec.temperature} if spec.temperature is not None else {}
        if spec.extra_body:
            kwargs["extra_body"] = spec.extra_body
        return ChatDeepSeek(model=spec.model, api_base=spec.base_url or "https://api.deepseek.com",
                            api_key=os.environ["DEEPSEEK_API_KEY"], max_tokens=spec.max_tokens,
                            timeout=spec.timeout, max_retries=3, **kwargs)
    if spec.provider == "zai":
        try:
            from .providers.zai import ChatZai
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("Z.ai provider needs: pip install 'vulnlens[zai]'") from e
        if not os.environ.get("ZAI_API_KEY"):
            raise RuntimeError("ZAI_API_KEY is not set")
        return ChatZai(model=spec.model, base_url=spec.base_url, temperature=spec.temperature,
                       max_tokens=spec.max_tokens, timeout=spec.timeout, thinking=spec.reasoning,
                       reasoning_effort=spec.effort, extra_body=spec.extra_body)
    raise ValueError(f"unknown provider {spec.provider}")


class LimitedModel:
    """Proxy that caps concurrent ainvoke calls per LLM profile (shared across agents in the event loop)."""

    def __init__(self, model: Any, sem: asyncio.Semaphore):
        self._model, self._sem = model, sem

    def bind_tools(self, tools: Any, **kw: Any) -> "LimitedModel":
        return LimitedModel(self._model.bind_tools(tools, **kw), self._sem)

    async def ainvoke(self, *args: Any, **kw: Any) -> Any:
        async with self._sem:
            return await self._model.ainvoke(*args, **kw)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._model, name)


def _is_transient(e: Exception) -> bool:
    """Errors worth retrying: network drops, proxy 5xx pages, and Ollama failing to parse a malformed tool call."""
    import httpx

    if isinstance(e, (httpx.TransportError, asyncio.TimeoutError)):
        return True
    if type(e).__name__ in ("APIConnectionError", "APITimeoutError", "APIInternalError",
                            "APIServerFlowExceedError") and type(e).__module__.startswith("zai"):
        return True  # Z.ai SDK: network drop, timeout, 5xx, server overloaded
    status = getattr(e, "status_code", None)
    text = str(e)
    if type(e).__name__ == "ResponseError":  # ollama client
        return (status is not None and (status >= 500 or status == -1)) or "<!DOCTYPE html" in text[:200] \
            or "<html" in text[:200].lower()
    return False


async def ainvoke_retry(model: Any, messages: Any, tag: str = "", attempts: int = 3, backoff: float = 15.0) -> Any:
    for i in range(attempts):
        try:
            return await model.ainvoke(messages)
        except Exception as e:
            if i == attempts - 1 or not _is_transient(e):
                raise
            msg = re.sub(r"\s+", " ", str(e))
            if "<title>" in msg:
                msg = "HTML error page: " + msg.split("<title>", 1)[1].split("</title>", 1)[0]
            log.warning("%stransient LLM error (attempt %d/%d), retrying in %.0fs: %s", tag, i + 1, attempts,
                        backoff * (i + 1), msg[:200])
            await asyncio.sleep(backoff * (i + 1))


_SEMAPHORES: dict[tuple[int, str], asyncio.Semaphore] = {}


def _semaphore(profile: str, limit: int) -> asyncio.Semaphore:
    try:
        loop_id = id(asyncio.get_running_loop())
    except RuntimeError:
        loop_id = 0
    key = (loop_id, profile)
    if key not in _SEMAPHORES:
        _SEMAPHORES[key] = asyncio.Semaphore(limit)
    return _SEMAPHORES[key]


def get_llm(settings: Settings, agent: str, profile_override: str | None = None,
            use_cache: bool = True) -> LLMHandle:
    """use_cache=False (e.g. the agent is in --refresh) forces fresh model calls for this agent."""
    from .llm_cache import get_llm_cache

    profile, spec = settings.llm_for(agent, profile_override)
    model: Any = build_chat_model(spec)
    cache = get_llm_cache(settings.llm_cache, settings.cache_dir) \
        if use_cache and agent not in settings.llm_cache.exclude_agents else None
    model.cache = cache if cache is not None else False  # False: also ignore any global langchain cache
    limit = spec.effective_concurrency()
    if limit:
        model = LimitedModel(model, _semaphore(profile, limit))
    return LLMHandle(profile=profile, spec=spec, model=model)


def system_message(llm: LLMHandle, text: str) -> SystemMessage:
    """System prompt; on Claude mark it cacheable (stable prefix across CVEs/runs)."""
    if llm.is_anthropic:
        return SystemMessage(content=[{"type": "text", "text": text, "cache_control": {"type": "ephemeral"}}])
    return SystemMessage(content=text)


# ---------------------------------------------------------------------------
# Structured output
# ---------------------------------------------------------------------------

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.S)


def message_text(msg: BaseMessage) -> str:
    c = msg.content
    if isinstance(c, str):
        return c
    parts = []
    for block in c:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict) and block.get("type") == "text":
            parts.append(block.get("text", ""))
    return "".join(parts)


def extract_json(text: str) -> Any:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)  # local reasoning models
    for m in _FENCE.finditer(text):
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    raise ValueError("no JSON object found in model output")


def schema_instruction(schema: type[BaseModel]) -> str:
    return (
        "Respond with ONLY one JSON object (no prose, no markdown fences) that validates against this JSON Schema:\n"
        + json.dumps(schema.model_json_schema(), separators=(",", ":"))
    )


async def invoke_structured(
    model: BaseChatModel | Any,
    messages: Sequence[BaseMessage],
    schema: type[T],
    retries: int = 1,
    lead: str = "",
    label: str = "",
) -> T:
    msgs = list(messages) + [HumanMessage(content=(lead + "\n\n" if lead else "") + schema_instruction(schema))]
    last_err: Exception | None = None
    tag = f"[{label}] " if label else ""
    for attempt in range(retries + 1):
        t0 = time.monotonic()
        resp = await ainvoke_retry(model, msgs, tag)
        text = message_text(resp)
        try:
            out = schema.model_validate(extract_json(text))
            log.info("%sfinal %s answer in %.1fs%s", tag, schema.__name__, time.monotonic() - t0, _usage(resp))
            return out
        except (ValueError, ValidationError) as e:
            last_err = e
            _record({"kind": "json_repair", "label": label, "schema": schema.__name__, "attempt": attempt,
                     "error": str(e)[:300]})
            log.info("%sstructured output attempt %d failed after %.1fs: %s", tag, attempt,
                     time.monotonic() - t0, str(e)[:300])
            msgs = msgs + [resp, HumanMessage(content=f"That was not valid. Error: {str(e)[:1500]}\n"
                                              "Return ONLY the corrected JSON object.")]
    raise ValueError(f"model failed to produce valid {schema.__name__}: {last_err}")


# ---------------------------------------------------------------------------
# ReAct loop
# ---------------------------------------------------------------------------


@dataclass
class ReactTrace:
    steps: list[dict[str, Any]] = field(default_factory=list)
    exhausted: bool = False


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + f"\n...[truncated {len(s) - n} chars]"


async def _run_tool(tool: BaseTool, args: dict, max_chars: int) -> str:
    try:
        out = await asyncio.to_thread(tool.invoke, args)
    except Exception as e:  # tools must never crash the agent
        return f"ERROR: {type(e).__name__}: {e}"
    if not isinstance(out, str):
        out = json.dumps(out, default=str)
    return _truncate(out, max_chars)


def react_steps(settings: Any, llm: "LLMHandle", key: str, default: int) -> int:
    """Step budget for one agent loop: the LLM profile's override, else the global setting."""
    own = llm.spec.max_react_steps or {}
    return own.get(key) or settings.max_react_steps.get(key, default)


async def run_react(
    llm: LLMHandle,
    system: str,
    task: str,
    tools: list[BaseTool],
    schema: type[T],
    max_steps: int,
    max_tool_chars: int = 12000,
    final_instruction: str = "Stop using tools now. Produce your final answer.",
    label: str = "",
) -> tuple[T, ReactTrace]:
    trace = ReactTrace()
    tag = f"[{label}] " if label else ""
    started = time.monotonic()
    pb = current_playbooks()
    if pb is not None and pb.skills:
        system = f"{system}\n\n{pb.text()}"
        if pb.overflow:
            tools = list(tools) + [pb.view_tool()]
    by_name = {t.name: t for t in tools}
    bound = llm.model.bind_tools(tools) if tools else llm.model
    messages: list[BaseMessage] = [
        system_message(llm, system),
        HumanMessage(content=task + "\n\nInvestigate with the tools, then give the final answer when confident."),
    ]
    for step in range(max_steps):
        t0 = time.monotonic()
        ai: AIMessage = await ainvoke_retry(bound, messages, tag)
        messages.append(ai)
        calls = getattr(ai, "tool_calls", None) or []
        log.info("%sstep %d/%d: %.1fs%s -> %s", tag, step + 1, max_steps, time.monotonic() - t0, _usage(ai),
                 ", ".join(_fmt_call(c) for c in calls) if calls else "no tool call, finishing")
        if not calls:
            break
        results = await asyncio.gather(
            *[
                _run_tool(by_name[c["name"]], c.get("args") or {}, max_tool_chars)
                if c["name"] in by_name
                else asyncio.sleep(0, result=f"ERROR: unknown tool {c['name']}")
                for c in calls
            ]
        )
        for c, r in zip(calls, results):
            trace.steps.append({"step": step, "tool": c["name"], "args": c.get("args"), "result_preview": r[:300]})
            messages.append(ToolMessage(content=r, tool_call_id=c["id"], name=c["name"]))
    else:
        trace.exhausted = True
        log.info("%sstep budget (%d) exhausted, forcing final answer", tag, max_steps)
    # Tools stay bound so history containing tool_use blocks remains valid for the API.
    try:
        result = await invoke_structured(bound, messages, schema, lead=final_instruction, label=label)
    finally:
        _record({"kind": "react", "label": label, "steps": len({st["step"] for st in trace.steps}),
                 "tool_calls": len(trace.steps), "max_steps": max_steps, "exhausted": trace.exhausted,
                 "seconds": round(time.monotonic() - started, 1),
                 "tool_errors": [{"tool": st["tool"], "args": st["args"], "error": st["result_preview"][:200]}
                                 for st in trace.steps if st["result_preview"].startswith("ERROR:")][:20],
                 "trace": [{"tool": st["tool"], "args": st["args"]} for st in trace.steps][:60]})
    log.info("%sdone: %d tool calls, %.1fs total", tag, len(trace.steps), time.monotonic() - started)
    return result, trace


def _usage(msg: Any) -> str:
    u = getattr(msg, "usage_metadata", None) or {}
    if not u:
        return ""
    d = u.get("input_token_details") or {}
    extra = "".join(f" {k}={d[k]}" for k in ("cache_read", "cache_creation") if d.get(k))
    return f" (in={u.get('input_tokens')}{extra} out={u.get('output_tokens')} tok)"


def _fmt_call(c: dict) -> str:
    args = json.dumps(c.get("args") or {}, default=str)
    return f"{c['name']}({args[:120] + '…' if len(args) > 120 else args})"
