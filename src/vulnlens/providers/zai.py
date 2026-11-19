"""LangChain chat model for Z.ai GLM models (glm-5.3-flash, ...) on top of the official `zai-sdk`.

The SDK is synchronous (its `async_completions` is a submit-then-poll task API), so `_agenerate` runs the
blocking call in a worker thread. Messages and tools use the OpenAI-style schema the GLM API expects.

    pip install 'vulnlens[zai]'      # zai-sdk
    export ZAI_API_KEY=...           # https://z.ai/manage-apikey/apikey-list
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Callable, Literal, Optional, Sequence, Union

from langchain_core.callbacks import AsyncCallbackManagerForLLMRun, CallbackManagerForLLMRun
from langchain_core.language_models import BaseChatModel, LanguageModelInput
from langchain_core.messages import (AIMessage, BaseMessage, ChatMessage, HumanMessage, SystemMessage,
                                     ToolMessage)
from langchain_core.messages.ai import UsageMetadata
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable
from langchain_core.tools import BaseTool
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import ConfigDict, Field, PrivateAttr, SecretStr

ZAI_BASE_URL = "https://api.z.ai/api/paas/v4"          # international platform (ZaiClient default)
ZHIPU_BASE_URL = "https://open.bigmodel.cn/api/paas/v4"  # mainland China platform (ZhipuAiClient default)


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    parts = []
    for block in content or []:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict) and block.get("type") == "text":
            parts.append(block.get("text", ""))
    return "".join(parts)


def to_zai_messages(messages: Sequence[BaseMessage]) -> list[dict[str, Any]]:
    """LangChain messages -> GLM chat messages (OpenAI-style roles, tool_calls, tool_call_id)."""
    out: list[dict[str, Any]] = []
    for m in messages:
        if isinstance(m, SystemMessage):
            out.append({"role": "system", "content": _text(m.content)})
        elif isinstance(m, HumanMessage):
            out.append({"role": "user", "content": _text(m.content)})
        elif isinstance(m, AIMessage):
            msg: dict[str, Any] = {"role": "assistant", "content": _text(m.content)}
            if m.tool_calls:
                msg["tool_calls"] = [{"id": c["id"], "type": "function",
                                      "function": {"name": c["name"], "arguments": json.dumps(c["args"])}}
                                     for c in m.tool_calls]
            # GLM "preserved thinking": send the reasoning back with its tool calls so multi-step loops keep it.
            if m.additional_kwargs.get("reasoning_content"):
                msg["reasoning_content"] = m.additional_kwargs["reasoning_content"]
            out.append(msg)
        elif isinstance(m, ToolMessage):
            out.append({"role": "tool", "tool_call_id": m.tool_call_id, "content": _text(m.content)})
        elif isinstance(m, ChatMessage):
            out.append({"role": m.role, "content": _text(m.content)})
        else:
            raise ValueError(f"unsupported message type for Z.ai: {type(m).__name__}")
    return out


def from_zai_response(resp: Any) -> ChatResult:
    """GLM Completion -> ChatResult with tool calls, reasoning and usage (incl. cached prompt tokens)."""
    choice = resp.choices[0]
    msg = choice.message
    tool_calls, invalid = [], []
    for tc in msg.tool_calls or []:
        raw = tc.function.arguments
        try:
            args = json.loads(raw) if isinstance(raw, str) else (raw or {})
            if not isinstance(args, dict):
                raise ValueError("arguments are not an object")
            tool_calls.append({"name": tc.function.name, "args": args, "id": tc.id, "type": "tool_call"})
        except ValueError as e:
            invalid.append({"name": tc.function.name, "args": raw, "id": tc.id, "error": str(e),
                            "type": "invalid_tool_call"})
    usage: UsageMetadata | None = None
    u = getattr(resp, "usage", None)
    if u is not None:
        usage = {"input_tokens": u.prompt_tokens, "output_tokens": u.completion_tokens,
                 "total_tokens": u.total_tokens}
        cached = getattr(getattr(u, "prompt_tokens_details", None), "cached_tokens", None)
        if cached is not None:
            usage["input_token_details"] = {"cache_read": cached}
        reasoning = getattr(getattr(u, "completion_tokens_details", None), "reasoning_tokens", None)
        if reasoning is not None:
            usage["output_token_details"] = {"reasoning": reasoning}
    extra = {"reasoning_content": msg.reasoning_content} if getattr(msg, "reasoning_content", None) else {}
    ai = AIMessage(content=msg.content or "", tool_calls=tool_calls, invalid_tool_calls=invalid,
                   additional_kwargs=extra, usage_metadata=usage, id=getattr(resp, "id", None),
                   response_metadata={"model_name": getattr(resp, "model", None),
                                      "finish_reason": choice.finish_reason,
                                      "request_id": getattr(resp, "request_id", None)})
    return ChatResult(generations=[ChatGeneration(message=ai)])


class ChatZai(BaseChatModel):
    """Z.ai GLM chat model (glm-5.3-flash etc.) through the official zai-sdk."""

    model: str = "glm-5.3-flash"
    api_key: Optional[SecretStr] = Field(default=None, exclude=True)  # default: ZAI_API_KEY
    base_url: Optional[str] = None   # default: ZAI_BASE_URL env or the international endpoint
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    timeout: float = 600.0
    max_retries: int = 3
    thinking: Optional[bool] = None            # None = model default; False disables reasoning (faster)
    reasoning_effort: Optional[str] = None     # none|minimal|low|medium|high|xhigh|max (glm-5.2+)
    extra_body: Optional[dict] = None

    model_config = ConfigDict(arbitrary_types_allowed=True, populate_by_name=True)
    _client: Any = PrivateAttr(default=None)

    @property
    def _llm_type(self) -> str:
        return "zai-chat"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        # Part of the LLM response-cache key; never includes the API key.
        return {"model": self.model, "base_url": self._base_url(), "temperature": self.temperature,
                "max_tokens": self.max_tokens, "thinking": self.thinking,
                "reasoning_effort": self.reasoning_effort, "extra_body": self.extra_body}

    def _base_url(self) -> str:
        return self.base_url or os.environ.get("ZAI_BASE_URL") or ZAI_BASE_URL

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                from zai import ZaiClient
            except ImportError as e:  # pragma: no cover
                raise RuntimeError("Z.ai provider needs: pip install 'vulnlens[zai]'") from e
            key = self.api_key.get_secret_value() if self.api_key else os.environ.get("ZAI_API_KEY")
            if not key:
                raise RuntimeError("ZAI_API_KEY is not set")
            self._client = ZaiClient(api_key=key, base_url=self._base_url(), timeout=self.timeout,
                                     max_retries=self.max_retries)
        return self._client

    def _request(self, messages: list[BaseMessage], stop: Optional[list[str]], **kwargs: Any) -> dict[str, Any]:
        req: dict[str, Any] = {"model": self.model, "messages": to_zai_messages(messages), "stream": False}
        if self.temperature is not None:
            req["temperature"] = self.temperature
        if self.max_tokens:
            req["max_tokens"] = self.max_tokens
        if stop:
            req["stop"] = stop
        if self.thinking is not None:
            req["thinking"] = {"type": "enabled" if self.thinking else "disabled"}
        if self.reasoning_effort:
            req["reasoning_effort"] = self.reasoning_effort
        if self.extra_body:
            req["extra_body"] = self.extra_body
        for k in ("tools", "tool_choice"):
            if kwargs.get(k) is not None:
                req[k] = kwargs[k]
        return req

    def _generate(self, messages: list[BaseMessage], stop: Optional[list[str]] = None,
                  run_manager: Optional[CallbackManagerForLLMRun] = None, **kwargs: Any) -> ChatResult:
        resp = self._get_client().chat.completions.create(**self._request(messages, stop, **kwargs))
        return from_zai_response(resp)

    async def _agenerate(self, messages: list[BaseMessage], stop: Optional[list[str]] = None,
                         run_manager: Optional[AsyncCallbackManagerForLLMRun] = None, **kwargs: Any) -> ChatResult:
        req = self._request(messages, stop, **kwargs)
        client = self._get_client()
        resp = await asyncio.to_thread(client.chat.completions.create, **req)
        return from_zai_response(resp)

    def bind_tools(self, tools: Sequence[Union[dict[str, Any], type, Callable, BaseTool]], *,
                   tool_choice: Optional[Union[str, Literal["auto", "none"]]] = None,
                   **kwargs: Any) -> Runnable[LanguageModelInput, BaseMessage]:
        formatted = [convert_to_openai_tool(t) for t in tools]
        if tool_choice is not None:
            kwargs["tool_choice"] = tool_choice  # GLM supports "auto" only; forced choice is rejected
        return super().bind(tools=formatted, **kwargs)

