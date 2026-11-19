"""Z.ai GLM provider (zai-sdk) - offline: the SDK client is replaced by a recorder returning real SDK types."""

import asyncio

import pytest

pytest.importorskip("zai")

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage  # noqa: E402
from langchain_core.tools import tool  # noqa: E402
from zai.types.chat.chat_completion import Completion  # noqa: E402

from vulnlens.providers.zai import ChatZai, from_zai_response, to_zai_messages  # noqa: E402


def completion(content="", tool_calls=None, reasoning=None, cached=0, finish="stop"):
    return Completion.model_validate({
        "id": "resp-1", "model": "glm-5.3-flash", "created": 0, "request_id": "req-1",
        "choices": [{"index": 0, "finish_reason": finish, "message": {
            "role": "assistant", "content": content, "reasoning_content": reasoning,
            "tool_calls": [{"id": f"call_{i}", "type": "function",
                            "function": {"name": n, "arguments": a}} for i, (n, a) in enumerate(tool_calls or [])]
            or None}}],
        "usage": {"prompt_tokens": 1200, "completion_tokens": 40, "total_tokens": 1240,
                  "prompt_tokens_details": {"cached_tokens": cached},
                  "completion_tokens_details": {"reasoning_tokens": 25}},
    })


class Recorder:
    """Stands in for zai.ZaiClient: records create() kwargs, returns queued Completions."""

    def __init__(self, *responses):
        self.calls, self.responses = [], list(responses)
        self.chat = type("Chat", (), {})()
        self.chat.completions = type("Completions", (), {"create": self._create})()

    def _create(self, **kw):
        self.calls.append(kw)
        return self.responses.pop(0)


def model(*responses, **kw):
    m = ChatZai(api_key="test-key", **kw)
    m._client = Recorder(*responses)
    return m


@tool
def read_file(path: str) -> str:
    """Read a file from the target filesystem."""
    return ""


def test_message_conversion_roundtrips_tool_loop():
    msgs = [SystemMessage(content=[{"type": "text", "text": "sys", "cache_control": {"type": "ephemeral"}}]),
            HumanMessage(content="q"),
            AIMessage(content="", tool_calls=[{"name": "read_file", "args": {"path": "/etc/x"}, "id": "c1"}],
                      additional_kwargs={"reasoning_content": "need the file"}),
            ToolMessage(content="Listen 81", tool_call_id="c1")]
    out = to_zai_messages(msgs)
    assert out[0] == {"role": "system", "content": "sys"}  # Claude cache_control blocks flattened to text
    assert out[2]["tool_calls"][0] == {"id": "c1", "type": "function",
                                       "function": {"name": "read_file", "arguments": '{"path": "/etc/x"}'}}
    assert out[2]["reasoning_content"] == "need the file"  # preserved thinking
    assert out[3] == {"role": "tool", "tool_call_id": "c1", "content": "Listen 81"}


def test_response_parsing_tool_calls_usage_and_reasoning():
    r = from_zai_response(completion(tool_calls=[("read_file", '{"path": "/etc/httpd/conf/httpd.conf"}'),
                                                 ("read_file", "{not json")],
                                     reasoning="check config", cached=1024, finish="tool_calls"))
    ai = r.generations[0].message
    assert ai.tool_calls == [{"name": "read_file", "args": {"path": "/etc/httpd/conf/httpd.conf"},
                              "id": "call_0", "type": "tool_call"}]
    assert ai.invalid_tool_calls[0]["id"] == "call_1"  # malformed args are reported, not crashed on
    assert ai.usage_metadata["input_token_details"] == {"cache_read": 1024}
    assert ai.usage_metadata["output_token_details"] == {"reasoning": 25}
    assert ai.additional_kwargs["reasoning_content"] == "check config"
    assert ai.response_metadata["finish_reason"] == "tool_calls"


def test_request_shape_with_bound_tools_and_settings():
    m = model(completion(content="ok"), temperature=0, max_tokens=800, thinking=False, reasoning_effort="low")
    out = asyncio.run(m.bind_tools([read_file]).ainvoke([HumanMessage(content="hi")]))
    assert out.content == "ok"
    req = m._client.calls[0]
    assert req["model"] == "glm-5.3-flash" and req["stream"] is False
    assert req["temperature"] == 0 and req["max_tokens"] == 800
    assert req["thinking"] == {"type": "disabled"} and req["reasoning_effort"] == "low"
    assert req["tools"][0]["function"]["name"] == "read_file"
    assert "tool_choice" not in req  # forced tool choice is never sent


def test_react_loop_runs_against_glm():
    from vulnlens.config import LLMSpec
    from vulnlens.llm import LLMHandle, run_react
    from pydantic import BaseModel

    class Answer(BaseModel):
        verdict: str

    m = model(completion(tool_calls=[("read_file", '{"path": "/etc/httpd/conf/httpd.conf"}')], finish="tool_calls"),
              completion(content="done"), completion(content='{"verdict": "NOT_REACHABLE"}'))
    h = LLMHandle(profile="glm", spec=LLMSpec(provider="zai", model="glm-5.3-flash"), model=m)
    ans, trace = asyncio.run(run_react(h, "sys", "task", [read_file], Answer, max_steps=4))
    assert ans.verdict == "NOT_REACHABLE" and trace.steps[0]["tool"] == "read_file"
    second = m._client.calls[1]["messages"]
    assert second[-1]["role"] == "tool" and second[-1]["tool_call_id"] == "call_0"


def test_llm_cache_key_has_no_api_key_and_replays(tmp_path):
    from vulnlens.llm_cache import SQLiteCache

    cache = SQLiteCache(str(tmp_path / "z.sqlite"))
    a = model(completion(content="first"), cache=cache)
    assert "test-key" not in a._get_llm_string()
    assert a.invoke("hi").content == "first"
    b = model(completion(content="SHOULD NOT BE CALLED"), cache=cache)
    assert b.invoke("hi").content == "first" and b._client.calls == []


def test_factory_builds_glm_profile(monkeypatch):
    from vulnlens.config import load_settings
    from vulnlens.llm import build_chat_model

    monkeypatch.delenv("ZAI_API_KEY", raising=False)
    s = load_settings("configs/default.yml")
    with pytest.raises(RuntimeError, match="ZAI_API_KEY"):
        build_chat_model(s.llms["glm"])
    monkeypatch.setenv("ZAI_API_KEY", "x")
    m = build_chat_model(s.llms["glm"])
    assert isinstance(m, ChatZai) and m.model == "glm-5.3-flash" and m.thinking is True
    assert m.reasoning_effort == "high" and m.base_url == "https://api.z.ai/api/paas/v4"


def test_transient_sdk_errors_are_retried():
    import httpx
    from zai.core._errors import APIAuthenticationError, APITimeoutError

    from vulnlens.llm import _is_transient

    req = httpx.Request("POST", "https://api.z.ai/api/paas/v4/chat/completions")
    assert _is_transient(APITimeoutError(request=req))
    auth = APIAuthenticationError("bad key", response=httpx.Response(401, request=req))
    assert not _is_transient(auth)
