"""Local LLM response cache: replay across processes, tool calls round-trip, bypass rules."""

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage

from vulnlens.config import LLMCacheSettings, Settings
from vulnlens.llm_cache import SQLiteCache, get_llm_cache


def _model(cache, reply):
    return GenericFakeChatModel(messages=iter([reply, AIMessage(content="SECOND CALL")]), cache=cache)


def test_sqlite_cache_replays_tool_calls_across_instances(tmp_path):
    path = str(tmp_path / "c.sqlite")
    reply = AIMessage(content="", tool_calls=[{"name": "read_file", "args": {"path": "/etc/x"}, "id": "t1"}])
    first = _model(SQLiteCache(path), reply).invoke([HumanMessage(content="q")])
    assert first.tool_calls[0]["args"] == {"path": "/etc/x"}
    # new cache object on the same file (= a new process): served from disk, the model is not called
    again = _model(SQLiteCache(path), AIMessage(content="MODEL WAS CALLED")).invoke([HumanMessage(content="q")])
    assert again.tool_calls == first.tool_calls and again.content == ""
    # a different prompt misses
    other = _model(SQLiteCache(path), AIMessage(content="fresh")).invoke([HumanMessage(content="other")])
    assert other.content == "fresh"


def test_counting_and_backend_selection(tmp_path):
    cfg = LLMCacheSettings(backend="sqlite", path=str(tmp_path / "x.sqlite"))
    c = get_llm_cache(cfg, str(tmp_path))
    assert c is get_llm_cache(cfg, str(tmp_path))  # shared per configuration
    m = _model(c, AIMessage(content="a"))
    m.invoke("hi"); m.invoke("hi")
    assert (c.hits, c.misses, c.writes) == (1, 1, 1)
    assert get_llm_cache(LLMCacheSettings(backend="none"), str(tmp_path)) is None


def test_get_llm_bypass_rules(tmp_path, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test")
    from vulnlens import llm as llm_mod

    s = Settings(cache_dir=str(tmp_path), llm_cache=LLMCacheSettings(path=str(tmp_path / "y.sqlite")))
    s.llms["ds"] = s.llms["default"].model_copy(update={"provider": "deepseek", "model": "m", "effort": None})
    s.agents = {a: "ds" for a in s.agents}
    assert llm_mod.get_llm(s, "exploitability").model.cache is not False
    assert llm_mod.get_llm(s, "exploitability", use_cache=False).model.cache is False
    assert llm_mod.get_llm(s, "live_verifier").model.cache is False


def test_anthropic_requests_automatic_caching():
    from vulnlens.config import LLMSpec
    from vulnlens.llm import build_chat_model

    m = build_chat_model(LLMSpec(provider="anthropic", model="claude-opus-5-5", effort="high"))
    assert m.model_kwargs["cache_control"] == {"type": "ephemeral"}
    effort = getattr(m, "output_config", None) or m.model_kwargs.get("output_config")
    assert effort == {"effort": "high"}


def test_multi_step_loop_replays_every_step(tmp_path):
    """A replayed answer carries different metadata than the live one; later steps must still hit."""
    from langchain_core.messages import ToolMessage

    from vulnlens.llm_cache import CountingCache

    c = CountingCache(SQLiteCache(str(tmp_path / "loop.sqlite")), "t")

    def loop(first_id):
        call = AIMessage(content="", id=first_id, response_metadata={"x": first_id},
                         tool_calls=[{"name": "t", "args": {}, "id": "call_1"}])
        m = GenericFakeChatModel(messages=iter([call, AIMessage(content="done")]), cache=c)
        h = [HumanMessage(content="q")]
        a = m.invoke(h)
        h += [a, ToolMessage(content="r", tool_call_id="call_1")]
        return m.invoke(h).content

    assert loop("live-1") == "done"
    assert (c.hits, c.misses) == (0, 2)
    assert loop("never-used") == "done"
    assert (c.hits, c.misses) == (2, 2)  # both steps replayed


# ---------------------------------------------------------------------------
# Valkey / Redis backend. Runs against VULNLENS_TEST_VALKEY_URL (default: local valkey.service on 6379, db 15);
# skipped when no server answers. Every test writes under its own key prefix and deletes it afterwards.
# ---------------------------------------------------------------------------

import os
import uuid

import pytest

from vulnlens.llm_cache import CountingCache, KeyValueCache, build_backend, describe

VALKEY_URL = os.environ.get("VULNLENS_TEST_VALKEY_URL", "redis://127.0.0.1:6379/15")


@pytest.fixture
def valkey():
    try:
        kv = KeyValueCache(VALKEY_URL, ttl=600, prefix=f"vulnlens-test:{uuid.uuid4().hex[:12]}")
        kv.ping()
    except Exception as e:
        pytest.skip(f"no valkey/redis at {VALKEY_URL}: {e}")
    yield kv
    kv.clear()


def _cfg(**kw):
    return LLMCacheSettings(**{"backend": "valkey", "redis_url": VALKEY_URL, "ttl": 600,
                               "prefix": f"vulnlens-test:{uuid.uuid4().hex[:12]}", **kw})


def test_valkey_replays_tool_calls_across_clients(valkey):
    reply = AIMessage(content="", tool_calls=[{"name": "grep_search", "args": {"pattern": "Protocols"}, "id": "c1"}])
    first = _model(valkey, reply).invoke([HumanMessage(content="q")])
    other_client = KeyValueCache(VALKEY_URL, ttl=600, prefix=valkey.prefix)  # = another process / worker
    again = _model(other_client, AIMessage(content="MODEL WAS CALLED")).invoke([HumanMessage(content="q")])
    assert again.tool_calls == first.tool_calls and again.content == ""


def test_valkey_multi_step_loop_replays_every_step(valkey):
    from langchain_core.messages import ToolMessage

    c = CountingCache(valkey, "valkey")

    def loop(first_id):
        call = AIMessage(content="", id=first_id, response_metadata={"x": first_id},
                         tool_calls=[{"name": "t", "args": {}, "id": "call_1"}])
        m = GenericFakeChatModel(messages=iter([call, AIMessage(content="done")]), cache=c)
        h = [HumanMessage(content="q")]
        h += [m.invoke(h), ToolMessage(content="r", tool_call_id="call_1")]
        return m.invoke(h).content

    assert loop("live") == "done" and (c.hits, c.misses, c.writes) == (0, 2, 2)
    assert loop("other") == "done" and (c.hits, c.misses, c.writes) == (2, 2, 2)


def test_valkey_entries_expire_and_use_plain_strings(valkey):
    _model(valkey, AIMessage(content="a")).invoke("hi")
    (key,) = valkey.keys()
    assert key.decode().startswith(valkey.prefix + ":")
    assert valkey.client.type(key) == b"string"  # no RedisJSON / modules needed
    assert 0 < valkey.client.ttl(key) <= 600


def test_valkey_clear_only_touches_own_prefix(valkey):
    foreign = f"{valkey.prefix}-other:keep"
    valkey.client.set(foreign, "x", ex=60)
    try:
        _model(valkey, AIMessage(content="a")).invoke("hi")
        valkey.clear()
        assert valkey.keys() == [] and valkey.client.get(foreign) == b"x"
    finally:
        valkey.client.delete(foreign)


def test_valkey_tampered_entry_is_a_miss_not_an_object(valkey):
    """Only generation/message classes may be rebuilt from a shared server."""
    import json as _json

    from langchain_core.load import dumps
    from langchain_core.prompts import PromptTemplate

    m = _model(valkey, AIMessage(content="real answer"))
    m.invoke("hi")
    (key,) = valkey.keys()
    valkey.client.set(key, _json.dumps([dumps(PromptTemplate.from_template("{x}"))]))
    c = CountingCache(valkey, "valkey")
    assert c.lookup(*_only_key_args(m, "hi")) is None and c.misses == 1


def _only_key_args(model, text):
    """(prompt, llm_string) exactly as BaseChatModel builds them for a one-message call."""
    from langchain_core.load import dumps
    from langchain_core.messages import HumanMessage as H

    return dumps([H(content=text)]), model._get_llm_string()


def test_valkey_backend_from_settings_and_info(valkey):
    cfg = _cfg()
    try:
        c = get_llm_cache(cfg, "/nonexistent")
        assert c.label.startswith("valkey:redis://") and isinstance(c.inner, KeyValueCache)
        _model(c, AIMessage(content="a")).invoke("hi")
        info = describe(cfg, "/nonexistent")
        assert info["entries"] == 1 and info["server"].split()[0] in ("valkey", "redis")
    finally:
        build_backend(cfg, "/nonexistent")[0].clear()


def test_unreachable_valkey_falls_back_to_sqlite_or_fails(tmp_path):
    down = "redis://127.0.0.1:1/0"
    inner, label = build_backend(_cfg(redis_url=down, path=str(tmp_path / "fb.sqlite")), str(tmp_path))
    assert isinstance(inner, SQLiteCache) and label.startswith("sqlite:")
    with pytest.raises(RuntimeError, match="unreachable"):
        build_backend(_cfg(redis_url=down, fallback="none"), str(tmp_path))


def test_credentials_never_appear_in_label(tmp_path):
    from vulnlens.llm_cache import _redact_url

    assert _redact_url("redis://vl:s3cret@127.0.0.1:6379/0") == "redis://127.0.0.1:6379/0"
    with pytest.raises(RuntimeError) as e:
        build_backend(_cfg(redis_url="redis://vl:s3cret@127.0.0.1:1/0", fallback="none"), str(tmp_path))
    assert "s3cret" not in str(e.value)


def test_cli_llm_cache_info(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from vulnlens.cli import app

    cfg = tmp_path / "c.yml"
    cfg.write_text(f"cache_dir: {tmp_path}\nllm_cache:\n  backend: sqlite\n")
    r = CliRunner().invoke(app, ["llm-cache", "info", "-c", str(cfg)])
    assert r.exit_code == 0 and '"entries": 0' in r.output


def test_shipped_config_targets_local_valkey():
    from vulnlens.config import load_settings

    s = load_settings(os.path.join(os.path.dirname(__file__), "..", "configs", "default.yml"))
    assert s.llm_cache.backend == "valkey" and s.llm_cache.redis_url.startswith("redis://127.0.0.1:6379")
    assert s.llm_cache.fallback == "sqlite" and "live_verifier" in s.llm_cache.exclude_agents
