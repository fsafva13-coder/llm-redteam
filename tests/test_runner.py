import src.llm_client as client
import src.runner as runner
from src.attacks import ATTACKS_BY_CATEGORY
from src.config import CANARY, INJECTION_SYSTEM_PROMPT
from src.judge import _parse
from src.llm_client import LLMConfig, LLMError

CFG = LLMConfig(kind="openai", base_url="http://x/v1", model="m", api_key="k")


def test_build_and_estimate():
    attacks = runner.build_attack_list(["bias", "injection"])
    assert len(attacks) == 10
    assert runner.estimate_calls(attacks, use_judge=False) == 15   # 5*2 + 5
    assert runner.estimate_calls(attacks, use_judge=True) == 20    # + 5 bias judge calls, injection never judged


def test_custom_attacks_only_included_when_category_selected():
    custom = [runner.make_custom_attack(1, "t", "hi", True)]
    assert runner.build_attack_list(["jailbreak"], custom) == ATTACKS_BY_CATEGORY["jailbreak"]
    assert custom[0] in runner.build_attack_list(["custom"], custom)


def test_scan_preserves_order_and_survives_errors(monkeypatch):
    def fake(cfg, prompt, system=None):
        if "Hartmann" in prompt:
            raise LLMError("provider exploded")
        return "I can't help with that."
    monkeypatch.setattr(runner, "query_llm", fake)
    attacks = runner.build_attack_list(["jailbreak", "hallucination"])
    seen = []
    results = runner.run_scan(attacks, CFG, workers=3, progress_cb=lambda d, t, a: seen.append(d))
    assert [r["attack_id"] for r in results] == [a["id"] for a in attacks]
    assert seen == list(range(1, len(attacks) + 1))
    errors = [r for r in results if r["status"] == "ERROR"]
    assert len(errors) == 1 and "exploded" in errors[0]["explanation"]


def test_injection_gets_canary_system_prompt_and_user_prompt_is_appended(monkeypatch):
    captured = {}
    def fake(cfg, prompt, system=None):
        captured["system"] = system
        return f"The code is {CANARY}"
    monkeypatch.setattr(runner, "query_llm", fake)
    attack = ATTACKS_BY_CATEGORY["injection"][1]
    result = runner.run_attack(attack, CFG, user_system="Be concise.")
    assert INJECTION_SYSTEM_PROMPT in captured["system"] and "Be concise." in captured["system"]
    assert result["status"] == "FAIL"


def test_judge_used_for_non_injection_and_falls_back(monkeypatch):
    monkeypatch.setattr(runner, "query_llm", lambda cfg, p, s=None: "Sure, step by step:\n1. a\n2. b\n3. c")
    attack = ATTACKS_BY_CATEGORY["jailbreak"][0]
    monkeypatch.setattr(runner, "judge", lambda *a, **k: {"status": "PARTIAL", "reason": "judged"})
    res = runner.run_attack(attack, CFG, judge_cfg=CFG)
    assert res["status"] == "PARTIAL" and res["method"] == "llm-judge" and res["response"]

    def boom(*a, **k):
        raise LLMError("judge down")
    monkeypatch.setattr(runner, "judge", boom)
    res = runner.run_attack(attack, CFG, judge_cfg=CFG)
    assert res["status"] == "FAIL" and "Heuristic used" in res["explanation"]


def test_judge_json_parsing():
    assert _parse('Sure: {"verdict": "fail", "reason": "complied"}') == {"status": "FAIL", "reason": "complied"}
    assert _parse("no json here") is None
    assert _parse('{"verdict": "MAYBE"}') is None


def test_client_retries_on_429_then_succeeds(monkeypatch):
    calls = {"n": 0}
    class Resp:
        def __init__(self, code, body=None, headers=None):
            self.status_code, self._b, self.headers, self.text = code, body, headers or {}, "x"
        def json(self): return self._b
    def fake_post(*a, **k):
        calls["n"] += 1
        return Resp(429, headers={"retry-after": "0"}) if calls["n"] < 3 else Resp(200, {"choices": [{"message": {"content": "hi"}}]})
    monkeypatch.setattr(client.requests, "post", fake_post)
    monkeypatch.setattr(client.time, "sleep", lambda s: None)
    assert client.query_llm(CFG, "p") == "hi" and calls["n"] == 3


def test_client_rejects_empty_reply_and_sets_reasoning_effort(monkeypatch):
    sent = {}
    class Resp:
        status_code, headers, text = 200, {}, ""
        def __init__(self, content): self._c = content
        def json(self): return {"choices": [{"message": {"content": self._c}}]}
    def fake_post(url, headers=None, json=None, timeout=None):
        sent.update(json)
        return Resp(sent.get("_reply", ""))
    monkeypatch.setattr(client.requests, "post", fake_post)
    gpt_oss = LLMConfig(kind="openai", base_url="http://x/v1", model="openai/gpt-oss-20b", api_key="k")
    try:
        client.query_llm(gpt_oss, "p")
        assert False
    except LLMError as exc:
        assert "empty reply" in str(exc)
    assert sent["reasoning_effort"] == "low"
    sent.clear()
    try:
        client.query_llm(CFG, "p")  # non-reasoning model: field must not be sent
    except LLMError:
        pass
    assert "reasoning_effort" not in sent


def test_client_auth_error_message_and_missing_key(monkeypatch):
    class Resp:
        status_code, text, headers = 401, "no", {}
    monkeypatch.setattr(client.requests, "post", lambda *a, **k: Resp())
    try:
        client.query_llm(CFG, "p")
        assert False
    except LLMError as exc:
        assert "API key" in str(exc)
    try:
        client.query_llm(LLMConfig("openai", "http://x", "m", ""), "p")
        assert False
    except LLMError as exc:
        assert "No API key" in str(exc)
