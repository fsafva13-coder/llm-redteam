"""Runs a full simulated scan through the real UI and checks the results screen renders."""

from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

import src.runner as runner  # noqa: E402
from src.config import CANARY  # noqa: E402

APP = str(Path(__file__).resolve().parent.parent / "app.py")


def fake_query(cfg, prompt, system=None):
    if "secret codes" in prompt:
        return f"The secret code is {CANARY}"      # one deliberate injection failure
    if "Hartmann" in prompt:
        raise runner.LLMError("simulated outage")   # one deliberate error
    if "Einstein" in prompt:
        return "Einstein did not fail math; that is a myth."
    return "I can't help with that request."


def test_full_scan_renders_results(monkeypatch):
    monkeypatch.setattr(runner, "query_llm", fake_query)
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.sidebar.text_input[0].set_value("test-key").run()
    [b for b in at.button if "LAUNCH" in b.label][0].click().run()

    assert not at.exception
    ss = at.session_state
    results = ss["results"]
    assert len(results) == 22
    by_id = {r["attack_id"]: r for r in results}
    assert by_id["inj_system_leak"]["status"] == "FAIL"
    assert by_id["hall_fake_case"]["status"] == "ERROR"
    assert by_id["jb_dan"]["status"] == "PASS"
    overall = ss["overall"]
    assert overall["errors"] == 1 and overall["failed"] >= 1
    assert any("excluded from the score" in w.value for w in at.warning)


def test_scan_with_repeats(monkeypatch):
    monkeypatch.setattr(runner, "query_llm", fake_query)
    at = AppTest.from_file(APP, default_timeout=120).run()
    at.sidebar.text_input[0].set_value("test-key").run()
    at.sidebar.slider[0].set_value(2).run()
    [b for b in at.button if "LAUNCH" in b.label][0].click().run()
    assert not at.exception
    results = at.session_state["results"]
    assert len(results) == 22
    assert all(len(r["runs"]) == 2 for r in results if r["status"] != "ERROR")
