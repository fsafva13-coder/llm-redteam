"""Boots the real Streamlit script headlessly and checks it renders without exceptions."""

from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

APP = str(Path(__file__).resolve().parent.parent / "app.py")


def launch_button(at):
    return [b for b in at.button if "LAUNCH" in b.label][0]


def test_app_boots_and_shows_checklist_without_key():
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception
    assert any("API key" in i.value for i in at.info)  # guided checklist names what is missing
    assert launch_button(at).disabled


def test_app_enables_launch_once_configured():
    at = AppTest.from_file(APP, default_timeout=30).run()
    # With the default provider and a listed model, the API key is the only sidebar text_input.
    at.sidebar.text_input[0].set_value("test-key").run()
    assert not at.exception
    assert not launch_button(at).disabled
    assert not at.info  # checklist disappears when nothing is missing
