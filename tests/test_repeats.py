from src import runner
from src.evaluator import compute_overall, make_result
from src.report import to_csv, to_markdown
from src.runner import aggregate_runs, estimate_calls, run_scan

JB = {"id": "x", "name": "x", "category": "jailbreak", "type": "refusal", "severity": 3, "expected": "e", "prompt": "p"}


def run(status):
    return make_result(JB, status, status.lower(), "heuristic", prompt="p", response="r")


def test_aggregate_all_pass_all_fail_mixed():
    assert aggregate_runs(JB, [run("PASS")] * 3)["status"] == "PASS"
    assert aggregate_runs(JB, [run("FAIL")] * 3)["status"] == "FAIL"
    mixed = aggregate_runs(JB, [run("PASS"), run("FAIL"), run("PASS")])
    assert mixed["status"] == "PARTIAL" and mixed["score"] == 66.7 and len(mixed["runs"]) == 3


def test_aggregate_excludes_errors():
    err = make_result(JB, "ERROR", "boom", "none")
    res = aggregate_runs(JB, [run("PASS"), err])
    assert res["status"] == "PASS" and len(res["runs"]) == 1
    assert aggregate_runs(JB, [err, err])["status"] == "ERROR"


def test_estimate_scales_with_repeats():
    assert estimate_calls([JB], False, 3) == 3


def test_run_scan_repeats_and_progress(monkeypatch):
    seq = iter(["I can't help.", "1. a\n2. b\n3. c", "I can't help."])
    monkeypatch.setattr(runner, "query_llm", lambda cfg, prompt, system=None: next(seq))
    ticks = []
    res = run_scan([JB], None, repeats=3, progress_cb=lambda d, t, a: ticks.append((d, t)))
    assert res[0]["status"] == "PARTIAL" and ticks[-1] == (3, 3)
    overall = compute_overall(res)
    assert overall["unstable_tests"] == ["x"]
    assert overall["top_findings"][0]["failed_runs"] == 1 and overall["top_findings"][0]["runs"] == 3
    assert "Unstable" in to_markdown(res, overall, {"repeats": 3})
    assert "passed_runs" in to_csv(res)
