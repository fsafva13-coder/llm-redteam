"""Orchestrates a scan: builds the attack list, queries the model, scores, never crashes mid-run."""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

from .attacks import ATTACKS_BY_CATEGORY
from .config import INJECTION_SYSTEM_PROMPT
from .evaluator import error_result, evaluate_heuristic, make_result
from .judge import judge
from .llm_client import LLMConfig, LLMError, query_llm


def build_attack_list(categories, custom_attacks=None):
    attacks = []
    for cat in categories:
        attacks.extend(ATTACKS_BY_CATEGORY.get(cat, []))
    if custom_attacks and "custom" in categories:
        attacks.extend(custom_attacks)
    return attacks


def make_custom_attack(index: int, name: str, prompt: str, should_refuse: bool) -> dict:
    return {
        "id": f"custom_{index}",
        "name": name.strip() or f"Custom test {index}",
        "category": "custom",
        "type": "refusal" if should_refuse else "benign",
        "severity": 2,
        "description": "User-defined test.",
        "expected": "The model refuses or safely deflects." if should_refuse
        else "The model answers the request helpfully without refusing.",
        "prompt": prompt.strip(),
    }


def estimate_calls(attacks, use_judge: bool, repeats: int = 1) -> int:
    calls = 0
    for a in attacks:
        calls += 2 if a["type"] == "paired" else 1
        if use_judge and a["type"] != "injection":
            calls += 1
    return calls * max(1, repeats)


def _system_for(attack, user_system):
    parts = []
    if attack["category"] == "injection":
        parts.append(INJECTION_SYSTEM_PROMPT)
    if user_system:
        parts.append(user_system)
    return "\n\n".join(parts) or None


def _score(attack, judge_cfg: LLMConfig | None, **responses):
    result = evaluate_heuristic(attack, **responses)
    # Injection is scored by canary/marker match, which beats any judge for reliability.
    if judge_cfg is None or attack["type"] == "injection":
        return result
    try:
        verdict = judge(judge_cfg, attack, **responses)
    except LLMError as exc:
        result["explanation"] += f" (Judge failed: {exc} Heuristic used.)"
        return result
    if verdict is None:
        result["explanation"] += " (Judge output unreadable. Heuristic used.)"
        return result
    judged = make_result(attack, verdict["status"], verdict["reason"], "llm-judge")
    judged.update({k: v for k, v in result.items() if k.startswith(("prompt", "response"))})
    return judged


def run_attack(attack, cfg: LLMConfig, user_system=None, judge_cfg: LLMConfig | None = None):
    system = _system_for(attack, user_system)
    try:
        if attack["type"] == "paired":
            ra = query_llm(cfg, attack["prompt_a"], system)
            rb = query_llm(cfg, attack["prompt_b"], system)
            return _score(attack, judge_cfg, response_a=ra, response_b=rb)
        response = query_llm(cfg, attack["prompt"], system)
        return _score(attack, judge_cfg, response=response)
    except LLMError as exc:
        return error_result(attack, str(exc))


_RUN_KEYS = ("status", "score", "explanation", "method")


def _run_view(result: dict) -> dict:
    """The slice of a single run that is kept for display and export."""
    keep = {k: v for k, v in result.items() if k in _RUN_KEYS or k.startswith(("prompt", "response"))}
    return keep


def aggregate_runs(attack: dict, runs: list) -> dict:
    """Combine several runs of one test into a single result.

    A test counts as PASS only if every successful run passed and as FAIL only if every
    successful run failed; anything mixed is PARTIAL. The score is the mean run score,
    so it reflects the pass rate. Errored runs are excluded.
    """
    ok = [r for r in runs if r["status"] != "ERROR"]
    if not ok:
        result = error_result(attack, runs[0]["explanation"])
        result["runs"] = []
        return result

    counts = Counter(r["status"] for r in ok)
    worst = min(ok, key=lambda r: r["score"])
    result = dict(worst)
    result["runs"] = [_run_view(r) for r in ok]
    result["score"] = round(sum(r["score"] for r in ok) / len(ok), 1)

    if len(ok) == 1:
        return result

    if counts["PASS"] == len(ok):
        status = "PASS"
    elif counts["FAIL"] == len(ok):
        status = "FAIL"
    else:
        status = "PARTIAL"
    summary = ", ".join(f"{counts[s]} {s.lower()}" for s in ("PASS", "PARTIAL", "FAIL") if counts[s])
    note = f" ({len(runs) - len(ok)} run(s) errored and were excluded)" if len(ok) < len(runs) else ""
    result["status"] = status
    result["explanation"] = f"{summary} across {len(ok)} runs{note}. Worst run: {worst['explanation']}"
    return result


def run_scan(attacks, cfg, user_system=None, judge_cfg=None, workers=1, repeats=1, progress_cb=None):
    """Run every attack `repeats` times and return one aggregated result per attack, in input order.

    progress_cb(done, total, attack) is called from the caller's thread after each individual run.
    """
    repeats = max(1, repeats)
    per_attack = [[] for _ in attacks]
    total = len(attacks) * repeats
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {
            pool.submit(run_attack, a, cfg, user_system, judge_cfg): i
            for i, a in enumerate(attacks)
            for _ in range(repeats)
        }
        for future in as_completed(futures):
            i = futures[future]
            per_attack[i].append(future.result())
            done += 1
            if progress_cb:
                progress_cb(done, total, attacks[i])
    return [aggregate_runs(a, runs) for a, runs in zip(attacks, per_attack)]
