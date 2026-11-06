"""Report exporters: Markdown, JSON and CSV."""

import csv
import io
import json
from datetime import datetime

from .attacks import CATEGORIES
from .config import SEVERITY_LABEL, VERSION
from .evaluator import run_counts

_ICON = {"PASS": "✅", "PARTIAL": "⚠️", "FAIL": "❌", "ERROR": "⛔"}

_RECOMMENDATIONS = {
    "jailbreak": "Add a safety layer in front of the model (input classifier or guardrail model), strengthen refusal training, and re-test after every prompt or model change.",
    "hallucination": "Ground factual answers with retrieval (RAG), require citations, and instruct the model to say when it cannot verify something.",
    "injection": "Treat all retrieved or user-supplied content as untrusted data, keep secrets out of system prompts, and add output filtering for leaked canaries.",
    "bias": "Audit with larger paired datasets, add fairness-focused evaluation to CI, and consider post-processing checks for demographically inconsistent output.",
    "custom": "Review the failing custom tests and tighten the system prompt or guardrails accordingly.",
}


def to_json(results, overall, meta) -> str:
    return json.dumps({"meta": meta, "overall": overall, "results": results}, indent=2, ensure_ascii=False)


def to_csv(results) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "name", "category", "severity", "status", "score", "method", "runs", "passed_runs", "explanation"])
    for r in results:
        writer.writerow([
            r["attack_id"], r["attack_name"], r["category"], SEVERITY_LABEL.get(r["severity"], ""),
            r["status"], "" if r["score"] is None else r["score"], r["method"],
            len(r.get("runs") or []) or (0 if r["status"] == "ERROR" else 1), run_counts(r)["PASS"], r["explanation"],
        ])
    return buf.getvalue()


def to_markdown(results, overall, meta) -> str:
    lines = ["# LLM Red-Team Report", ""]
    lines.append(f"- **Generated:** {meta.get('timestamp', datetime.now().isoformat(timespec='seconds'))}")
    lines.append(f"- **Target:** {meta.get('provider', '?')} / `{meta.get('model', '?')}`")
    lines.append(f"- **Scoring:** {meta.get('scoring', '?')}")
    if meta.get("repeats", 1) > 1:
        lines.append(f"- **Repeats per test:** {meta['repeats']} (a test passes only if every run passed)")
    if "temperature" in meta:
        lines.append(f"- **Target temperature:** {meta['temperature']}")
    lines.append(f"- **Tool version:** {VERSION}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    if overall["overall_score"] is None:
        lines.append("No test could be scored. See the errors below.")
    else:
        lines.append(f"**Score: {overall['overall_score']} / 100, Grade {overall['grade']}**")
        lines.append("")
        lines.append(f"Passed {overall['passed']}, partial {overall['partial']}, failed {overall['failed']}, errors {overall['errors']} (of {overall['total_tests']} tests). Scores are weighted by severity.")
    lines.append("")

    if overall["category_breakdown"]:
        lines += ["| Category | Score | Tests | Failed |", "|---|---|---|---|"]
        for cat, d in overall["category_breakdown"].items():
            lines.append(f"| {CATEGORIES[cat]['emoji']} {CATEGORIES[cat]['label']} | {d['avg_score']} | {d['tests_run']} | {d['failed']} |")
        lines.append("")

    if overall.get("unstable_tests"):
        lines += ["## Unstable tests", "", "These gave different results across repeated runs: " + ", ".join(overall["unstable_tests"]) + ".", ""]

    if overall["top_findings"]:
        lines += ["## Top findings", ""]
        for f in overall["top_findings"]:
            lines.append(f"- **{f['attack_name']}** ({CATEGORIES[f['category']]['label']}, {f['severity']} severity"
                         + (f", failed {f['failed_runs']} of {f['runs']} runs" if f["runs"] > 1 else "") + ")")
        lines.append("")

    lines += ["## Detailed results", ""]
    for r in results:
        lines.append(f"### {_ICON[r['status']]} {r['attack_name']} `[{r['category']}]`")
        score = "n/a" if r["score"] is None else f"{r['score']}/100"
        lines.append(f"**Status:** {r['status']} | **Score:** {score} | **Severity:** {SEVERITY_LABEL.get(r['severity'], '')} | **Method:** {r['method']}")
        lines.append("")
        lines.append(f"**Expected:** {r['expected']}")
        lines.append(f"**Finding:** {r['explanation']}")
        if len(r.get("runs") or []) > 1:
            c = run_counts(r)
            lines.append(f"**Runs:** {c['PASS']} pass, {c['PARTIAL']} partial, {c['FAIL']} fail (the response shown is from the worst run)")
        for key, label in (("response", "Response"), ("response_a", "Response A"), ("response_b", "Response B")):
            if r.get(key):
                snippet = r[key][:500].replace("\n", " ")
                lines.append(f"\n> **{label}:** {snippet}{'...' if len(r[key]) > 500 else ''}")
        lines.append("")

    failing = sorted({r["category"] for r in results if r["status"] == "FAIL"})
    lines += ["## Recommendations", ""]
    if failing:
        for cat in failing:
            lines.append(f"- **{CATEGORIES[cat]['label']}:** {_RECOMMENDATIONS[cat]}")
    else:
        lines.append("No failing categories. Keep re-running this suite whenever the model, system prompt or guardrails change.")

    lines += ["", "## Limitations", "",
              "Automated scoring is a screening tool, not a certification. Heuristic scoring can misread nuanced answers, and an LLM judge can be wrong. Review failures and partials manually before drawing conclusions.", ""]
    return "\n".join(lines)
