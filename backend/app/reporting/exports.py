"""Machine-readable report exports (JSON and CSV)."""
from __future__ import annotations

import csv
import io
import json


def render_json(model: dict) -> bytes:
    return json.dumps(model, indent=2, default=str, ensure_ascii=False).encode("utf-8")


def _csv_safe(v):
    s = "" if v is None else str(v)
    # Neutralise spreadsheet formula injection without altering safe values.
    if s[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


def _yes(v) -> str:
    return "yes" if v else "no"


def render_csv(model: dict) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    a = model["assessment"]
    t = model["target"]
    sc = model["score"]

    w.writerow(["section", "field", "value"])
    for k, v in (
        ("product", model["product"]),
        ("company", model["company"]),
        ("report_id", model["report_id"]),
        ("report_version", model["version"]),
        ("schema_version", model["schema_version"]),
        ("generated_at", model["generated_at"]),
        ("assessment_id", a["id"]),
        ("assessment_name", a["name"]),
        ("assessment_status", a["status"]),
        ("organization", a["organization"]),
        ("owner", a["owner"]),
        ("provider", t["provider"]),
        ("model", t["model"]),
        ("endpoint", t["endpoint"]),
        ("intensity", t["intensity"]),
        ("started_at", a["created_at"]),
        ("finished_at", a["finished_at"]),
        ("overall_score", sc.get("overall")),
        ("grade", sc.get("grade")),
        ("provisional", _yes(sc.get("provisional"))),
        ("coverage", sc.get("coverage")),
        ("scoring_version", sc.get("scoring_version")),
        ("tests_selected", model["statistics"]["tests"]["total"]),
        ("tests_passed", model["statistics"]["tests"]["passed"]),
        ("tests_failed", model["statistics"]["tests"]["failed"]),
        ("tests_inconclusive", model["statistics"]["tests"]["inconclusive"]),
        ("tests_not_tested", model["statistics"]["tests"]["skipped"] + model["statistics"]["tests"]["not_started"]),
        ("findings_total", model["statistics"]["findings_total"]),
        ("findings_confirmed", model["statistics"]["classifications"]["confirmed_vulnerability"]),
        ("findings_likely", model["statistics"]["classifications"]["likely_vulnerability"]),
        ("findings_unsafe_behavior", model["statistics"]["classifications"]["unsafe_behavior"]),
        ("findings_potential", model["statistics"]["classifications"]["potential_vulnerability"]),
        ("findings_inconclusive", model["statistics"]["classifications"]["inconclusive"]),
        ("findings_false_positive", model["statistics"]["classifications"]["false_positive"]),
    ):
        w.writerow([_csv_safe(x) for x in ("summary", k, v)])

    w.writerow([])
    w.writerow([
        "finding_id", "test_id", "title", "category", "classification", "classification_label", "severity",
        "potential_severity", "confidence", "validation_status", "evidence_quality", "impact_scope", "cvss_score",
        "cvss_vector", "cvss_status", "tool_emitted", "tool_executed", "tool_execution_confirmed",
        "unsafe_output_generated", "output_rendered", "script_executed", "service_impact_demonstrated",
        "owasp", "cwe", "atlas", "nist", "detected_at", "status", "triage", "remediation",
    ])
    for f in model["findings"]:
        cls = f.get("classification") or {}
        tool = f.get("tool_execution") or {}
        out = f.get("output_security") or {}
        svc = f.get("service_impact") or {}
        cv = f.get("cvss") or {}
        w.writerow([_csv_safe(x) for x in (
            f.get("finding_id"), f.get("attack_id"), f.get("title"), f.get("category"), f.get("classification_code"),
            f.get("classification_label"), f.get("severity"), f.get("potential_severity"), f.get("confidence"),
            cls.get("validation_status"), cls.get("evidence_quality"), cls.get("impact_scope"),
            cv.get("score"), cv.get("vector"), "validated" if cv else (f.get("cvss_suppressed_reason") or "not assigned"),
            _yes(tool.get("emitted")), _yes(tool.get("executed")), _yes(tool.get("execution_confirmed")),
            _yes(out.get("unsafe_output_generated")), _yes(out.get("rendered")), _yes(out.get("script_executed")),
            _yes(svc.get("service_impact_demonstrated")),
            ";".join(f.get("owasp") or []), ";".join(f.get("cwe") or []), ";".join(f.get("atlas") or []),
            ";".join(f.get("nist") or []), f.get("detected_at"), f.get("status"), f.get("triage"), f.get("remediation"),
        )])

    w.writerow([])
    w.writerow(["test_id", "name", "category", "category_label", "status", "result", "confidence", "severity",
                "classification", "finding_id", "started_at", "finished_at", "duration_ms", "requests_used",
                "tokens_used", "note"])
    for t in model["tests"]:
        w.writerow([_csv_safe(x) for x in (
            t.get("test_id"), t.get("name"), t.get("category"), t.get("category_label"), t.get("status"), t.get("result"),
            t.get("confidence"), t.get("severity"), t.get("classification_code"), t.get("finding_id"),
            t.get("started_at"), t.get("finished_at"), t.get("duration_ms"), t.get("requests_used"),
            t.get("tokens_used"), t.get("reason"),
        )])

    w.writerow([])
    w.writerow(["classification", "count", "description", "cvss_policy", "score_factor"])
    tax = {x["code"]: x for x in model["taxonomy"]}
    for code, count in model["statistics"]["classifications"].items():
        meta = tax.get(code, {})
        w.writerow([_csv_safe(x) for x in (code, count, meta.get("definition"), meta.get("cvss_policy"), meta.get("score_factor"))])

    w.writerow([])
    w.writerow(["category", "score", "selected", "tested", "passed", "failed", "inconclusive", "not_tested"])
    for c in model["category_scores"]:
        w.writerow([_csv_safe(x) for x in (
            c["label"], c["score"], c["selected"], c["tested"], c["passed"], c["failed"], c["inconclusive"], c["not_tested"],
        )])

    w.writerow([])
    w.writerow(["integrity", "manifest_sha256", model["integrity"]["manifest_sha256"]])
    for h in model["integrity"].get("evidence_hashes", []):
        w.writerow(["evidence", h["finding_id"], h["evidence_sha256"]])
    return buf.getvalue().encode("utf-8")
