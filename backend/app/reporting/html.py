"""Premium, print-ready HTML report renderer.

The document is fully static: no JavaScript, no remote assets, no external
fonts. All data is escaped, long values wrap, and finding cards avoid page
breaks so the printed/PDF output never clips evidence.
"""
from __future__ import annotations

import base64
import html
import re
from pathlib import Path

from .model import COMPANY, PRODUCT, TAGLINE

CLASS_COLOR = {
    "confirmed_vulnerability": "#b91c1c",
    "likely_vulnerability": "#c2410c",
    "unsafe_behavior": "#a16207",
    "potential_vulnerability": "#1d4ed8",
    "inconclusive": "#475569",
    "false_positive": "#64748b",
}
CLASS_BG = {
    "confirmed_vulnerability": "#fef2f2",
    "likely_vulnerability": "#fff7ed",
    "unsafe_behavior": "#fefce8",
    "potential_vulnerability": "#eff6ff",
    "inconclusive": "#f1f5f9",
    "false_positive": "#f8fafc",
}
SEV_COLOR = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#2563eb", "info": "#64748b"}
SEV_BG = {"critical": "#fef2f2", "high": "#fff7ed", "medium": "#fffbeb", "low": "#eff6ff", "info": "#f8fafc"}

def _asset_data_uri(name: str, mime: str) -> str:
    """Embed the supplied brand asset so reports stay fully self-contained."""
    try:
        raw = (Path(__file__).resolve().parents[1] / "assets" / name).read_bytes()
    except OSError:
        return ""
    return f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}"


LOGO_DATA = _asset_data_uri("logo.jpg", "image/jpeg")

CSS = """
:root{--navy:#0b1730;--ink:#0f172a;--muted:#5b6b82;--line:#dbe3ee;--blue:#2563eb;--cyan:#0891b2;--bg:#f6f8fc;--card:#fff}
*{box-sizing:border-box}html{font-size:15px}body{margin:0;background:var(--bg);color:var(--ink);font-family:"Segoe UI",Inter,system-ui,-apple-system,Arial,sans-serif;line-height:1.58;-webkit-print-color-adjust:exact;print-color-adjust:exact}
a{color:var(--blue);text-decoration:none}main{max-width:1080px;margin:0 auto;background:var(--card);box-shadow:0 18px 60px rgba(15,23,42,.08);min-height:100vh}
.sheet{padding:42px 56px}
.cover{background:linear-gradient(145deg,#07101f 0%,#0b1730 48%,#123a6b 100%);color:#fff;padding:64px 56px 48px;position:relative;overflow:hidden}
.cover:before{content:"";position:absolute;inset:-30% -10% auto auto;width:620px;height:620px;border-radius:50%;background:radial-gradient(circle,rgba(34,211,238,.22),transparent 65%)}
.cover:after{content:"";position:absolute;inset:auto auto -40% -15%;width:520px;height:520px;border-radius:50%;background:radial-gradient(circle,rgba(37,99,235,.25),transparent 65%)}
.cover>*{position:relative;z-index:1}
.cover .brandline{margin-bottom:24px}
.cover .brand-logo{display:block;width:250px;height:auto;max-width:70%;mix-blend-mode:screen;filter:drop-shadow(0 10px 30px rgba(34,211,238,.16))}
.cover .brand{font-size:20px;font-weight:700;letter-spacing:.02em}.cover .tag{font-size:12px;color:#9fd8ef;letter-spacing:.12em;text-transform:uppercase;margin-top:2px}
.cover .eyebrow{font-size:11px;letter-spacing:.22em;text-transform:uppercase;color:#7dd3fc;margin-bottom:14px}
.cover h1{font-size:44px;line-height:1.12;margin:0 0 18px;font-weight:750;letter-spacing:-.02em;max-width:800px}
.cover .subject{font-size:19px;color:#cfe3ff;margin:0 0 40px;max-width:760px}
.cover .meta{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:18px;border-top:1px solid rgba(148,197,255,.25);padding-top:22px;margin-top:34px}
.cover .meta div span{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:#8fb6dd;margin-bottom:4px}
.cover .meta div b{font-size:13px;font-weight:600;color:#fff;overflow-wrap:anywhere}
.cover .scorebox{display:inline-flex;align-items:center;gap:16px;background:rgba(255,255,255,.07);border:1px solid rgba(148,197,255,.28);border-radius:14px;padding:14px 20px;margin-top:30px}
.cover .scorebox .num{font-size:34px;font-weight:750;color:#7dd3fc;line-height:1}
.cover .scorebox .lbl{font-size:12px;color:#bfd8f6}
.cover .confidential{position:absolute;right:56px;top:34px;font-size:10px;letter-spacing:.16em;color:#8fb6dd;text-transform:uppercase;border:1px solid rgba(148,197,255,.3);padding:6px 10px;border-radius:4px}
h2{font-size:23px;line-height:1.25;margin:0 0 8px;letter-spacing:-.01em;color:var(--navy)}
h3{font-size:16px;margin:22px 0 8px;color:var(--navy)}
h4{font-size:12px;margin:16px 0 6px;color:var(--muted);text-transform:uppercase;letter-spacing:.09em}
p{margin:0 0 10px}ul,ol{margin:6px 0 12px;padding-left:22px}li{margin:3px 0}
.section{padding:34px 0;border-top:1px solid var(--line)}.section:first-child{border-top:0}
.kicker{font-size:10px;letter-spacing:.18em;text-transform:uppercase;color:var(--cyan);font-weight:700;margin-bottom:5px}
.lead{font-size:15px;color:#334155;max-width:850px}
.meta-row{display:flex;flex-wrap:wrap;gap:8px 22px;color:var(--muted);font-size:12px;margin:8px 0 0}
.grid{display:grid;gap:14px}.g2{grid-template-columns:repeat(2,minmax(0,1fr))}.g3{grid-template-columns:repeat(3,minmax(0,1fr))}.g4{grid-template-columns:repeat(4,minmax(0,1fr))}
.card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:16px 18px}
.card .k{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);font-weight:700}
.card .v{font-size:24px;font-weight:750;color:var(--navy);line-height:1.2;margin-top:3px}
.card .s{font-size:12px;color:var(--muted)}
.score-hero{display:grid;grid-template-columns:170px minmax(0,1fr);gap:26px;align-items:center;background:linear-gradient(135deg,#f8fbff,#eef5ff);border:1px solid #d3e2f7;border-radius:14px;padding:24px}
.score-hero .grade{font-size:13px;font-weight:700;color:var(--navy)}.score-hero .provisional{color:#b45309;font-size:12px;font-weight:700}
.score-hero ul{margin:8px 0 0;padding-left:18px;color:#334155;font-size:13px}
.badge{display:inline-flex;align-items:center;gap:5px;border-radius:999px;padding:3px 9px;font-size:10.5px;font-weight:700;letter-spacing:.02em;white-space:nowrap}
.chip{display:inline-block;border-radius:4px;padding:2px 7px;font-size:10.5px;font-weight:700;letter-spacing:.03em}
.mono{font-family:Consolas,"SFMono-Regular",Menlo,monospace;font-size:11.5px}
.muted{color:var(--muted)}.small{font-size:12px}.tiny{font-size:10.5px}
table{width:100%;border-collapse:collapse;margin:8px 0 12px;font-size:12px;table-layout:fixed}
th{background:#f1f5fb;color:#334155;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.08em;padding:8px 9px;border:1px solid var(--line);vertical-align:bottom}
td{padding:8px 9px;border:1px solid var(--line);vertical-align:top;overflow-wrap:break-word}
tr:nth-child(even) td{background:#fbfdff}
.table-wrap{width:100%;overflow-x:auto}
.kv{display:grid;grid-template-columns:190px minmax(0,1fr);border:1px solid var(--line);border-radius:10px;overflow:hidden}
.kv>div{padding:9px 12px;border-top:1px solid var(--line);font-size:12.5px;overflow-wrap:anywhere}.kv>div:nth-child(-n+2){border-top:0}
.kv .k{background:#f7f9fd;color:#475569;font-weight:650}
.bar-row{display:grid;grid-template-columns:150px minmax(0,1fr) 44px;gap:10px;align-items:center;margin:6px 0;font-size:12px}
.bar{height:11px;background:#edf2f9;border-radius:99px;overflow:hidden}.bar>i{display:block;height:100%;border-radius:99px}
.finding{border:1px solid var(--line);border-left:5px solid #94a3b8;border-radius:10px;margin:18px 0;padding:18px 20px;background:#fff;break-inside:avoid;page-break-inside:avoid}
.finding-head{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:6px}
.finding h3{margin:0;font-size:17px;flex:1 1 320px;min-width:0;overflow-wrap:anywhere}
.finding .fid{font-size:11px;color:var(--muted);font-family:Consolas,monospace}
.finding .facts{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin:10px 0 12px}
.finding .fact{background:#f8fafd;border:1px solid #e7edf6;border-radius:7px;padding:7px 9px;font-size:11px;color:var(--muted)}
.finding .fact b{display:block;color:var(--ink);font-size:12px;margin-top:1px;overflow-wrap:anywhere}
.callout{border-radius:8px;padding:10px 12px;font-size:12.5px;margin:10px 0;border:1px solid}
.callout.warn{background:#fffbeb;border-color:#fde68a;color:#78350f}.callout.info{background:#eff6ff;border-color:#bfdbfe;color:#1e3a8a}.callout.danger{background:#fef2f2;border-color:#fecaca;color:#7f1d1d}
.evidence{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:10px 12px;margin:8px 0;font-family:Consolas,Menlo,monospace;font-size:11px;white-space:pre-wrap;overflow-wrap:anywhere;max-height:280px;overflow:auto}
.evidence .r{color:#0e7490}.evidence .u{color:#7c3aed}.evidence .m{color:#0f172a}
.msg{border-left:3px solid #cbd5e1;padding:4px 0 4px 9px;margin:6px 0}.msg.user{border-color:#2563eb}.msg.system{border-color:#7c3aed}.msg.assistant{border-color:#0891b2}
.subhead{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#475569;margin:14px 0 4px}
.toc{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:4px 28px;font-size:12.5px;margin-top:10px}
.toc a{color:#1e3a8a}.toc span{color:var(--muted);font-size:11px;margin-left:5px}
.status{font-weight:700;font-size:10.5px;text-transform:uppercase;letter-spacing:.04em}
.st-passed{color:#15803d}.st-failed{color:#b91c1c}.st-inconclusive{color:#a16207}.st-skipped,.st-queued,.st-running{color:#64748b}.st-error{color:#7c3aed}
.note{font-size:11.5px;color:var(--muted)}
.signature{margin-top:28px;border-top:1px solid var(--line);padding-top:14px;font-size:12px;color:var(--muted)}
.footer{padding:20px 56px 34px;border-top:1px solid var(--line);color:var(--muted);font-size:11px;display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:center}
.footer .footmark{display:inline-flex;align-items:center;gap:7px}
@media (max-width:820px){html{font-size:14px}main{box-shadow:none}.sheet,.cover{padding:28px 20px}.cover h1{font-size:32px}.cover .confidential{display:none}.cover .meta,.g2,.g3,.g4,.finding .facts{grid-template-columns:repeat(2,minmax(0,1fr))}.score-hero{grid-template-columns:1fr}.kv{grid-template-columns:1fr}.kv>div:nth-child(2){border-top:1px solid var(--line)}.kv .k{border-bottom:0}.toc{grid-template-columns:1fr}.footer{padding:18px 20px}}
@media (max-width:480px){.cover h1{font-size:26px}.cover .meta,.g2,.g3,.g4,.finding .facts{grid-template-columns:1fr}.bar-row{grid-template-columns:100px minmax(0,1fr) 36px}.finding{padding:14px}}
@media print{body{background:#fff}main{box-shadow:none;max-width:none}.cover{min-height:255mm;page-break-after:always}.sheet{padding:0 2mm}.section{padding:18px 0}.finding,.card,.score-hero,.kv{break-inside:avoid;page-break-inside:avoid}tr{break-inside:avoid}h2{break-after:avoid}.print-hide{display:none}.evidence{max-height:none;overflow:visible}.footer{display:none}@page{size:A4;margin:16mm 14mm}}
"""


def _e(x) -> str:
    return html.escape("" if x is None else str(x), quote=True)


def _pct(v) -> str:
    try:
        return f"{float(v):.0%}"
    except (TypeError, ValueError):
        return "n/a"


def _ts(v, suffix: bool = False) -> str:
    """Compact an ISO timestamp for display without losing the UTC date."""
    if v is None or v == "":
        return "—"
    m = re.match(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", str(v))
    if not m:
        return str(v)
    return f"{m.group(1)} {m.group(2)}" + (" UTC" if suffix else "")


def _score_svg(score, size=150) -> str:
    value = 0 if score is None else max(0, min(100, float(score)))
    r = 54
    circ = 2 * 3.14159265 * r
    dash = circ * value / 100
    color = "#0891b2" if value >= 75 else "#d97706" if value >= 50 else "#dc2626"
    return (
        f'<svg viewBox="0 0 150 150" width="{size}" height="{size}" role="img" aria-label="Security score {value:.0f} of 100">'
        f'<circle cx="75" cy="75" r="{r}" fill="none" stroke="#dbe7f5" stroke-width="11"/>'
        f'<circle cx="75" cy="75" r="{r}" fill="none" stroke="{color}" stroke-width="11" stroke-linecap="round" '
        f'stroke-dasharray="{circ:.1f}" stroke-dashoffset="{circ - dash:.1f}" transform="rotate(-90 75 75)"/>'
        f'<text x="75" y="72" text-anchor="middle" font-size="30" font-weight="750" fill="#0b1730">{_e("N/A" if score is None else round(value))}</text>'
        f'<text x="75" y="91" text-anchor="middle" font-size="9" letter-spacing="1.5" fill="#64748b">SCORE / 100</text></svg>'
    )


def _badge(code: str, label: str) -> str:
    return f'<span class="badge" style="color:{CLASS_COLOR.get(code, "#475569")};background:{CLASS_BG.get(code, "#f1f5f9")}">{_e(label)}</span>'


def _sev(sev: str) -> str:
    return f'<span class="chip" style="color:{SEV_COLOR.get(sev, "#64748b")};background:{SEV_BG.get(sev, "#f8fafc")}">{_e(str(sev).upper())}</span>'


def _yes(v) -> str:
    return "Yes" if v else "No"


def _bar_rows(items, maximum=None) -> str:
    maximum = max([1] + [v for _, v, _ in items]) if maximum is None else max(1, maximum)
    rows = []
    for label, value, color in items:
        width = max(1, round(100 * (value or 0) / maximum))
        rows.append(
            f'<div class="bar-row"><span>{_e(label)}</span><div class="bar"><i style="width:{width}%;background:{color}"></i></div><b>{_e(value)}</b></div>'
        )
    return "".join(rows)


def _toc() -> str:
    sections = [
        ("cover", "Cover"), ("control", "Document control"), ("executive", "Executive summary"),
        ("scope", "Scope, authorization and limitations"), ("target", "Target configuration"),
        ("method", "Assessment methodology"), ("taxonomy", "Finding classification"),
        ("overview", "Risk overview"), ("findings", "Detailed findings"), ("inventory", "Test inventory"),
        ("roadmap", "Risk analysis and remediation roadmap"), ("appendix", "Appendix and integrity"),
    ]
    return '<nav class="toc">' + "".join(f'<div><a href="#{sid}">{_e(title)}</a></div>' for sid, title in sections) + "</nav>"


def _front(model: dict) -> str:
    a, t, sc, sm, st = model["assessment"], model["target"], model["score"], model["summary"], model["statistics"]
    cls = st["classifications"]
    overall = sc.get("overall")
    grade_txt = sc.get("grade") or "Not assessed"
    provisional = "Provisional" if sc.get("provisional") else "Final"
    counts = [
        ("Confirmed", cls["confirmed_vulnerability"], CLASS_COLOR["confirmed_vulnerability"]),
        ("Likely", cls["likely_vulnerability"], CLASS_COLOR["likely_vulnerability"]),
        ("Unsafe behaviour", cls["unsafe_behavior"], CLASS_COLOR["unsafe_behavior"]),
        ("Potential", cls["potential_vulnerability"], CLASS_COLOR["potential_vulnerability"]),
        ("Inconclusive", cls["inconclusive"], CLASS_COLOR["inconclusive"]),
        ("False positive", cls["false_positive"], CLASS_COLOR["false_positive"]),
    ]
    class_cards = "".join(
        f'<div class="card"><div class="k">{_e(label)}</div><div class="v" style="color:{color}">{n}</div></div>'
        for label, n, color in counts
    )
    test = st["tests"]
    key_points = "".join(f"<li>{_e(x)}</li>" for x in sm["key_points"])
    roadmap = "".join(
        f'<tr><td>{_e(r["priority"])}</td><td>{_e(r["window"])}</td><td>{_e(r["label"])}</td><td>{r["count"]}</td><td>{_e(r["action"])}</td></tr>'
        for r in model["risk_analysis"]["roadmap"]
    ) or '<tr><td colspan="5">No findings require a remediation action.</td></tr>'

    target_rows = [
        ("Provider", t.get("provider")), ("Model", t.get("model")),
        ("Endpoint", t.get("endpoint") or "Provider default"),
        ("Intensity profile", t.get("intensity")),
        ("Request budget", (t.get("limits") or {}).get("max_requests")),
        ("Max retries", (t.get("limits") or {}).get("retries")),
        ("System prompt", "Configured — content intentionally not reproduced" if t.get("system_prompt_configured") else "Harness default"),
        ("AI-assisted analysis", _yes(t.get("ai_analysis"))),
        ("Parameters", ", ".join(f"{k}={v}" for k, v in (t.get("params") or {}).items()) or "Provider defaults"),
    ]
    target_html = "".join(f'<div class="k">{_e(k)}</div><div>{_e(v)}</div>' for k, v in target_rows)

    scope_in = "".join(f"<li>{_e(x)}</li>" for x in model["scope"]["in_scope"])
    scope_out = "".join(f"<li>{_e(x)}</li>" for x in model["scope"]["out_of_scope"])
    limits = "".join(f"<li>{_e(x)}</li>" for x in model["scope"]["limitations"])
    phases = "".join(f'<tr><td><b>{_e(p["phase"])}</b></td><td>{_e(p["detail"])}</td></tr>' for p in model["methodology"]["phases"])
    taxonomy = "".join(
        f'<tr><td>{_badge(x["code"], x["label"])}</td><td>{_e(x["definition"])}</td><td>{_e(x["cvss_policy"])}</td><td class="mono">{x["score_factor"]:.2f}</td></tr>'
        for x in model["taxonomy"]
    )
    cat_rows = "".join(
        f'<tr><td>{_e(c["label"])}</td><td>{_e("N/A" if c["score"] is None else c["score"])}</td><td>{c["selected"]}</td><td>{c["tested"]}</td><td>{c["passed"]}</td><td>{c["failed"]}</td><td>{c["inconclusive"]}</td><td>{c["not_tested"]}</td></tr>'
        for c in model["category_scores"]
    ) or '<tr><td colspan="8">No category was selected.</td></tr>'
    sev_bars = _bar_rows([(s.title(), st["severity"][s], SEV_COLOR[s]) for s in ("critical", "high", "medium", "low", "info")])
    cls_bars = _bar_rows([(label, n, color) for label, n, color in counts])
    brand_html = f'<img class="brand-logo" src="{LOGO_DATA}" alt="ZeroDay Security Services">' if LOGO_DATA else ""

    return f"""
<header class="cover" id="cover">
  <div class="brandline">{brand_html}</div>
  <div class="eyebrow">AI Security Assessment Report · {_e(PRODUCT)}</div>
  <h1>{_e(a.get("name"))}</h1>
  <p class="subject">Evidence-aware assessment of <b>{_e(t.get("provider"))} / {_e(t.get("model"))}</b>. Findings are classified by the evidence actually observed, not by the attack name.</p>
  <div class="scorebox"><div class="num">{_e("N/A" if overall is None else overall)}</div><div class="lbl">Security score / 100<br><b>{_e(grade_txt)}</b> · {_e(provisional)}</div></div>
  <div class="meta">
    <div><span>Assessment ID</span><b class="mono">{_e(a.get("id"))}</b></div>
    <div><span>Report</span><b class="mono">{_e(model["report_id"])} · v{model["version"]}</b></div>
    <div><span>Generated</span><b>{_e(_ts(model["generated_at"], True))}</b></div>
    <div><span>Organization</span><b>{_e(a.get("organization"))}</b></div>
  </div>
  <div class="confidential">Confidential — authorized recipients only</div>
</header>

<div class="sheet">
<section class="section" id="control">
  <div class="kicker">Document control</div>
  <h2>Report identification and navigation</h2>
  <p class="lead">This report is a rendering of persisted assessment records. The JSON export is the canonical machine-readable copy; HTML, PDF and CSV are generated from the same model.</p>
  <div class="kv">
    <div class="k">Product</div><div>{_e(PRODUCT)} — {_e(COMPANY)}</div>
    <div class="k">Report ID / version</div><div class="mono">{_e(model["report_id"])} · version {model["version"]}</div>
    <div class="k">Report schema / methodology</div><div class="mono">{_e(model["schema_version"])} / {_e(model["methodology_version"])}</div>
    <div class="k">Assessment status</div><div>{_e(a.get("status"))}</div>
    <div class="k">Assessment started (UTC)</div><div>{_e(_ts(a.get("created_at"), True))}</div>
    <div class="k">Assessment finished (UTC)</div><div>{_e(_ts(a.get("finished_at"), True) if a.get("finished_at") else "Not recorded")}</div>
    <div class="k">Report owner</div><div>{_e(a.get("owner"))}</div>
    <div class="k">Integrity manifest (SHA-256)</div><div class="mono">{_e(model["integrity"]["manifest_sha256"])}</div>
  </div>
  {_toc()}
</section>

<section class="section" id="executive">
  <div class="kicker">01 · Executive summary</div>
  <h2>Security posture at a glance</h2>
  <div class="score-hero">
    {_score_svg(overall)}
    <div>
      <p><b>{_e(sm["posture"])}</b></p>
      <ul>{key_points}</ul>
      <p class="note">{_e(model["score_reconciliation"]["note"])}</p>
    </div>
  </div>
  <div class="grid g3" style="margin-top:14px">
    <div class="card"><div class="k">Coverage</div><div class="v">{_pct(sc.get("coverage"))}</div><div class="s">{test["passed"] + test["failed"]} of {test["total"]} selected tests produced a pass/fail result</div></div>
    <div class="card"><div class="k">Validated findings</div><div class="v">{st["validated_findings"]}</div><div class="s">Confirmed + likely · {st["findings_total"]} records including observations</div></div>
    <div class="card"><div class="k">Provisional score</div><div class="v">{_e("Yes" if sc.get("provisional") else "No")}</div><div class="s">A score below 60% coverage is provisional and must not be treated as a final posture.</div></div>
  </div>
  <h4>Finding classification distribution</h4>
  <div class="grid g3">{class_cards}</div>
  <h4>Assessment narrative</h4>
  <p>{_e(sm["posture"])}</p>
  {f'<div class="callout info"><b>Recorded narrative.</b> The assessment’s stored narrative is reproduced for context only and may predate the current classification methodology: “{_e(sm["recorded_narrative"])}”</div>' if sm.get("recorded_narrative") else ""}
</section>

<section class="section" id="scope">
  <div class="kicker">02 · Scope and limitations</div>
  <h2>What was tested — and what was not</h2>
  <p class="lead">The assessment is limited to the configured model API. Application integration, tool execution and downstream impact are explicitly out of scope unless recorded as observed evidence.</p>
  <div class="grid g2">
    <div class="card"><h4 style="margin-top:0">In scope</h4><ul>{scope_in}</ul></div>
    <div class="card"><h4 style="margin-top:0">Out of scope</h4><ul>{scope_out}</ul></div>
  </div>
  <h4>Authorization</h4>
  <div class="kv">
    <div class="k">Authorization confirmed</div><div>{_yes(a.get("authorization_confirmed"))}</div>
    <div class="k">Endpoint owner confirmed</div><div>{_yes(a.get("endpoint_owner_confirmed"))}</div>
    <div class="k">Statement</div><div>{_e(a.get("authorization_statement") or "Not recorded")}</div>
  </div>
  <h4>Limitations</h4><ul>{limits}</ul>
</section>

<section class="section" id="target">
  <div class="kicker">03 · Target configuration</div>
  <h2>System under test</h2>
  <p class="lead">Configuration is reproduced from the assessment record at execution time. The system prompt is never included in the report.</p>
  <div class="kv">{target_html}</div>
</section>

<section class="section" id="method">
  <div class="kicker">04 · Methodology</div>
  <h2>Bounded testing with evidence-aware conclusions</h2>
  <p>{_e(model["methodology"]["description"])}</p>
  <div class="table-wrap"><table><colgroup><col style="width:24%"><col></colgroup><thead><tr><th>Phase</th><th>What happens</th></tr></thead><tbody>{phases}</tbody></table></div>
  <h4>Detection layers</h4>
  <div class="table-wrap"><table><colgroup><col style="width:38%"><col></colgroup><thead><tr><th>Layer</th><th>Use in this assessment</th></tr></thead><tbody>{"".join(f'<tr><td>{_e(d["method"])}</td><td>{_e(d["use"])}</td></tr>' for d in model["methodology"]["detection"])}</tbody></table></div>
</section>

<section class="section" id="taxonomy">
  <div class="kicker">05 · Finding classification</div>
  <h2>What each conclusion means</h2>
  <p class="lead">A detector firing is an observation. A vulnerability claim requires evidence that supports the specific impact. The six classifications below are used consistently across every finding, score and export.</p>
  <div class="table-wrap"><table><colgroup><col style="width:22%"><col style="width:34%"><col><col style="width:9%"></colgroup>
  <thead><tr><th>Classification</th><th>Definition</th><th>CVSS policy</th><th>Score factor</th></tr></thead><tbody>{taxonomy}</tbody></table></div>
</section>

<section class="section" id="overview">
  <div class="kicker">06 · Vulnerability statistics and risk overview</div>
  <h2>Results, coverage and category posture</h2>
  <div class="grid g2">
    <div class="card"><h4 style="margin-top:0">Effective severity of validated findings</h4>{sev_bars or '<p class="muted small">No validated findings.</p>'}<p class="note">Inconclusive and false-positive records are excluded from severity distribution.</p></div>
    <div class="card"><h4 style="margin-top:0">Classification distribution</h4>{cls_bars}<p class="note">Unsafe behaviour and potential vulnerabilities are not counted as confirmed vulnerabilities.</p></div>
  </div>
  <h4>Test execution summary</h4>
  <div class="grid g4">
    <div class="card"><div class="k">Selected</div><div class="v">{test["total"]}</div></div>
    <div class="card"><div class="k">Passed</div><div class="v" style="color:#15803d">{test["passed"]}</div></div>
    <div class="card"><div class="k">Failed (indicator observed)</div><div class="v" style="color:#b91c1c">{test["failed"]}</div></div>
    <div class="card"><div class="k">Inconclusive / not tested</div><div class="v" style="color:#a16207">{test["inconclusive"] + test["skipped"] + test["not_started"] + test["error"]}</div></div>
  </div>
  <h4>Security score by category</h4>
  <div class="table-wrap"><table><colgroup><col style="width:27%"><col style="width:9%"><col span="6"></colgroup>
  <thead><tr><th>Category</th><th>Score</th><th>Selected</th><th>Tested</th><th>Passed</th><th>Failed</th><th>Inconclusive</th><th>Not tested</th></tr></thead><tbody>{cat_rows}</tbody></table></div>
  <p class="note">A category score of “N/A” means no test in that category produced a pass/fail result. Untested categories are not treated as secure.</p>
</section>

<section class="section" id="findings">
  <div class="kicker">07 · Detailed findings</div>
  <h2>Evidence, validation and impact scope</h2>
  <p class="lead">{st["findings_total"]} finding record(s) are included. Each section preserves the test ID, target, provider, timestamp, procedure, redacted request/response, expected versus actual behaviour, detection rule, confidence, validation status and impact states.</p>
  #FINDINGS#
</section>

<section class="section" id="inventory">
  <div class="kicker">08 · Test inventory</div>
  <h2>Every selected test and its result</h2>
  <p class="lead">This inventory is the complete record of executions for the assessment. “Not tested” is never reported as secure. Timestamps are UTC.</p>
  #INVENTORY#
</section>

<section class="section" id="roadmap">
  <div class="kicker">09 · Risk analysis and remediation recommendations</div>
  <h2>Prioritised actions</h2>
  <p class="lead">Priority is driven by classification and evidence, not by the attack name alone. Confirmed findings come first; potential and unsafe-behaviour findings require integration validation before exploitability can be claimed.</p>
  <div class="table-wrap"><table><colgroup><col style="width:11%"><col style="width:12%"><col style="width:22%"><col style="width:7%"><col></colgroup>
  <thead><tr><th>Priority</th><th>Window</th><th>Classification</th><th>Count</th><th>Required action</th></tr></thead><tbody>{roadmap}</tbody></table></div>
  <h4>Finding-specific remediation</h4>
  <div class="table-wrap"><table><colgroup><col style="width:11%"><col style="width:30%"><col></colgroup>
  <thead><tr><th>Finding</th><th>Title</th><th>Remediation</th></tr></thead><tbody>
  {"".join(f'<tr><td class="mono">{_e(f["finding_id"])}</td><td>{_e(f["title"])}</td><td>{_e(f["remediation"])}</td></tr>' for f in model["findings"] if f["classification_code"] not in ("false_positive",)) or '<tr><td colspan="3">No remediation required for executed tests.</td></tr>'}
  </tbody></table></div>
</section>
"""


def _state_cards(f: dict) -> str:
    tool = f.get("tool_execution") or {}
    out = f.get("output_security") or {}
    svc = f.get("service_impact") or {}
    if tool.get("applicable"):
        rows = "".join(
            f'<div class="k">{_e(k)}</div><div>{_e(v)}</div>'
            for k, v in (
                ("Proposed", _yes(tool.get("proposed"))),
                ("Emitted in response", _yes(tool.get("emitted"))),
                ("Authorized", _yes(tool.get("authorized"))),
                ("Executed", _yes(tool.get("executed"))),
                ("Execution confirmed", _yes(tool.get("execution_confirmed"))),
                ("Emitted calls", ", ".join(tool.get("emitted_calls") or []) or "None"),
            )
        )
        tool_html = f'<div class="card"><h4 style="margin-top:0">Tool execution states</h4><div class="kv">{rows}</div><p class="note" style="margin-top:8px">{_e(tool.get("evidence"))}</p></div>'
    else:
        tool_html = '<div class="card"><h4 style="margin-top:0">Tool execution</h4><p class="note">Not applicable to this test.</p></div>'
    if out.get("applicable"):
        rows = "".join(
            f'<div class="k">{_e(k)}</div><div>{_e(v)}</div>'
            for k, v in (
                ("Unsafe output generated", _yes(out.get("unsafe_output_generated"))),
                ("Output type", out.get("output_type") or "n/a"),
                ("Rendered", _yes(out.get("rendered"))),
                ("Script executed", _yes(out.get("script_executed"))),
                ("Data transfer observed", _yes(out.get("data_transfer_observed"))),
                ("Impact demonstrated", _yes(out.get("impact_demonstrated"))),
            )
        )
        out_html = f'<div class="card"><h4 style="margin-top:0">Output security states</h4><div class="kv">{rows}</div><p class="note" style="margin-top:8px">{_e(out.get("notes"))}</p></div>'
    else:
        out_html = '<div class="card"><h4 style="margin-top:0">Output security</h4><p class="note">Not applicable to this test.</p></div>'
    if svc.get("applicable"):
        rows = "".join(
            f'<div class="k">{_e(k)}</div><div>{_e(v)}</div>'
            for k, v in (
                ("Requests observed", svc.get("requests_observed")),
                ("Timeouts", svc.get("timeouts")),
                ("Server errors", svc.get("server_errors")),
                ("Rate-limited responses", svc.get("rate_limited_responses")),
                ("Service impact demonstrated", _yes(svc.get("service_impact_demonstrated"))),
                ("Availability impact", svc.get("availability_impact")),
            )
        )
        svc_html = f'<div class="card"><h4 style="margin-top:0">Service impact states</h4><div class="kv">{rows}</div><p class="note" style="margin-top:8px">{_e(svc.get("notes"))}</p></div>'
    else:
        svc_html = ""
    svc_block = f'<div style="margin-top:12px">{svc_html}</div>' if svc_html else ""
    return f'<div class="grid g2" style="margin-top:12px">{tool_html}{out_html}</div>{svc_block}'


def _matched_rules(f: dict) -> str:
    rules = (f.get("evidence_validation") or {}).get("detection_rule", {}).get("matched_rules") or (f.get("evidence") or {}).get("matched_rules") or []
    if not rules:
        return '<p class="note">No matched rule was persisted for this finding.</p>'
    rows = []
    for r in rules:
        if not isinstance(r, dict):
            rows.append(f'<tr><td class="mono">{_e(r)}</td><td>—</td><td>—</td><td>—</td></tr>')
            continue
        rows.append(
            f'<tr><td class="mono">{_e(r.get("rule"))}</td><td>{_e(r.get("conf"))}</td><td>{_e("soft" if r.get("soft") else "deterministic")}</td><td>{_e(r.get("detail") or r.get("note") or "")}</td></tr>'
        )
    return f'<div class="table-wrap"><table><colgroup><col style="width:22%"><col style="width:10%"><col style="width:14%"><col></colgroup><thead><tr><th>Rule</th><th>Confidence</th><th>Type</th><th>Detail</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>'


def _transcript_html(f: dict) -> str:
    ev = f.get("transcript") or {}
    parts = []
    if ev.get("system"):
        parts.append(f'<div class="msg system"><b>System prompt (redacted, may be harness default):</b><br>{_e(ev["system"])}</div>')
    for m in ev.get("messages") or []:
        role = _e(m.get("role") or "user")
        parts.append(f'<div class="msg {role}"><b>{role.title()}:</b><br>{_e(m.get("content"))}</div>')
    for i, r in enumerate(ev.get("responses") or [], 1):
        calls = "".join(f'<div class="mono">→ {_e(c.get("name"))}({_e(c.get("arguments"))})</div>' for c in (r.get("tool_calls") or []))
        meta = " · ".join(x for x in (
            f"status={_e(r.get('status'))}" if r.get("status") else "",
            f"latency={_e(r.get('latency_ms'))} ms" if r.get("latency_ms") is not None else "",
        ) if x)
        err = f'<div class="mono" style="color:#b91c1c">{_e(r.get("error"))}</div>' if r.get("error") else ""
        parts.append(f'<div class="msg assistant"><b>Model response {i}:</b> <span class="note">{_e(meta)}</span><br>{_e(r.get("text") or "(no text)")}{calls}{err}</div>')
    return "".join(parts) or '<p class="note">No transcript was persisted.</p>'


def _finding_card(f: dict, index: int) -> str:
    cls = f.get("classification") or {}
    code = f.get("classification_code") or "inconclusive"
    color = CLASS_COLOR.get(code, "#64748b")
    cv = f.get("cvss")
    if cv:
        cvss_html = f'<div class="callout info"><b>CVSS {_e(cv.get("score"))}</b> · <span class="mono">{_e(cv.get("vector"))}</span><br>{_e(cv.get("basis"))}</div>'
    else:
        cvss_html = f'<div class="callout warn"><b>CVSS not assigned.</b> {_e(f.get("cvss_suppressed_reason") or "No defensible CVSS score could be derived from the available evidence.")}</div>'
    facts = [
        ("Test ID", f.get("attack_id")), ("Effective severity", f.get("severity")),
        ("Potential severity", f.get("potential_severity")), ("Confidence", _pct(f.get("confidence"))),
        ("Validation", (cls.get("validation_status") or "needs_review").replace("_", " ")),
        ("Evidence quality", cls.get("evidence_quality") or "weak"),
        ("Impact scope", cls.get("impact_scope") or "none"),
        ("Detected at (UTC)", _ts(f.get("detected_at"))),
        ("Status / triage", f'{f.get("status") or "-"} / {f.get("triage") or "-"}'),
        ("Integration testing", _yes(cls.get("requires_integration_testing"))),
    ]
    fact_html = "".join(f'<div class="fact">{_e(k)}<b>{_e(v)}</b></div>' for k, v in facts)
    ev = f.get("evidence_validation") or {}
    expected = ev.get("expected_behavior") or ""
    actual = ev.get("actual_behavior") or ""
    limitations = "".join(f"<li>{_e(x)}</li>" for x in (ev.get("limitations") or [])) or "<li>Evidence is limited to the model/API boundary.</li>"
    steps = "".join(f"<li>{_e(s)}</li>" for s in f.get("reproduction_steps") or []) or "<li>No reproduction steps were persisted.</li>"
    frameworks = " · ".join(x for x in (
        "OWASP: " + ", ".join(f.get("owasp") or []) if f.get("owasp") else "",
        "CWE: " + ", ".join(f.get("cwe") or []) if f.get("cwe") else "",
        "ATLAS: " + ", ".join(f.get("atlas") or []) if f.get("atlas") else "",
        "NIST: " + ", ".join(f.get("nist") or []) if f.get("nist") else "",
    ) if x)
    evidence_note = "This finding is retained for audit only and is excluded from risk scoring." if code == "false_positive" else ""
    return f"""
<article class="finding" id="finding-{_e(f.get("finding_id"))}" style="border-left-color:{color}">
  <div class="finding-head">
    {_badge(code, f.get("classification_label") or code)} {_sev(f.get("severity"))}
    <h3>{index}. {_e(f.get("title"))}</h3>
    <span class="fid">{_e(f.get("finding_id"))}</span>
  </div>
  <div class="meta-row"><span>{_e(f.get("category_label"))}</span><span>Target: {_e((ev.get("target_model") or ""))}</span><span>Provider: {_e(ev.get("provider") or "")}</span><span>{_e(frameworks)}</span></div>
  <div class="facts">{fact_html}</div>
  <p><b>Observed behaviour.</b> {_e(actual)}</p>
  <div class="grid g2">
    <div class="callout info"><b>Expected secure behaviour.</b><br>{_e(expected)}</div>
    <div class="callout {'danger' if code in ('confirmed_vulnerability', 'likely_vulnerability') else 'warn'}"><b>Classification rationale.</b><br>{_e(cls.get("rationale"))}</div>
  </div>
  <p class="note"><b>Severity basis.</b> {_e(f.get("severity_basis") or "Derived from the classification and observed evidence.")}</p>
  {evidence_note and f'<div class="callout warn">{_e(evidence_note)}</div>'}
  {cvss_html}
  <div class="subhead">Detection evidence</div>
  <p class="small"><b>Method:</b> {_e((f.get("detection") or {}).get("method") or ev.get("detection_rule", {}).get("method") or "n/a")}<br><b>Reason:</b> {_e((f.get("detection") or {}).get("reason") or ev.get("detection_rule", {}).get("reason") or "n/a")}</p>
  {_matched_rules(f)}
  {_state_cards(f)}
  <div class="subhead">Procedure and redacted evidence</div>
  <div class="evidence">{_transcript_html(f)}</div>
  <div class="grid g2">
    <div><h4>Reproduction steps</h4><ol>{steps}</ol></div>
    <div><h4>Remediation</h4><p>{_e(f.get("remediation") or "No remediation guidance was recorded.")}</p></div>
  </div>
  <h4>Evidence limitations specific to this finding</h4><ul>{limitations}</ul>
  <p class="tiny muted">Evidence SHA-256: <span class="mono">{_e(f.get("evidence_sha256") or "not available for legacy record")}</span></p>
</article>"""


def _findings(model: dict) -> str:
    findings = model["findings"]
    if not findings:
        return ('<div class="callout info"><b>No findings were recorded by the executed tests.</b> '
                'This is not a statement that the system is free of vulnerabilities. Untested modules and application integration remain outside the evidence base.</div>')
    return "".join(_finding_card(f, i) for i, f in enumerate(findings, 1))


def _inventory(model: dict) -> str:
    rows = []
    for t in model["tests"]:
        cls = f'<span class="badge" style="color:{CLASS_COLOR.get(t["classification_code"], "#475569")};background:{CLASS_BG.get(t["classification_code"], "#f1f5f9")}">{_e(t["classification_label"])}</span>' if t.get("classification_code") else "—"
        finding = f'<span class="mono">{_e(t["finding_id"])}</span>' if t.get("finding_id") else "—"
        reason = f'<div class="note">{_e(t["reason"])}</div>' if t.get("reason") else ""
        rows.append(
            f'<tr><td class="mono">{_e(t["test_id"])}</td><td>{_e(t["name"])}<div class="note">{_e(t["category_label"])}</div></td>'
            f'<td><span class="status st-{_e(t["status"])}">{_e(t["result"])}</span>{reason}</td><td>{cls}</td>'
            f'<td>{_e(_pct(t.get("confidence")) if t.get("confidence") is not None else "—")}</td><td>{finding}</td>'
            f'<td class="tiny">{_e(_ts(t.get("started_at")))}<br>{_e(_ts(t.get("finished_at")))}</td>'
            f'<td>{_e(t.get("duration_ms") if t.get("duration_ms") is not None else "—")}</td></tr>'
        )
    return f"""<div class="table-wrap"><table>
<colgroup><col style="width:11%"><col style="width:23%"><col style="width:15%"><col style="width:14%"><col style="width:6%"><col style="width:11%"><col style="width:14%"><col style="width:6%"></colgroup>
<thead><tr><th>Test ID</th><th>Test</th><th>Result</th><th>Classification</th><th>Conf.</th><th>Finding</th><th>Start / finish (UTC)</th><th>ms</th></tr></thead>
<tbody>{"".join(rows) or '<tr><td colspan="8">No tests were selected.</td></tr>'}</tbody></table></div>"""


def _appendix(model: dict) -> str:
    st = model["statistics"]
    hashes = "".join(
        f'<tr><td class="mono">{_e(h["finding_id"])}</td><td class="mono">{_e(h["evidence_sha256"])}</td></tr>'
        for h in model["integrity"].get("evidence_hashes", [])
    ) or '<tr><td colspan="2">No evidence hashes were recorded.</td></tr>'
    glossary = "".join(f'<tr><td><b>{_e(k)}</b></td><td>{_e(v)}</td></tr>' for k, v in model["appendix"]["glossary"])
    weights = ", ".join(f"{k}={v}" for k, v in model["appendix"]["scoring_weights"].items())
    return f"""
<section class="section" id="conclusion">
  <div class="kicker">10 · Conclusion</div>
  <h2>Conclusion and sign-off</h2>
  <p>{_e(model["summary"]["posture"])}</p>
  <ul>
    <li><b>Confirmed vulnerabilities:</b> {st["classifications"]["confirmed_vulnerability"]}. Confirmed findings require remediation and verification before release.</li>
    <li><b>Likely vulnerabilities:</b> {st["classifications"]["likely_vulnerability"]}. Reproduce and triage these findings; heuristic evidence is not a confirmed exploit.</li>
    <li><b>Unsafe behaviour and potential vulnerabilities:</b> {st["classifications"]["unsafe_behavior"] + st["classifications"]["potential_vulnerability"]}. Integration testing is required before claiming application impact.</li>
    <li><b>Inconclusive and false positives:</b> {st["classifications"]["inconclusive"] + st["classifications"]["false_positive"]}. Retained for audit; excluded from validated risk.</li>
    <li><b>Coverage:</b> {_pct(model["score"].get("coverage"))} ({st["tests"]["passed"] + st["tests"]["failed"]} pass/fail results out of {st["tests"]["total"]} selected tests).</li>
  </ul>
  <div class="signature">
    <p><b>{_e(COMPANY)}</b> · {_e(PRODUCT)}</p>
    <p class="note">This report was generated from persisted assessment records. Findings are valid for the tested configuration and time window. Re-test after remediation or material configuration change. The JSON export and its SHA-256 manifest are the canonical evidence record.</p>
    <p class="note">Report {_e(model["report_id"])} · version {model["version"]} · generated {_e(_ts(model["generated_at"], True))} · methodology {_e(model["methodology_version"])}</p>
  </div>
</section>

<section class="section" id="appendix">
  <div class="kicker">11 · Appendix</div>
  <h2>Integrity, glossary and report control</h2>
  <h4>Evidence integrity hashes</h4>
  <div class="table-wrap"><table><colgroup><col style="width:18%"><col></colgroup><thead><tr><th>Finding</th><th>Evidence SHA-256</th></tr></thead><tbody>{hashes}</tbody></table></div>
  <h4>Report manifest</h4>
  <div class="kv">
    <div class="k">Manifest SHA-256</div><div class="mono">{_e(model["integrity"]["manifest_sha256"])}</div>
    <div class="k">Algorithm</div><div>{_e(model["integrity"]["algorithm"])}</div>
    <div class="k">Integrity note</div><div>{_e(model["integrity"]["note"])}</div>
    <div class="k">Scoring weights</div><div>{_e(weights)}</div>
    <div class="k">Report generated by</div><div>{_e(COMPANY)} — {_e(PRODUCT)}</div>
    <div class="k">Company tagline</div><div>{_e(TAGLINE)}</div>
  </div>
  <h4>Glossary</h4>
  <div class="table-wrap"><table><colgroup><col style="width:18%"><col></colgroup><thead><tr><th>Term</th><th>Definition</th></tr></thead><tbody>{glossary}</tbody></table></div>
</section>
"""


def render_html(model: dict) -> bytes:
    body = _front(model)
    body = body.replace("#FINDINGS#", _findings(model)).replace("#INVENTORY#", _inventory(model))
    body += _appendix(model)
    a = model["assessment"]
    title = f"{PRODUCT} report — {a.get('name')}"
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="color-scheme" content="light"><title>{_e(title)}</title><style>{CSS}</style></head>
<body><main>
{body}
<footer class="footer"><span class="footmark">{_e(PRODUCT)} · {_e(COMPANY)}</span><span>Report {_e(model["report_id"])} v{model["version"]} · Assessment {_e(a.get("id"))}</span><span>Generated {_e(_ts(model["generated_at"], True))}</span></footer>
</main></body></html>"""
    return doc.encode("utf-8")
