"""
Streamlit dashboard for the AI Security Engineer project.

    streamlit run dashboard/app.py
"""
from __future__ import annotations

import os

import httpx
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

load_dotenv()
API_URL = os.getenv("API_URL", "http://localhost:8000").rstrip("/")
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

st.set_page_config(
    page_title="Security Dashboard",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ── Styling ───────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* page bg */
.stApp { background-color: #111318; color: #d4d8e1; }

/* sidebar */
section[data-testid="stSidebar"] {
    background-color: #1a1d24 !important;
    border-right: 1px solid #2a2d35;
}

.block-container { padding-top: 1.5rem !important; }

/* severity pill */
.pill {
    display: inline-block;
    font-size: 0.72rem;
    font-weight: 600;
    padding: 2px 9px;
    border-radius: 99px;
    letter-spacing: 0.04em;
}
.pill-CRITICAL { background:#3d1212; color:#f87171; border:1px solid #7f1d1d; }
.pill-HIGH     { background:#3a1f08; color:#fb923c; border:1px solid #7c2d12; }
.pill-MEDIUM   { background:#362904; color:#fbbf24; border:1px solid #78350f; }
.pill-LOW      { background:#0d2d17; color:#4ade80; border:1px solid #14532d; }

/* info boxes */
.infobox {
    background: #1a1d24;
    border: 1px solid #2a2d35;
    border-radius: 8px;
    padding: 14px 16px;
    margin-bottom: 10px;
    font-size: 0.85rem;
    line-height: 1.6;
    color: #c9cdd8;
}
.infobox-label {
    font-size: 0.68rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    color: #6b7280;
    margin-bottom: 5px;
}

/* code block */
div[data-testid="stCodeBlock"] pre {
    background: #0d1015 !important;
    border: 1px solid #2a2d35 !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.78rem !important;
}

/* stat card */
.stat-num {
    font-size: 2.4rem;
    font-weight: 600;
    line-height: 1;
    margin: 4px 0 2px;
}
.stat-lbl { font-size: 0.72rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.06em; }

/* chunk card */
.chunk {
    background: #161820;
    border: 1px solid #2a2d35;
    border-radius: 8px;
    padding: 12px 14px;
    margin-bottom: 10px;
    font-size: 0.83rem;
    color: #9ca3af;
    line-height: 1.55;
}
.chunk-head {
    display: flex;
    align-items: baseline;
    gap: 8px;
    margin-bottom: 6px;
}
.chunk-title { font-weight: 600; color: #d1d5db; font-size: 0.85rem; }
.chunk-sim { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: #6b7280; }
.chunk-tag-cwe { font-size: 0.68rem; color: #60a5fa; font-weight: 600; }
.chunk-tag-sem { font-size: 0.68rem; color: #6b7280; font-weight: 600; }
.chunk-foot { font-size: 0.68rem; color: #4b5563; margin-top: 8px; }

/* gen badge */
.gen-badge {
    display: inline-block;
    font-size: 0.72rem;
    padding: 3px 10px;
    border-radius: 6px;
    margin-bottom: 12px;
    font-weight: 500;
}
.gen-llm      { background:#0c2a1a; color:#4ade80; border:1px solid #166534; }
.gen-fallback { background:#1e2028; color:#9ca3af; border:1px solid #374151; }

/* note */
.note { background:#271e08; border:1px solid #854d0e; border-radius:6px;
        padding:10px 14px; font-size:0.82rem; color:#fbbf24; margin-bottom:10px; }

[data-testid="stDataFrame"] { border-radius: 8px !important; overflow: hidden !important; }

hr { border-color: #2a2d35 !important; margin: 1.2rem 0 !important; }
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
SEV_COLOR = {"CRITICAL": "#f87171", "HIGH": "#fb923c", "MEDIUM": "#fbbf24", "LOW": "#4ade80"}


def pill(severity: str) -> str:
    return f'<span class="pill pill-{severity}">{severity}</span>'


class ApiError(Exception):
    pass


def _get(path: str, **params):
    try:
        r = httpx.get(f"{API_URL}{path}", params=params or None, timeout=60)
    except httpx.HTTPError as exc:
        raise ApiError(
            f"Can't reach API at {API_URL}. Start it with: uvicorn backend.main:app"
        ) from exc
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail", r.text)
        except ValueError:
            detail = r.text
        raise ApiError(f"API {r.status_code} — {detail}")
    return r.json()


@st.cache_data(ttl=10, show_spinner=False)
def load_overview():
    return _get("/summary"), _get("/findings", limit=1000)


@st.cache_data(ttl=300, show_spinner="Loading analysis…")
def load_analysis(finding_id: str):
    return _get(f"/findings/{finding_id}/analysis")


def fmt_finding(f: dict) -> str:
    icon = SEV_ICON.get(f["severity"], "⚪")
    fp = f["file_path"] or "?"
    return f"{icon} {f['finding_type']}  —  {fp}:{f['line_number']}  [{f['scanner']}]"


# ── Page header ───────────────────────────────────────────────────────────────

st.markdown("## 🔐 Security Dashboard")
st.caption("AI-Powered Security Engineer for CI/CD — midterm prototype")
st.markdown("---")

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("### ⚙️ Filters")

    severity_filter = st.multiselect(
        "Severity", SEVERITIES, default=SEVERITIES
    )
    scanner_filter = st.multiselect(
        "Scanner", ["Semgrep", "Gitleaks"], default=["Semgrep", "Gitleaks"]
    )

    st.markdown("---")

    if st.button("↺ Refresh", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.markdown("---")
    st.markdown(f"""
<div style="font-size:0.73rem;color:#6b7280;line-height:1.7">
<b style="color:#9ca3af">API</b><br>
{API_URL}<br><br>
<b style="color:#9ca3af">Stack</b><br>
Semgrep · Gitleaks<br>
FastAPI · PostgreSQL<br>
pgvector · Streamlit<br><br>
<b style="color:#9ca3af">Note:</b> Advisory only.<br>
No auto-remediation.
</div>
""", unsafe_allow_html=True)

# ── Load data ─────────────────────────────────────────────────────────────────

try:
    summary, findings = load_overview()
except ApiError as exc:
    st.error(str(exc))
    st.stop()

# ── Summary stats ─────────────────────────────────────────────────────────────

c1, c2, c3, c4, c5 = st.columns(5)
with c1:
    st.markdown(f"""
<div class="infobox">
  <div class="stat-lbl">Total</div>
  <div class="stat-num" style="color:#e2e8f0">{summary['total']}</div>
</div>""", unsafe_allow_html=True)
with c2:
    st.markdown(f"""
<div class="infobox">
  <div class="stat-lbl">Critical</div>
  <div class="stat-num" style="color:#f87171">{summary['critical']}</div>
</div>""", unsafe_allow_html=True)
with c3:
    st.markdown(f"""
<div class="infobox">
  <div class="stat-lbl">High</div>
  <div class="stat-num" style="color:#fb923c">{summary['high']}</div>
</div>""", unsafe_allow_html=True)
with c4:
    st.markdown(f"""
<div class="infobox">
  <div class="stat-lbl">Medium</div>
  <div class="stat-num" style="color:#fbbf24">{summary['medium']}</div>
</div>""", unsafe_allow_html=True)
with c5:
    st.markdown(f"""
<div class="infobox">
  <div class="stat-lbl">Low</div>
  <div class="stat-num" style="color:#4ade80">{summary['low']}</div>
</div>""", unsafe_allow_html=True)

st.markdown("---")

if not findings:
    st.info("No findings yet. Run: `python -m scripts.run_pipeline`")
    st.stop()

# ── Findings table ────────────────────────────────────────────────────────────

visible = [
    f for f in findings
    if f["severity"] in severity_filter and f["scanner"] in scanner_filter
]

st.markdown(f"**Findings** — {len(visible)} shown / {len(findings)} total")

if not visible:
    st.warning("No findings match the current filters.")
    st.stop()

table = pd.DataFrame([{
    "": SEV_ICON.get(f["severity"], "⚪"),
    "Severity": f["severity"],
    "Type": f["finding_type"],
    "Scanner": f["scanner"],
    "File": f["file_path"],
    "Line": f["line_number"],
    "CWE": f["cwe"] or "—",
    "Status": f["status"],
} for f in visible])

sev_colors = {"CRITICAL": "#f87171", "HIGH": "#fb923c", "MEDIUM": "#fbbf24", "LOW": "#4ade80"}

styled = (
    table.style
    .map(lambda v: f"color:{sev_colors.get(v, '#9ca3af')};font-weight:600", subset=["Severity"])
    .set_properties(**{
        "background-color": "#161820",
        "color": "#c9cdd8",
        "border-color": "#2a2d35",
        "font-size": "0.83rem",
    })
)

st.dataframe(styled, hide_index=True, use_container_width=True,
             column_config={
                 "": st.column_config.TextColumn(width="small"),
                 "Line": st.column_config.NumberColumn(width="small"),
                 "CWE": st.column_config.TextColumn(width="small"),
             })

st.markdown("---")

# ── Finding selector ──────────────────────────────────────────────────────────

st.markdown("**Inspect a finding**")
selected = st.selectbox(
    "Pick a finding",
    visible,
    format_func=fmt_finding,
    key="selected_finding",
    label_visibility="collapsed",
)

st.markdown("")

left, right = st.columns([1, 1], gap="large")

# ── Left: metadata + evidence ─────────────────────────────────────────────────

with left:
    sev = selected["severity"]

    st.markdown(f"##### {SEV_ICON.get(sev, '')} {selected['title']}")
    st.markdown(pill(sev), unsafe_allow_html=True)
    st.markdown("")

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown(f"""
<div class="infobox">
  <div class="infobox-label">Scanner</div>
  {selected['scanner']}
</div>""", unsafe_allow_html=True)
    with col_b:
        st.markdown(f"""
<div class="infobox">
  <div class="infobox-label">CWE</div>
  {selected['cwe'] or '—'}
</div>""", unsafe_allow_html=True)

    col_c, col_d = st.columns(2)
    with col_c:
        rule_short = (selected["rule_id"] or "—").split(".")[-1]
        st.markdown(f"""
<div class="infobox">
  <div class="infobox-label">Rule</div>
  <code style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:#93c5fd">{rule_short}</code>
</div>""", unsafe_allow_html=True)
    with col_d:
        st.markdown(f"""
<div class="infobox">
  <div class="infobox-label">Status</div>
  {selected['status']}
</div>""", unsafe_allow_html=True)

    st.markdown(f"""
<div class="infobox">
  <div class="infobox-label">Location</div>
  <code style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:#93c5fd">{selected['file_path']}:{selected['line_number']}</code>
</div>""", unsafe_allow_html=True)

    st.markdown("**Scanner message**")
    desc = selected["description"] or "No description provided by the scanner."
    st.markdown(
        f'<div style="font-size:0.85rem;color:#9ca3af;line-height:1.6">{desc}</div>',
        unsafe_allow_html=True,
    )

    st.markdown("")
    st.markdown("**Evidence**")
    st.code(selected["evidence"] or "(no evidence available)", language="python")

# ── Right: analysis ───────────────────────────────────────────────────────────

with right:
    try:
        analysis = load_analysis(selected["id"])
    except ApiError as exc:
        st.error(str(exc))
        st.stop()

    gen = analysis["generated_by"]
    provider = analysis["provider"]

    if gen == "llm":
        st.markdown(f'<span class="gen-badge gen-llm">✨ AI via {provider}</span>',
                    unsafe_allow_html=True)
    else:
        st.markdown(
            '<span class="gen-badge gen-fallback">📚 Extractive fallback — no LLM configured</span>',
            unsafe_allow_html=True,
        )

    if analysis.get("note"):
        st.markdown(f'<div class="note">⚠️ {analysis["note"]}</div>', unsafe_allow_html=True)

    exp = analysis["explanation"]

    with st.expander("🔍 What is this vulnerability?", expanded=True):
        st.markdown(
            f'<div style="font-size:0.85rem;color:#c9cdd8;line-height:1.6">{exp["what_is_it"]}</div>',
            unsafe_allow_html=True,
        )

    with st.expander("⚠️ Why is it dangerous?", expanded=True):
        st.markdown(
            f'<div style="font-size:0.85rem;color:#c9cdd8;line-height:1.6">{exp["why_dangerous"]}</div>',
            unsafe_allow_html=True,
        )

    with st.expander("📌 CWE / OWASP", expanded=False):
        st.markdown(
            f'<div style="font-size:0.85rem;color:#c9cdd8;line-height:1.6">{exp["cwe_owasp"]}</div>',
            unsafe_allow_html=True,
        )

    with st.expander("🔧 How to fix it", expanded=True):
        st.markdown(
            f'<div style="font-size:0.85rem;color:#c9cdd8;line-height:1.6">{exp["recommended_practice"]}</div>',
            unsafe_allow_html=True,
        )

# ── RAG context ───────────────────────────────────────────────────────────────

st.markdown("---")
st.markdown("**Retrieved security context** (RAG knowledge base)")

context = analysis["retrieved_context"]
if not context:
    st.caption("No relevant entry found in the knowledge base.")
else:
    cols = st.columns(min(len(context), 2))
    for i, chunk in enumerate(context):
        is_cwe = chunk["match_type"] == "cwe"
        tag_cls = "chunk-tag-cwe" if is_cwe else "chunk-tag-sem"
        tag_txt = "exact CWE match" if is_cwe else "similarity match"
        dot = "●" if is_cwe else "◌"
        src = chunk.get("source") or "n/a"
        owasp = chunk.get("owasp") or "no OWASP tag"
        cwe_tag = chunk.get("cwe") or ""
        with cols[i % len(cols)]:
            st.markdown(f"""
<div class="chunk">
  <div class="chunk-head">
    <span class="chunk-title">{chunk['title']} — {chunk['section']}</span>
    <span class="chunk-sim">{chunk['similarity']:.2f}</span>
  </div>
  <div class="{tag_cls}" style="margin-bottom:6px">{dot} {tag_txt}</div>
  {chunk['content']}
  <div class="chunk-foot">{cwe_tag} · {owasp}<br>Source: {src}</div>
</div>""", unsafe_allow_html=True)

