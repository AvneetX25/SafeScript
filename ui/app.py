# ui/app.py
# Run with: streamlit run ui/app.py

import sys
import os

# ── Path fix: allow imports from project root ──────────────────────────────────
# ui/app.py lives one level below project root, so we add the root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import time
import tempfile
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
from scanner.pipeline import run_pipeline
import shutil
import subprocess

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SafeScript",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  /* Base */
  .stApp { background-color: #0d1117; color: #e6edf3; }

  /* Sidebar */
  [data-testid="stSidebar"] { background-color: #161b22; border-right: 1px solid #30363d; }

  /* Cards */
  .metric-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1rem 1.25rem;
    text-align: center;
  }
  .metric-card .value { font-size: 2rem; font-weight: 700; font-family: monospace; }
  .metric-card .label { font-size: 0.78rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.2rem; }

  .red   { color: #f85149; }
  .amber { color: #e3b341; }
  .green { color: #3fb950; }
  .blue  { color: #58a6ff; }

  /* Severity badges */
  .badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.04em;
  }
  .badge-HIGH   { background: #3d1f1f; color: #f85149; border: 1px solid #f85149; }
  .badge-MEDIUM { background: #2d2208; color: #e3b341; border: 1px solid #e3b341; }
  .badge-LOW    { background: #0d2119; color: #3fb950; border: 1px solid #3fb950; }

  /* Method badge */
  .method-both  { background: #1a2d4a; color: #58a6ff; border: 1px solid #58a6ff; border-radius: 6px; padding: 2px 8px; font-size: 0.72rem; }
  .method-model { background: #2d1f3d; color: #bc8cff; border: 1px solid #bc8cff; border-radius: 6px; padding: 2px 8px; font-size: 0.72rem; }

  /* Finding expander header */
  .finding-header {
    display: flex; align-items: center; gap: 10px;
    font-family: monospace; font-size: 0.9rem;
  }

  /* Fix code block */
  .fix-block {
    background: #0d2119;
    border-left: 3px solid #3fb950;
    border-radius: 0 6px 6px 0;
    padding: 0.75rem 1rem;
    font-family: monospace;
    font-size: 0.85rem;
    white-space: pre-wrap;
    color: #aff5b4;
    margin-top: 0.5rem;
  }

  /* Pipeline stage indicator */
  .stage-pill {
    display: inline-block;
    padding: 3px 12px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    margin: 2px;
  }
  .stage-static  { background: #1a2d4a; color: #58a6ff; }
  .stage-model   { background: #2d1f3d; color: #bc8cff; }
  .stage-llm     { background: #1e2d1a; color: #3fb950; }

  /* Section headers */
  .section-title {
    font-size: 1.1rem;
    font-weight: 600;
    color: #e6edf3;
    border-bottom: 1px solid #30363d;
    padding-bottom: 0.5rem;
    margin: 1.5rem 0 1rem 0;
  }

  /* Override Streamlit expander */
  [data-testid="stExpander"] {
    background: #161b22 !important;
    border: 1px solid #30363d !important;
    border-radius: 8px !important;
    margin-bottom: 0.5rem !important;
  }

  /* Dataframe */
  [data-testid="stDataFrame"] { border: 1px solid #30363d; border-radius: 8px; }

  /* Button */
  .stButton > button {
    background: #238636 !important;
    color: white !important;
    border: none !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    padding: 0.5rem 1.5rem !important;
  }
  .stButton > button:hover { background: #2ea043 !important; }

  /* Text input */
  .stTextInput input {
    background: #161b22 !important;
    border: 1px solid #30363d !important;
    color: #e6edf3 !important;
    border-radius: 6px !important;
    font-family: monospace !important;
  }

  /* Hide Streamlit branding */
  #MainMenu { visibility: hidden; }
  footer    { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


# ── Helpers ────────────────────────────────────────────────────────────────────

def severity_badge(severity: str) -> str:
    s = severity.upper()
    return f'<span class="badge badge-{s}">{s}</span>'

def method_badge(method: str) -> str:
    if method == 'both_stages':
        return '<span class="method-both">⚡ Both Stages</span>'
    return '<span class="method-model">🤖 Model Only</span>'

def confidence_bar(prob: float) -> str:
    pct = int(prob * 100)
    color = "#f85149" if pct >= 70 else "#e3b341" if pct >= 50 else "#3fb950"
    return f"""
    <div style="background:#21262d;border-radius:4px;height:6px;width:100%;margin-top:4px;">
      <div style="background:{color};width:{pct}%;height:6px;border-radius:4px;"></div>
    </div>
    <div style="font-size:0.72rem;color:#8b949e;margin-top:2px;">{pct}% confidence</div>
    """


SKIP_DIRS = {
    '__pycache__', '.git', 'node_modules', 'venv', '.venv',
    'env', 'dist', 'build', 'target', 'vendor', '.idea',
    '.vscode', 'migrations', 'test', 'tests', 'resources'
}

def collect_files(root: str) -> list[str]:
    collected = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if Path(fname).suffix.lower() in ('.py', '.java'):
                collected.append(os.path.join(dirpath, fname))
    return sorted(collected)

def is_github_url(s: str) -> bool:
    return s.startswith('https://github.com') or s.startswith('git@github.com')

def severity_order(s: str) -> int:
    return {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(s.upper(), 3)

def rule_label(rule: str) -> str:
    """Map Bandit/static rule codes to readable vulnerability type."""
    mapping = {
        "B608": "SQL Injection",
        "B602": "Shell Injection",
        "B603": "Shell Injection",
        "B604": "Shell Injection",
        "B605": "Shell Injection",
        "B606": "Shell Injection",
        "B607": "Shell Injection",
        "B105": "Hardcoded Secret",
        "B106": "Hardcoded Secret",
        "B107": "Hardcoded Secret",
        "B307": "Unsafe eval()",
        "B301": "Unsafe Pickle",
        "B302": "Unsafe Marshal",
        "B303": "Weak Crypto",
        "B304": "Weak Crypto",
        "B305": "Weak Crypto",
        "B306": "Insecure Temp File",
        "B324": "Weak Hash",
        "B501": "TLS/SSL Issue",
        "B502": "TLS/SSL Issue",
        "B503": "TLS/SSL Issue",
        "B504": "TLS/SSL Issue",
        "B505": "Weak Key Size",
        "B506": "YAML Load",
        "B701": "Jinja2 XSS",
        "B702": "Template Injection",
        "model-detected": "Model Detected",
        "SQL_INJECTION": "SQL Injection",
        "COMMAND_INJECTION": "Command Injection",
        "XSS": "Cross-Site Scripting",
        "PATH_TRAVERSAL": "Path Traversal",
    }
    return mapping.get(rule, rule)


# ── Sidebar ────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🛡️ SafeScript")
    st.markdown(
        '<div style="color:#8b949e;font-size:0.82rem;margin-bottom:1.5rem;">'
        'Fine-tuned CodeBERT + static analysis + LLM-powered fixes'
        '</div>',
        unsafe_allow_html=True
    )

    st.markdown("### Pipeline")
    st.markdown(
        '<span class="stage-pill stage-static">① Static Analysis</span>'
        '<span class="stage-pill stage-model">② CodeBERT</span>'
        '<span class="stage-pill stage-llm">③ LLM Fix</span>',
        unsafe_allow_html=True
    )

    st.markdown("---")
    st.markdown("### Stats")
    st.markdown(
        '<div style="font-size:0.82rem;color:#8b949e;line-height:1.8;">'
        '🗂️ Trained on <b style="color:#e6edf3;">7,866</b> samples<br>'
        '🐍 Python + ☕ Java support<br>'
        '🎯 3-tier false positive filter<br>'
        '🤖 Groq LLM explanations'
        '</div>',
        unsafe_allow_html=True
    )

    st.markdown("---")
    use_llm = st.toggle("Enable LLM explanations", value=True)
    st.markdown(
        '<div style="font-size:0.75rem;color:#8b949e;">Disable to run stages 1+2 only (faster)</div>',
        unsafe_allow_html=True
    )


# ── Header ─────────────────────────────────────────────────────────────────────

st.markdown("""
<div style="padding: 1.5rem 0 1rem 0;">
  <div style="display:flex;align-items:center;gap:12px;">
    <span style="font-size:2rem;">🛡️</span>
    <div>
      <div style="font-size:1.75rem;font-weight:700;color:#e6edf3;letter-spacing:-0.02em;">
        SafeScript
      </div>
      <div style="color:#8b949e;font-size:0.875rem;margin-top:2px;">
        AI-Augmented Secure Code Analysis Platform
      </div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

st.divider()

# ── Input ──────────────────────────────────────────────────────────────────────

col_input, col_btn = st.columns([5, 1])
with col_input:
    repo_url = st.text_input(
        "GitHub URL",
        placeholder="https://github.com/username/repository",
        label_visibility="collapsed"
    )
    
with col_btn:
    scan_clicked = st.button("🔍 Scan", use_container_width=True)

st.markdown(
    '<div style="font-size:0.78rem;color:#8b949e;margin-top:-0.5rem;">'
    'Enter a public GitHub repository URL — all .py and .java files will be scanned recursively.'
    '</div>',
    unsafe_allow_html=True
)


# ── Scan logic ─────────────────────────────────────────────────────────────────

if scan_clicked and repo_url:
    url = repo_url.strip()

    if not is_github_url(url):
        st.error("Please enter a valid GitHub URL starting with `https://github.com/`")
        st.stop()

    tmp_dir = tempfile.mkdtemp(prefix='ai_scanner_')
    clone_status = st.empty()
    clone_status.markdown(
        '<div style="color:#8b949e;font-size:0.85rem;">⏳ Cloning repository...</div>',
        unsafe_allow_html=True
    )

    try:
        result = subprocess.run(
            ['git', 'clone', '--depth=1', url, tmp_dir],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            st.error(f"Make sure the URL is correct and the repo is public.\n\n`{result.stderr.strip()}`")
            st.stop()
    except FileNotFoundError:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        st.error("`git` not found. Make sure Git is installed and on your PATH.")
        st.stop()

    clone_status.empty()

    files_to_scan = collect_files(tmp_dir)

    if not files_to_scan:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        st.warning("No .py or .java files found in this repository.")
        st.stop()

    # ── Progress UI ───────────────────────────────────────────────────────────
    st.markdown("---")
    progress_bar    = st.progress(0)
    status_text     = st.empty()
    all_file_results = []
    errors           = []

    for i, filepath in enumerate(files_to_scan):
        short = Path(filepath).name
        status_text.markdown(
            f'<div style="color:#8b949e;font-size:0.85rem;">Scanning <code>{short}</code> '
            f'({i+1}/{len(files_to_scan)})</div>',
            unsafe_allow_html=True
        )
        try:
            result = run_pipeline(filepath, use_llm=use_llm)
            all_file_results.append(result)
        except Exception as e:
            errors.append((filepath, str(e)))
        progress_bar.progress((i + 1) / len(files_to_scan))
    shutil.rmtree(tmp_dir, ignore_errors=True)

    progress_bar.empty()
    status_text.empty()

    # ── Aggregate results ─────────────────────────────────────────────────────
    all_findings = []
    total_chunks  = 0
    total_files   = len(all_file_results)

    for file_result in all_file_results:
        total_chunks += file_result.get('total_chunks', 0)
        for r in file_result.get('results', []):
            all_findings.append({
                **r,
                'file': file_result['file'],
                'language': file_result.get('language', ''),
            })

    # Sort: severity first, then confidence
    all_findings.sort(key=lambda x: (severity_order(x.get('severity', 'LOW')), -x.get('vuln_probability', 0)))

    # ── Summary metrics ───────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Scan Summary</div>', unsafe_allow_html=True)

    high_count   = sum(1 for f in all_findings if f.get('severity','').upper() == 'HIGH')
    medium_count = sum(1 for f in all_findings if f.get('severity','').upper() == 'MEDIUM')
    low_count    = sum(1 for f in all_findings if f.get('severity','').upper() == 'LOW')
    total_vulns  = len(all_findings)

    m1, m2, m3, m4, m5 = st.columns(5)
    metrics = [
        (m1, str(total_files),  "Files Scanned",    "blue"),
        (m2, str(total_chunks), "Chunks Analyzed",  "blue"),
        (m3, str(high_count),   "High Severity",    "red"),
        (m4, str(medium_count), "Medium Severity",  "amber"),
        (m5, str(low_count),    "Low Severity",     "green"),
    ]
    for col, val, label, color in metrics:
        with col:
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="value {color}">{val}</div>'
                f'<div class="label">{label}</div>'
                f'</div>',
                unsafe_allow_html=True
            )

    if errors:
        with st.expander(f"⚠️ {len(errors)} file(s) failed to scan"):
            for fp, err in errors:
                st.markdown(f"`{fp}` — {err}")

    # ── No findings ───────────────────────────────────────────────────────────
    if not all_findings:
        st.success("✅ No vulnerabilities detected across all scanned files.")
        st.stop()

    # ── Charts ────────────────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Vulnerability Breakdown</div>', unsafe_allow_html=True)

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        # By severity
        sev_counts = {"HIGH": high_count, "MEDIUM": medium_count, "LOW": low_count}
        sev_counts = {k: v for k, v in sev_counts.items() if v > 0}
        fig_sev = go.Figure(go.Bar(
            x=list(sev_counts.keys()),
            y=list(sev_counts.values()),
            marker_color=["#f85149", "#e3b341", "#3fb950"][:len(sev_counts)],
            text=list(sev_counts.values()),
            textposition="outside",
            textfont=dict(color="#e6edf3"),
        ))
        fig_sev.update_layout(
            title=dict(text="By Severity", font=dict(color="#e6edf3", size=13)),
            paper_bgcolor="#161b22", plot_bgcolor="#161b22",
            font=dict(color="#8b949e"),
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor="#21262d"),
            margin=dict(t=40, b=20, l=20, r=20),
            height=260,
        )
        st.plotly_chart(fig_sev, use_container_width=True)

    with chart_col2:
        # By vulnerability type
        type_counts: dict = {}
        for f in all_findings:
            vtype = rule_label(f.get('primary_rule', 'Unknown'))
            type_counts[vtype] = type_counts.get(vtype, 0) + 1

        type_counts = dict(sorted(type_counts.items(), key=lambda x: -x[1]))
        fig_type = go.Figure(go.Bar(
            x=list(type_counts.values()),
            y=list(type_counts.keys()),
            orientation='h',
            marker_color="#58a6ff",
            text=list(type_counts.values()),
            textposition="outside",
            textfont=dict(color="#e6edf3"),
        ))
        fig_type.update_layout(
            title=dict(text="By Vulnerability Type", font=dict(color="#e6edf3", size=13)),
            paper_bgcolor="#161b22", plot_bgcolor="#161b22",
            font=dict(color="#8b949e"),
            xaxis=dict(showgrid=True, gridcolor="#21262d"),
            yaxis=dict(showgrid=False),
            margin=dict(t=40, b=20, l=20, r=20),
            height=260,
        )
        st.plotly_chart(fig_type, use_container_width=True)

    # ── Results table ─────────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Findings Table</div>', unsafe_allow_html=True)

    table_data = []
    for f in all_findings:
        table_data.append({
            "File":       Path(f['file']).name,
            "Function":   f['function'],
            "Line":       f['start_line'],
            "Type":       rule_label(f.get('primary_rule', '')),
            "Severity":   f.get('severity', '').upper(),
            #"Confidence": f"{int(f.get('vuln_probability', 0) * 100)}%",
            "Confidence": round(f.get('vuln_probability', 0) * 100, 1),
            "Method":     "Both Stages" if f['detection_method'] == 'both_stages' else "Model Only",
            "Language":   f.get('language', '').title(),
        })

    df = pd.DataFrame(table_data)
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Confidence": st.column_config.ProgressColumn(
                "Confidence",
                min_value=0,
                max_value=100,
                format="%d%%",
            ),
            "Severity": st.column_config.TextColumn("Severity"),
        }
    )

    # ── Detailed findings ─────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Detailed Findings</div>', unsafe_allow_html=True)

    for idx, finding in enumerate(all_findings):
        func      = finding['function']
        line      = finding['start_line']
        sev       = finding.get('severity', 'LOW').upper()
        prob      = finding.get('vuln_probability', 0)
        method    = finding.get('detection_method', '')
        vtype     = rule_label(finding.get('primary_rule', ''))
        fname     = Path(finding['file']).name
        lang      = finding.get('language', 'python').lower()
        expl      = finding.get('explanation', '')
        fix       = finding.get('fix', '')
        static_fs = finding.get('static_findings', [])

        # Expander label (plain text — no HTML)
        label = f"{fname} › {func}()  |  Line {line}  |  {sev}  |  {vtype}"

        with st.expander(label):
            # Top row: badges + confidence
            badge_col, conf_col = st.columns([3, 2])
            with badge_col:
                st.markdown(
                    f'{severity_badge(sev)}&nbsp;&nbsp;{method_badge(method)}',
                    unsafe_allow_html=True
                )
            with conf_col:
                st.markdown(confidence_bar(prob), unsafe_allow_html=True)

            st.markdown("")

            # Static findings detail
            if static_fs:
                st.markdown("**Static Analysis Findings**")
                for sf in static_fs:
                    rule_sev = sf.get('severity', '').upper()
                    st.markdown(
                        f'<div style="background:#161b22;border:1px solid #30363d;border-radius:6px;'
                        f'padding:0.6rem 0.9rem;margin-bottom:0.4rem;font-size:0.83rem;">'
                        f'<code style="color:#58a6ff;">{sf.get("rule","")}</code>&nbsp;&nbsp;'
                        f'{severity_badge(rule_sev)}&nbsp;&nbsp;'
                        f'<span style="color:#8b949e;">Line {sf.get("line","?")}</span>&nbsp;—&nbsp;'
                        f'<span style="color:#e6edf3;">{sf.get("message","")}</span>'
                        f'</div>',
                        unsafe_allow_html=True
                    )

            # Explanation
            if expl:
                st.markdown("**Why it's dangerous**")
                st.markdown(
                    f'<div style="background:#161b22;border-left:3px solid #f85149;'
                    f'border-radius:0 6px 6px 0;padding:0.75rem 1rem;'
                    f'font-size:0.875rem;color:#e6edf3;line-height:1.6;">{expl}</div>',
                    unsafe_allow_html=True
                )
                st.markdown("")

            # Suggested fix
            if fix:
                st.markdown("**Suggested Fix**")
                # Strip markdown code fences if present
                clean_fix = fix.strip()
                if clean_fix.startswith("```"):
                    lines = clean_fix.split("\n")
                    clean_fix = "\n".join(lines[1:-1]) if len(lines) > 2 else clean_fix
                st.code(clean_fix, language=lang)
            elif use_llm:
                st.markdown(
                    '<div style="color:#8b949e;font-size:0.82rem;">No fix generated.</div>',
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    '<div style="color:#8b949e;font-size:0.82rem;">'
                    'Enable LLM explanations in the sidebar to see suggested fixes.'
                    '</div>',
                    unsafe_allow_html=True
                )

    # ── Export ────────────────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown('<div class="section-title">Export Report</div>', unsafe_allow_html=True)

    export_col1, export_col2 = st.columns(2)

    with export_col1:
        # JSON export — full pipeline output
        export_data = {
            "scan_summary": {
                "files_scanned":   total_files,
                "chunks_analyzed": total_chunks,
                "total_findings":  total_vulns,
                "high":   high_count,
                "medium": medium_count,
                "low":    low_count,
            },
            "findings": all_findings
        }
        json_str = json.dumps(export_data, indent=2)
        st.download_button(
            label="⬇️ Download JSON Report",
            data=json_str,
            file_name="security_scan_report.json",
            mime="application/json",
            use_container_width=True,
        )

    with export_col2:
        # CSV export — table only
        csv_str = df.to_csv(index=False)
        st.download_button(
            label="⬇️ Download CSV Summary",
            data=csv_str,
            file_name="security_scan_summary.csv",
            mime="text/csv",
            use_container_width=True,
        )