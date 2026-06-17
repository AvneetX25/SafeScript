# test_pipeline.py
# Run from project root: python test_pipeline.py

import json
from scanner.pipeline import run_pipeline, save_report

# ── Test on Python file ────────────────────────────────────────────────────────
print("=" * 60)
print("TEST 1: Python file")
print("=" * 60)

py_result = run_pipeline('tests/samples/vulnerable_sample.py', use_llm=True)

print(f"Total chunks: {py_result['total_chunks']}")
print(f"Stage 1     : {py_result['stage1_flagged']} flagged")
print(f"Stage 2     : {py_result['stage2_flagged']} flagged")
print(f"Both stages : {py_result['both_stages_confirmed']} confirmed")
print(f"Model only  : {py_result['model_only_confirmed']} confirmed (≥0.75)")
print(f"Total → LLM : {py_result['total_confirmed']}")

for i, r in enumerate(py_result['results'], 1):
    print(f"\n  Finding {i}: {r['function']}() — line {r['start_line']}")
    print(f"  Detection : {r['detection_method']}")   # ← new line
    print(f"  Rule      : {r['primary_rule']}")
    print(f"  Severity  : {r['severity']}")
    print(f"  Confidence: {r['vuln_probability']:.3f}")
    print(f"  Explanation:\n    {r['explanation']}")
    print(f"  Fix:\n    {r['fix'][:300]}...")

save_report(py_result, 'evaluation/pipeline_report_py.json')

# ── Test on Java file ─────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("TEST 2: Java file")
print("=" * 60)

java_result = run_pipeline('tests/samples/vulnerable_sample.java', use_llm=True)

print("\n── Pipeline Summary ──")
print(f"Total chunks: {java_result['total_chunks']}")
print(f"Stage 1     : {java_result['stage1_flagged']} flagged")
print(f"Stage 2     : {java_result['stage2_flagged']} flagged")
print(f"Both stages : {java_result['both_stages_confirmed']} confirmed")
print(f"Model only  : {java_result['model_only_confirmed']} confirmed (≥0.75)")
print(f"Total → LLM : {java_result['total_confirmed']}")
save_report(java_result, 'evaluation/pipeline_report_java.json')