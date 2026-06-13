# scanner/pipeline.py

import json
from pathlib import Path
from scanner.static_analysis import scan_file as static_scan
from scanner.classifier import VulnerabilityClassifier
from scanner.llm_explainer import explain_vulnerability

# ── Classifier singleton ───────────────────────────────────────────────────────

_classifier = None

def _get_classifier() -> VulnerabilityClassifier:
    global _classifier
    if _classifier is None:
        _classifier = VulnerabilityClassifier()
    return _classifier


# ── Intersection filter ────────────────────────────────────────────────────────

def _build_static_index(flagged_chunks: list[dict]) -> dict:
    """
    Build a lookup from chunk name+start_line → static findings.
    Used to check if a chunk was flagged by Stage 1.
    """
    index = {}
    for chunk in flagged_chunks:
        key = (chunk['name'], chunk['start_line'])
        index[key] = chunk.get('findings', [])
    return index


# ── Main pipeline ──────────────────────────────────────────────────────────────

def run_pipeline(filepath: str, use_llm: bool = True) -> dict:
    """
    Parallel intersection pipeline:

    Stage 1: static_analysis.scan_file() runs on all chunks
             → produces a set of statically flagged chunks

    Stage 2: CodeBERT runs on ALL chunks independently
             → produces a set of model-flagged chunks

    Intersection: chunk must be flagged by BOTH stages to reach LLM or chunk flagged my model should be of high confidence
                  → eliminates model false positives using static precision
                  → eliminates static blind spots using model recall

    Args:
        filepath: path to .py or .java file
        use_llm:  set False to skip Stage 3 (useful for testing stages 1+2)

    Returns structured report dict.
    """
    filepath = str(filepath)
    classifier = _get_classifier()

    # ── Stage 1: Static analysis ──────────────────────────────────────────────
    print(f"\n[Stage 1] Running static analysis on {filepath}")
    static_result = static_scan(filepath)

    if not static_result:
        return {'file': filepath, 'error': 'Unsupported file type or scan failed'}

    all_chunks = _get_all_chunks(filepath, static_result)
    flagged_chunks = static_result.get('flagged_chunks', [])
    language = static_result.get('language', 'python')

    # Build a fast lookup for intersection check
    static_index = _build_static_index(flagged_chunks)
    static_keys = set(static_index.keys())

    print(f"[Stage 1] {len(all_chunks)} total chunks, {len(flagged_chunks)} flagged")

    # ── Stage 2: Model runs on ALL chunks ─────────────────────────────────────
    print(f"[Stage 2] Running CodeBERT on all {len(all_chunks)} chunks")

    results = []
    stage2_flagged = 0
    intersection_count = 0

    for chunk in all_chunks:
        name = chunk['name']
        code = chunk['code']
        start_line = chunk['start_line']
        chunk_key = (name, start_line)

        # Stage 2 — classify every chunk
        classification = classifier.classify(code)
        vuln_prob = classification['vuln_probability']
        threshold = classification['threshold_used']
        model_flagged = classification['vulnerable']

        if model_flagged:
            stage2_flagged += 1

        print(f"[Stage 2] {name}() line {start_line} — "
              f"vuln_prob={vuln_prob:.3f} model={model_flagged} "
              f"static={'YES' if chunk_key in static_keys else 'NO'}")

        # ── Three-tier filter ─────────────────────────────────────────────────
        static_flagged = chunk_key in static_keys
        MODEL_ONLY_THRESHOLD = 0.75

        # Determine detection method
        if static_flagged and model_flagged:
            detection_method = 'both_stages'
        elif model_flagged and not static_flagged and vuln_prob >= MODEL_ONLY_THRESHOLD:
            detection_method = 'model_only_high_confidence'
        else:
            # Build drop reason for terminal
            reasons = []
            if not model_flagged:
                reasons.append(f"model confidence {vuln_prob:.3f} below threshold {threshold}")
            if not static_flagged and vuln_prob < MODEL_ONLY_THRESHOLD:
                reasons.append(f"model-only confidence {vuln_prob:.3f} below model-only threshold {MODEL_ONLY_THRESHOLD}")
            print(f"[Filter] Dropped {name}() — {' | '.join(reasons)}")
            continue

        # Get static findings if available
        static_findings = static_index.get(chunk_key, [])
        primary_finding = _pick_primary_finding(static_findings) if static_findings else {
            'rule': 'model-detected',
            'severity': 'HIGH',
            'message': f'No static rule matched — model flagged with confidence {vuln_prob:.3f}'
        }

        print(f"[{detection_method.upper()}] CONFIRMED: {name}() "
              f"— vuln_prob={vuln_prob:.3f} "
              f"static={'YES' if static_flagged else 'NO'}")

        # ── Stage 3: LLM explanation ──────────────────────────────────────────
        llm_result = {}
        if use_llm:
            print(f"[Stage 3] Requesting LLM explanation for {name}()")
            llm_result = explain_vulnerability(
                code=code,
                rule=primary_finding['rule'],
                message=primary_finding['message'],
                severity=primary_finding['severity'],
                language=language
            )

        results.append({
            'function': name,
            'start_line': start_line,
            'end_line': chunk['end_line'],
            'language': language,
            'vuln_probability': vuln_prob,
            'threshold_used': threshold,
            'detection_method': detection_method,
            'static_findings': static_findings,
            'primary_rule': primary_finding['rule'],
            'explanation': llm_result.get('explanation', ''),
            'fix': llm_result.get('fix', ''),
            'severity': llm_result.get('severity', primary_finding['severity']),
            'severity_reason': llm_result.get('severity_reason', ''),
        })
        
        
    both_stages_count = sum(1 for r in results if r['detection_method'] == 'both_stages')
    model_only_count = sum(1 for r in results if r['detection_method'] == 'model_only_high_confidence')

    print(f"\n[Pipeline] Done.")
    print(f"  Total chunks          : {len(all_chunks)}")
    print(f"  Stage 1 flagged       : {len(flagged_chunks)}")
    print(f"  Stage 2 flagged       : {stage2_flagged}")
    print(f"  Both stages confirmed : {both_stages_count}")
    print(f"  Model-only (≥0.75)    : {model_only_count}")
    print(f"  Total sent to LLM     : {len(results)}")

    return {
        'file': filepath,
        'language': language,
        'total_chunks': len(all_chunks),
        'stage1_flagged': len(flagged_chunks),
        'stage2_flagged': stage2_flagged,
        'both_stages_confirmed': both_stages_count,
        'model_only_confirmed': model_only_count,
        'total_confirmed': len(results),
        'results': results
    }


def _get_all_chunks(filepath: str, static_result: dict) -> list[dict]:
    """
    Reconstruct the full chunk list from the static result.
    static_scan() returns flagged_chunks only — we need all chunks
    for Stage 2 to run on. Re-extract them here.
    """
    from scanner.static_analysis import (
        extract_python_functions, extract_python_module_level,
        extract_java_functions, extract_java_class_fields
    )
    ext = Path(filepath).suffix.lower()

    if ext == '.py':
        return extract_python_module_level(filepath) + extract_python_functions(filepath)
    elif ext == '.java':
        return extract_java_class_fields(filepath) + extract_java_functions(filepath)
    return []


def _pick_primary_finding(findings: list[dict]) -> dict:
    """Pick highest severity finding to send to LLM."""
    severity_order = {'ERROR': 0, 'HIGH': 0, 'MEDIUM': 1, 'WARNING': 1, 'LOW': 2, 'INFO': 2}
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_order.get(f['severity'].upper(), 99)
    )
    return sorted_findings[0] if sorted_findings else {
        'rule': 'unknown',
        'severity': 'MEDIUM',
        'message': 'Flagged by static analysis'
    }


# ── Report saving ─────────────────────────────────────────────────────────────

def save_report(pipeline_result: dict, output_path: str = 'evaluation/pipeline_report.json'):
    """Save the pipeline output to a JSON report file."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(pipeline_result, f, indent=2)
    print(f"[Report] Saved to {output_path}")