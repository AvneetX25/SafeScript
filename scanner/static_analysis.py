import ast
import json
import subprocess
import re
from pathlib import Path

import javalang


# ─────────────────────────────────────────────
# SECTION 1: Python Chunking using ast
# ─────────────────────────────────────────────

def extract_python_functions(filepath: str) -> list[dict]:
    """
    Parse a Python file using ast and extract all function-level chunks.
    Returns a list of dicts with name, code, start_line, end_line.
    """
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        source = f.read()

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"[WARN] SyntaxError parsing {filepath}: {e}")
        return []

    chunks = []
    lines = source.split('\n')

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno - 1       # 0-indexed
            end = node.end_lineno         # end_lineno is 1-indexed, slice is exclusive so this works
            chunk_code = '\n'.join(lines[start:end])
            chunks.append({
                'name': node.name,
                'code': chunk_code,
                'start_line': start + 1,  # back to 1-indexed for matching
                'end_line': end,
                'language': 'python'
            })

    return chunks


# ─────────────────────────────────────────────
# SECTION 2: Java Chunking using javalang
# ─────────────────────────────────────────────

def extract_java_functions(filepath: str) -> list[dict]:
    """
    Parse a Java file using javalang and extract all method-level chunks.
    Falls back to regex if javalang fails (e.g., syntax issues).
    """
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        source = f.read()

    lines = source.split('\n')
    chunks = []

    try:
        tree = javalang.parse.parse(source)
    except Exception as e:
        print(f"[WARN] javalang failed on {filepath}: {e}. Falling back to regex.")
        return _extract_java_functions_regex(filepath, source)

    for _, node in tree.filter(javalang.tree.MethodDeclaration):
        method_name = node.name

        # javalang gives us start position (line, col) — 1-indexed
        start_line = node.position.line if node.position else None
        if start_line is None:
            continue

        # Find the method end: scan forward from start for matching braces
        end_line = _find_java_method_end(lines, start_line - 1)  # convert to 0-indexed

        chunk_code = '\n'.join(lines[start_line - 1:end_line])
        chunks.append({
            'name': method_name,
            'code': chunk_code,
            'start_line': start_line,
            'end_line': end_line,
            'language': 'java'
        })

    return chunks


def _find_java_method_end(lines: list[str], start_idx: int) -> int:
    """
    Walk forward from start_idx counting braces to find the closing } of a method.
    Returns the 1-indexed end line number.
    """
    depth = 0
    found_open = False

    for i, line in enumerate(lines[start_idx:], start=start_idx):
        depth += line.count('{') - line.count('}')
        if '{' in line:
            found_open = True
        if found_open and depth == 0:
            return i + 1  # 1-indexed

    return len(lines)  # fallback: end of file


def _extract_java_functions_regex(filepath: str, source: str) -> list[dict]:
    """
    Regex fallback for Java function extraction when javalang fails.
    Catches public/private/protected methods.
    """
    lines = source.split('\n')
    chunks = []
    # Matches method signatures like: public void foo(...) or private int bar(...)
    pattern = re.compile(
        r'^\s*(public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*(\throws\s+\w+)?\s*\{'
    )

    for i, line in enumerate(lines):
        match = pattern.match(line)
        if match:
            method_name = match.group(2)
            end_line = _find_java_method_end(lines, i)
            chunk_code = '\n'.join(lines[i:end_line])
            chunks.append({
                'name': method_name,
                'code': chunk_code,
                'start_line': i + 1,
                'end_line': end_line,
                'language': 'java'
            })

    return chunks


# ─────────────────────────────────────────────
# SECTION 3: Run Semgrep
# ─────────────────────────────────────────────

def run_semgrep(filepath: str) -> list[dict]:
    """
    Run Semgrep with auto config on a file.
    Returns a list of findings with line, rule, severity, message.
    """
    result = subprocess.run(
        ['semgrep', '--config=auto', '--json', filepath],
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace'
   )

    # Semgrep exits 0 (no findings) or 1 (findings found) — both are valid
    if result.returncode not in (0, 1):
        print(f"[ERROR] Semgrep failed on {filepath}:\n{result.stderr[:300]}")
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"[ERROR] Could not parse Semgrep JSON output for {filepath}")
        return []

    findings = []
    for r in data.get('results', []):
        findings.append({
            'line': r['start']['line'],
            'rule': r['check_id'],
            'severity': r['extra']['severity'],
            'message': r['extra']['message']
        })

    return findings


# ─────────────────────────────────────────────
# SECTION 4: Run Bandit (Python only)
# ─────────────────────────────────────────────

def run_bandit(filepath: str) -> list[dict]:
    """
    Run Bandit on a Python file.
    Returns a list of findings with line, rule, severity, message.
    """
    
    result = subprocess.run(
        ['bandit', '-f', 'json', '-q', filepath],
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace'
    )

    # Bandit exits 0 (no issues), 1 (issues found)
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"[ERROR] Could not parse Bandit JSON output for {filepath}")
        return []

    findings = []
    for issue in data.get('results', []):
        findings.append({
            'line': issue['line_number'],
            'rule': issue['test_id'],
            'severity': issue['issue_severity'],
            'message': issue['issue_text']
        })

    return findings


# ─────────────────────────────────────────────
# SECTION 5: Pre-Filter Logic
# ─────────────────────────────────────────────

def filter_flagged_chunks(chunks: list[dict], findings: list[dict]) -> list[dict]:
    """
    Match findings back to chunks by line range.
    A chunk is flagged if any finding falls within its start_line..end_line.
    Returns only flagged chunks, each annotated with its matched findings.
    """
    flagged = []
    finding_lines = set(f['line'] for f in findings)

    for chunk in chunks:
        chunk_lines = set(range(chunk['start_line'], chunk['end_line'] + 1))
        overlap = chunk_lines & finding_lines

        if overlap:
            matched_findings = [f for f in findings if f['line'] in chunk_lines]
            flagged_chunk = dict(chunk)  # copy to avoid mutating original
            flagged_chunk['findings'] = matched_findings
            flagged_chunk['finding_count'] = len(matched_findings)
            flagged.append(flagged_chunk)

    return flagged


# ─────────────────────────────────────────────
# SECTION 6: Main Scanner Entry Point
# ─────────────────────────────────────────────

def scan_file(filepath: str) -> dict:
    """
    Full pipeline for a single file:
    1. Chunk by language
    2. Run Semgrep (all languages) + Bandit (Python only)
    3. Filter chunks that overlap with findings
    4. Return structured result
    """
    filepath = str(filepath)
    ext = Path(filepath).suffix.lower()

    # Step 1: Chunk
    if ext == '.py':
        chunks = extract_python_functions(filepath)
    elif ext == '.java':
        chunks = extract_java_functions(filepath)
    else:
        print(f"[SKIP] Unsupported file type: {filepath}")
        return {}

    if not chunks:
        print(f"[WARN] No functions found in {filepath}")
        return {'file': filepath, 'chunks': [], 'flagged_chunks': [], 'total_findings': 0}

    # Step 2: Run tools
    all_findings = run_semgrep(filepath)

    if ext == '.py':
        bandit_findings = run_bandit(filepath)
        all_findings = _merge_findings(all_findings, bandit_findings)

    # Step 3: Filter
    flagged = filter_flagged_chunks(chunks, all_findings)

    result = {
        'file': filepath,
        'language': 'python' if ext == '.py' else 'java',
        'total_chunks': len(chunks),
        'total_findings': len(all_findings),
        'flagged_chunks': flagged,
        'flagged_count': len(flagged),
        'all_findings': all_findings
    }

    return result


def _merge_findings(semgrep: list[dict], bandit: list[dict]) -> list[dict]:
    """Merge Semgrep and Bandit findings, avoiding exact line duplicates."""
    seen = set()
    merged = []
    for f in semgrep + bandit:
        key = (f['line'], f['rule'])
        if key not in seen:
            seen.add(key)
            merged.append(f)
    return merged