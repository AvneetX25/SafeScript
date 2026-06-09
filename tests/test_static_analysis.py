import json
import sys
from pathlib import Path

# Make sure scanner/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.static_analysis import scan_file

def print_report(result: dict):
    print("\n" + "="*60)
    print(f"FILE     : {result['file']}")
    print(f"LANGUAGE : {result.get('language', 'unknown')}")
    print(f"CHUNKS   : {result['total_chunks']} total  |  {result['flagged_count']} flagged")
    print(f"FINDINGS : {result['total_findings']} total")
    print("="*60)

    if not result['flagged_chunks']:
        print("  No flagged chunks.")
        return

    for i, chunk in enumerate(result['flagged_chunks'], 1):
        print(f"\n  [{i}] Function : {chunk['name']}")
        print(f"      Lines    : {chunk['start_line']} → {chunk['end_line']}")
        print(f"      Findings : {chunk['finding_count']}")
        for f in chunk['findings']:
            print(f"        • Line {f['line']} | {f['severity'].upper()} | {f['rule']}")
            print(f"          {f['message'][:100]}")


def run_tests():
    samples_dir = Path(__file__).parent / "samples"
    test_files = [
        samples_dir / "vulnerable_sample.py",
        samples_dir / "vulnerable_sample.java"
    ]

    all_results = []

    for filepath in test_files:
        if not filepath.exists():
            print(f"[SKIP] File not found: {filepath}")
            continue

        print(f"\n[SCANNING] {filepath.name} ...")
        result = scan_file(str(filepath))
        print_report(result)
        all_results.append(result)

    # Save results to JSON for inspection
    output_path = Path(__file__).parent / "sample_scan_results.json"
    with open(output_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\n[SAVED] Results → {output_path}")


if __name__ == "__main__":
    run_tests()