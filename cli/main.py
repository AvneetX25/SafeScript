# cli/main.py
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich import box

# ── import your pipeline ──────────────────────────────────────────────────────
# Adjust the import path if cli/ is not a sibling of scanner/
sys.path.insert(0, str(Path(__file__).parent.parent))
from scanner.pipeline import run_pipeline

console = Console()

# ── directories to skip during file walk ─────────────────────────────────────
SKIP_DIRS = {
    '__pycache__', '.git', 'node_modules', 'venv', '.venv',
    'env', 'dist', 'build', 'target', 'vendor', '.idea',
    '.vscode', 'migrations', 'test', 'tests', 'resources'
}

SUPPORTED_EXTENSIONS = {'.py', '.java'}


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Repo resolver: URL vs local path
# ─────────────────────────────────────────────────────────────────────────────

def is_github_url(repo: str) -> bool:
    """Returns True if the argument looks like a GitHub URL."""
    return repo.startswith('https://github.com') or repo.startswith('git@github.com')


def clone_repo(url: str) -> tuple[str, str]:
    """
    Clones a GitHub repo into a temporary directory.
    Returns (temp_dir_path, cloned_repo_path).
    Caller is responsible for deleting temp_dir after use.
    """
    temp_dir = tempfile.mkdtemp(prefix='ai_scanner_')
    console.print(f"[bold cyan]Cloning[/bold cyan] {url} → {temp_dir}")

    result = subprocess.run(
        ['git', 'clone', '--depth=1', url, temp_dir],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        shutil.rmtree(temp_dir, ignore_errors=True)
        console.print(f"[bold red]Clone failed:[/bold red] {result.stderr.strip()}")
        sys.exit(1)

    console.print(f"[green]Clone successful.[/green]\n")
    return temp_dir, temp_dir


def resolve_repo(repo_arg: str) -> tuple[str, str | None]:
    """
    Returns (local_path_to_scan, temp_dir_to_cleanup).
    temp_dir_to_cleanup is None if no cloning happened.
    """
    if is_github_url(repo_arg):
        _, cloned_path = clone_repo(repo_arg)
        return cloned_path, cloned_path
    else:
        if not os.path.isdir(repo_arg):
            console.print(f"[bold red]Error:[/bold red] '{repo_arg}' is not a valid directory.")
            sys.exit(1)
        return repo_arg, None


# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — File walker
# ─────────────────────────────────────────────────────────────────────────────

def collect_files(root: str) -> list[str]:
    """
    Recursively walks root, returns all .py and .java files,
    skipping noise directories.
    """
    collected = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in-place so os.walk doesn't descend into them
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for fname in filenames:
            ext = Path(fname).suffix.lower()
            if ext in SUPPORTED_EXTENSIONS:
                collected.append(os.path.join(dirpath, fname))

    return sorted(collected)


# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — Scan all files with progress bar
# ─────────────────────────────────────────────────────────────────────────────

def scan_all_files(files: list[str], use_llm: bool = True) -> list[dict]:
    """
    Runs run_pipeline() on each file.
    Returns a flat list of per-file report dicts.
    """
    all_reports = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:

        task = progress.add_task("[cyan]Scanning files...", total=len(files))

        for filepath in files:
            rel = os.path.relpath(filepath)
            progress.update(task, description=f"[cyan]Scanning[/cyan] {rel}")

            report = run_pipeline(filepath, use_llm=use_llm)
            all_reports.append(report)

            progress.advance(task)

    return all_reports


# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — Rich terminal table
# ─────────────────────────────────────────────────────────────────────────────

def _shorten_path(filepath: str, max_len: int = 45) -> str:
    """Truncates long paths to keep the table readable."""
    if len(filepath) <= max_len:
        return filepath
    return '...' + filepath[-(max_len - 3):]


def _severity_color(severity: str) -> str:
    mapping = {
        'CRITICAL': 'bold red',
        'HIGH':     'red',
        'MEDIUM':   'yellow',
        'LOW':      'cyan',
    }
    return mapping.get(severity.upper(), 'white')


def _method_label(method: str) -> str:
    if method == 'both_stages':
        return '[green]both[/green]'
    if method == 'model_only_high_confidence':
        return '[yellow]model[/yellow]'
    return method


def print_report(all_reports: list[dict]) -> None:
    """Prints a rich table of all findings across all files."""

    table = Table(
        title='AI Security Scanner — Results',
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
    )
    table.add_column('File',       style='cyan',    no_wrap=False, max_width=45)
    table.add_column('Function',   style='magenta', no_wrap=True)
    table.add_column('Lines',      style='white',   no_wrap=True, justify='center')
    table.add_column('Severity',   no_wrap=True,    justify='center')
    table.add_column('Confidence', no_wrap=True,    justify='center')
    table.add_column('Method',     no_wrap=True,    justify='center')
    table.add_column('Primary rule', style='white', no_wrap=False, max_width=30)

    total_findings = 0

    for report in all_reports:
        if 'error' in report:
            # Skipped / unsupported file — don't add a row
            continue

        filepath = _shorten_path(os.path.relpath(report['file']))
        findings = report.get('results', [])

        for finding in findings:
            total_findings += 1
            severity   = finding.get('severity', 'UNKNOWN')
            sev_color  = _severity_color(severity)
            confidence = finding.get('vuln_probability', 0.0)
            method     = finding.get('detection_method', '')
            start      = finding.get('start_line', '?')
            end        = finding.get('end_line', '?')

            table.add_row(
                filepath,
                finding.get('function', '?'),
                f"{start}–{end}",
                f"[{sev_color}]{severity}[/{sev_color}]",
                f"{confidence:.2f}",
                _method_label(method),
                finding.get('primary_rule', ''),
            )

    console.print()
    console.print(table)
    console.print()

    return total_findings


# ─────────────────────────────────────────────────────────────────────────────
# Step 5 — Summary footer
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(all_reports: list[dict], total_findings: int) -> None:
    """Prints aggregate counts after the table."""

    total_files    = len(all_reports)
    error_files    = sum(1 for r in all_reports if 'error' in r)
    scanned_files  = total_files - error_files
    flagged_files  = sum(1 for r in all_reports if r.get('results'))

    # Severity breakdown
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
    lang_counts     = {}
    method_counts   = {'both_stages': 0, 'model_only_high_confidence': 0}

    for report in all_reports:
        for finding in report.get('results', []):
            sev = finding.get('severity', 'UNKNOWN').upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            lang = finding.get('language', 'unknown')
            lang_counts[lang] = lang_counts.get(lang, 0) + 1

            method = finding.get('detection_method', '')
            if method in method_counts:
                method_counts[method] += 1

    lines = [
        f"[bold]Files scanned    :[/bold] {scanned_files}  ([dim]{error_files} skipped[/dim])",
        f"[bold]Files flagged    :[/bold] {flagged_files}",
        f"[bold]Total findings   :[/bold] {total_findings}",
        "",
        "[bold]Severity breakdown[/bold]",
        f"  [red]HIGH/CRITICAL[/red]  : {severity_counts['CRITICAL'] + severity_counts['HIGH']}",
        f"  [yellow]MEDIUM[/yellow]         : {severity_counts['MEDIUM']}",
        f"  [cyan]LOW[/cyan]            : {severity_counts['LOW']}",
        "",
        "[bold]Detection method[/bold]",
        f"  Both stages    : {method_counts['both_stages']}",
        f"  Model only     : {method_counts['model_only_high_confidence']}",
        "",
        "[bold]Language breakdown[/bold]",
    ]
    for lang, count in sorted(lang_counts.items()):
        lines.append(f"  {lang:<10}: {count}")

    console.print(Panel('\n'.join(lines), title='Summary', border_style='cyan'))


# ─────────────────────────────────────────────────────────────────────────────
# Step 6 — JSON dump
# ─────────────────────────────────────────────────────────────────────────────

def dump_json(all_reports: list[dict], output_path: str) -> None:
    """Writes the full report list to a JSON file."""
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(all_reports, f, indent=2, default=str)

    console.print(f"[dim]Full results saved → {output_path}[/dim]")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='AI Security Scanner — scan a local repo or GitHub URL',
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        '--repo',
        required=True,
        help=(
            'Path to a local repository folder, or a GitHub URL.\n'
            'Examples:\n'
            '  --repo /home/user/projects/WebGoat\n'
            '  --repo https://github.com/WebGoat/WebGoat'
        ),
    )
    parser.add_argument(
        '--output',
        default='evaluation/scan_output.json',
        help='Path for JSON output file (default: evaluation/scan_output.json)',
    )
    parser.add_argument(
        '--no-llm',
        action='store_true',
        help='Skip Stage 3 LLM explanation (faster, useful for testing)',
    )
    args = parser.parse_args()

    # ── Resolve repo ──────────────────────────────────────────────────────────
    repo_path, temp_dir = resolve_repo(args.repo)

    try:
        console.print(Panel(
            f"[bold]Repo[/bold]  : {args.repo}\n"
            f"[bold]Path[/bold]  : {repo_path}\n"
            f"[bold]LLM[/bold]   : {'disabled' if args.no_llm else 'enabled'}\n"
            f"[bold]Output[/bold]: {args.output}",
            title='AI Security Scanner',
            border_style='cyan',
        ))

        # ── Collect files ─────────────────────────────────────────────────────
        files = collect_files(repo_path)
        console.print(f"[bold cyan]{len(files)}[/bold cyan] supported files found (.py / .java)\n")

        if not files:
            console.print("[yellow]No .py or .java files found. Nothing to scan.[/yellow]")
            return

        # ── Scan ──────────────────────────────────────────────────────────────
        all_reports = scan_all_files(files, use_llm=not args.no_llm)

        # ── Print table ───────────────────────────────────────────────────────
        total_findings = print_report(all_reports)

        # ── Summary footer ────────────────────────────────────────────────────
        print_summary(all_reports, total_findings)

        # ── JSON dump ─────────────────────────────────────────────────────────
        dump_json(all_reports, args.output)

    finally:
        # Always clean up temp dir even if scan crashes
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
            console.print(f"[dim]Cleaned up temp clone.[/dim]")


if __name__ == '__main__':
    main()