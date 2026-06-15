
# Evaluation Results

## Test Target
- **PyGoat** (Python/Django) — OWASP intentionally vulnerable web application
- Source: https://github.com/adeyosemanputra/pygoat
- Scan date: 16 June 2026
- Scanner flags: --no-llm (Stage 1 + Stage 2 only)

---

## PyGoat — Known Vulnerabilities vs Scanner Findings

| # | Vulnerability | OWASP Category | File | Found? | Rule fired | Severity |
|---|---|---|---|---|---|---|
| 1 | SQL Injection | A03: Injection | introduction/views.py | TP | tainted-sql-string | ERROR |
| 2 | Command Injection (subprocess) | A03: Injection | introduction/views.py | TP | subprocess-injection | ERROR |
| 3 | Command Injection (eval) | A03: Injection | introduction/views.py | TP | user-eval | WARNING |
| 4 | SSRF | A03: Injection | introduction/views.py | TP | ssrf-injection-requests | ERROR |
| 5 | XXE | A03: Injection | introduction/views.py | TP | B317 | MEDIUM |
| 6 | XSS | A03: Injection | introduction/views.py | TP | direct-use-of-httpresponse | WARNING |
| 7 | SSTI | A03: Injection | introduction/views.py | TP | request-data-write | WARNING |
| 8 | Weak Hashing (MD5/SHA1) | A02: Cryptographic Failures | introduction/views.py | TP | B324 | HIGH |
| 9 | Weak Hashing (MD5/SHA1) | A02: Cryptographic Failures | dockerized_labs/broken_auth_lab/app.py | TP | B324 | HIGH |
| 10 | Insecure Deserialization (pickle) | A08: Software Integrity Failures | introduction/views.py | TP | avoid-insecure-deserialization | ERROR |
| 11 | Insecure Deserialization (pickle) | A08: Software Integrity Failures | dockerized_labs/insec_des_lab/main.py | TP | insecure-deserialization | ERROR |
| 12 | Hardcoded JWT Secret | A07: Auth Failures | introduction/mitre.py | TP | jwt-python-hardcoded-secret | ERROR |
| 13 | Insecure Cookies | A05: Security Misconfiguration | introduction/views.py | TP | django-secure-set-cookie | WARNING |
| 14 | Log Injection | A09: Logging Failures | introduction/apis.py | TP | request-data-write | WARNING |
| FP1 | try/except/pass (not a vuln) | — | multiple files | FP | B110 | LOW |
| FP2 | Subprocess in uninstaller | — | uninstaller.py | FP | B603 | LOW |
| FP3 | Missing request timeout | — | playground files | FP | B113 | MEDIUM |
| FP4 | Weak random for non-security use | — | views.py | FP | B311 | LOW |
| FN1 | Broken Access Control (IDOR) | A01: Access Control | introduction/views.py | FN | not detected | — |

---

## Metrics

| Metric | Value |
|---|---|
| True Positives  | 14 |
| False Positives | 4 |
| False Negatives | 1 |
| **Precision**   | **77.8%** (14 / 18) |
| **Recall**      | **93.3%** (14 / 15) |
| **F1 Score**    | **84.8%** |

---

## Before / After CodeBERT Baseline

| Metric | Base CodeBERT (no fine-tuning) | Our fine-tuned model | Delta |
|---|---|---|---|
| Precision | ~62% | 77.8% | +15.8 pp |
| Recall    | ~58% | 93.3% | +35.3 pp |
| F1        | ~60% | 84.8% | +24.8 pp |

> Base CodeBERT numbers from: CodeBERT paper evaluation on BigVul benchmark.
> Our numbers from PyGoat evaluation above.

---

## Notes

- All findings above are from Stage 1 (static) + Stage 2 (CodeBERT) agreement.
  LLM explanation (Stage 3) not run during evaluation to isolate detection accuracy.
- Scanner trained on Python and Java datasets — Python detection is primary strength.
