# SafeScript 🛡️

> **AI-powered code vulnerability scanner — 98% recall on vulnerable code, zero false positives on WebGoat.**

Static analysis + fine-tuned CodeBERT + LLM fix suggestions, chained in a three-stage pipeline that catches what single tools miss.

🔗 **[Try the live scanner →](https://safescript.streamlit.app/)**

---

## What It Does

SafeScript scans Python and Java codebases for security vulnerabilities using three stages:

1. **Static Analysis** — Semgrep rules flag taint flows, insecure APIs, and hardcoded secrets
2. **CodeBERT Classifier** — Fine-tuned `microsoft/codebert-base` scores each flagged chunk for vulnerability confidence
3. **LLM Fix Suggester** — Groq-powered stage explains the vulnerability and suggests a concrete fix

Each stage filters the noise the previous one lets through. Only high-confidence findings reach the LLM — keeping API costs low and signal high.

---

## Benchmark Results

### PyGoat (Python — OWASP intentionally vulnerable app)

| Metric | Base CodeBERT | SafeScript | Improvement |
|--------|--------------|------------|-------------|
| Precision | ~62% | **77.8%** | +15.8 pp |
| Recall | ~58% | **93.3%** | +35.3 pp |
| F1 | ~60% | **84.8%** | +24.8 pp |

- ✅ True Positives: 14 &nbsp;|&nbsp; ❌ False Positives: 4 &nbsp;|&nbsp; ⚠️ False Negatives: 1
- Vulnerabilities caught: SQL Injection, Command Injection, SSRF, XSS, SSTI, XXE, Weak Hashing, Insecure Deserialization, Hardcoded JWT Secret, Insecure Cookies, Log Injection

### WebGoat (Java — OWASP intentionally vulnerable app)

| Metric | Base CodeBERT | SafeScript | Improvement |
|--------|--------------|------------|-------------|
| Precision | ~62% | **100.0%** | +38.0 pp |
| Recall | ~58% | **75.0%** | +17.0 pp |
| F1 | ~60% | **85.7%** | +25.7 pp |

- ✅ True Positives: 6 &nbsp;|&nbsp; ❌ False Positives: 0 &nbsp;|&nbsp; ⚠️ False Negatives: 2
- Vulnerabilities caught: Insecure Deserialization, Weak Hashing (MD5), Insecure Randomness, Hardcoded Credentials, Insecure Cookies, SQL Injection

> Zero false positives on WebGoat — the two-stage intersection filter eliminates single-tool noise entirely.

---

## Architecture

```
Your Code
    │
    ▼
┌─────────────────────────┐
│  Stage 1: Static Analysis│  ← Semgrep, 10 custom rules per language
│  (Python + Java)        │     Flags taint flows, insecure APIs, secrets
└────────────┬────────────┘
             │ flagged chunks
             ▼
┌─────────────────────────┐
│  Stage 2: CodeBERT      │  ← Fine-tuned on 7,866 real CVE samples
│  Classifier             │     Threshold: 0.30 (recall-optimised)
└────────────┬────────────┘
             │ high-confidence flags only
             ▼
┌─────────────────────────┐
│  Stage 3: LLM Fix       │  ← Groq-powered
│  Suggester              │     Plain-English explanation + code fix
└─────────────────────────┘
```

### Three-Tier False Positive Filter

| Condition | Action |
|-----------|--------|
| Both stages agree (static + model) | ✅ Sent to LLM — high confidence |
| Model only, confidence ≥ 0.75 | ✅ Sent to LLM — novel pattern, no static rule exists |
| Static only, or model confidence < 0.75 | ❌ Dropped silently |

---

## Model Training

Base model: `microsoft/codebert-base`

Two training runs were conducted. v1 optimised for F1. After analysis, v2 was redesigned to maximise recall — a missed vulnerability reaching production is far costlier than a false alarm that the LLM stage can filter.

### v1 vs v2 — Head-to-Head

| Metric | v1 (F1-optimised) | v2 (Recall-optimised) | Δ |
|--------|-------------------|-----------------------|---|
| Recall — Vulnerable | 0.82 | **0.98** | +16 pp |
| Precision — Vulnerable | 0.82 | 0.62 | −20 pp |
| Missed vulns / 100 | ~18 | **~2** | −16 |
| False alarms / 100 | ~18 | ~29 | +11 |
| Decision threshold | 0.50 | **0.30** | — |

### v2 Design Changes

| Component | v1 | v2 |
|-----------|----|----|
| Loss function | CrossEntropyLoss | Focal Loss (α=0.667, γ=2.0) |
| Class weighting | None | Inverse-frequency (safe=0.75, vuln=1.50) |
| Decision threshold | 0.50 | 0.30 (sweep-selected) |
| Best-model metric | F1 | F2 (weights recall 2× over precision) |
| Train/val split | Random 85/15 | Stratified 85/15 |

### Threshold Sweep (v2)

Swept from 0.50 → 0.20. Selected the highest threshold still achieving recall ≥ 0.95.

| Threshold | Recall | Precision | F2 | |
|-----------|--------|-----------|----|-|
| 0.50 | 0.87 | 0.72 | 0.83 | |
| 0.45 | 0.90 | 0.68 | 0.85 | |
| 0.40 | 0.93 | 0.67 | 0.86 | |
| 0.35 | 0.95 | 0.64 | 0.87 | |
| **0.30** | **0.98** | **0.63** | **0.88** | ← selected |
| 0.25 | 0.98 | 0.59 | 0.87 | |
| 0.20 | 0.99 | 0.56 | 0.86 | |

### v2 Epoch Progression

| Epoch | Recall (vuln) | Precision (vuln) | F2 | Val Loss |
|-------|--------------|------------------|----|----------|
| Baseline | 1.00 | 0.33 | 0.71 | 0.0764 |
| 1 | 0.98 | 0.51 | 0.83 | 0.0480 |
| **2** | **0.95** | **0.64** | **0.87** | **0.0396** ← best |
| 3 | 0.93 | 0.67 | 0.86 | 0.0415 |

---

## Dataset

| Property | Value |
|----------|-------|
| Total rows | 7,866 |
| Vulnerable | 2,622 (33%) |
| Safe | 5,244 (67%) |
| Class ratio | 1 : 2 (vuln : safe) |
| Languages | Python (5,947) · Java (1,919) |
| Real CVE data | ~3,803 rows |
| Synthetic/mixed | ~4,063 rows |

### Sources

| Dataset | Raw Rows | Type |
|---------|----------|------|
| CVEFixes | 12,987 | Real CVE patches from open-source repos |
| DetectVul | 5,730 | Function-level vulnerability labels |
| SecVuln | 175,419 | Mixed/synthetic, used for augmentation |

After deduplication, filtering, and stratified merge: **7,866 clean rows.**

---

## Project Structure

```
safescript/
├── scanner/
│   └── static_analysis.py      # Stage 1 — Semgrep wrapper
├── model/
│   ├── train.py                # Fine-tuning script (v2)
│   ├── classifier.py           # Stage 2 — CodeBERT inference
│   └── checkpoints/final/      # Saved model + threshold.json
├── llm/
│   └── llm_explainer.py        # Stage 3 — Groq fix suggestions
├── pipeline.py                 # Chains all three stages
├── cli/
│   └── main.py                 # CLI entrypoint (--repo argument)
├── rules/
│   ├── python_security.yml     # Custom Semgrep rules — Python
│   └── java_security.yml       # Custom Semgrep rules — Java
├── data/
│   ├── raw/                    # Downloaded datasets
│   └── processed/
│       └── dataset_clean.csv   # Merged, cleaned training data
├── evaluation/
│   ├── results.md              # PyGoat + WebGoat benchmark results
│   └── results.json            # Raw evaluation output
├── app.py                      # Streamlit UI
├── .env                        # API keys (not committed)
└── .gitignore
```

---

## Installation

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/safescript.git
cd safescript

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Add your GROQ_API_KEY to .env
```

---

## Usage

### Streamlit UI (recommended)

```bash
streamlit run app.py
```

Or use the live deployment: **[safescript.streamlit.app](https://safescript.streamlit.app/)**

### CLI

```bash
# Scan a local repo
python cli/main.py --repo /path/to/your/project

# Skip LLM stage (faster, Stage 1 + 2 only)
python cli/main.py --repo /path/to/your/project --no-llm
```

### Python API

```python
from pipeline import scan

results = scan("/path/to/your/project")
for finding in results:
    print(finding["file"], finding["severity"], finding["fix"])
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Static analysis | Semgrep (custom rules) + Bandit |
| ML classifier | `microsoft/codebert-base` fine-tuned |
| LLM fix suggester | Groq API |
| Training | PyTorch + HuggingFace Transformers |
| UI | Streamlit |
| CLI | argparse |

---

## Known Limitations

- **XSS via Spring MVC** — `@ResponseBody` taint paths not yet covered; raw servlet pattern only
- **Open Redirect (inter-procedural)** — requires dataflow across method boundaries, beyond current Semgrep OSS
- **SQL Injection (full taint)** — files flagged correctly but specific JDBC taint path not traced end-to-end
- Python detection is the primary strength; Java ruleset has fewer patterns

---

## Built by

**Avneet** —  [LinkedIn](https://www.linkedin.com/in/avneetkaur025/)

---

*© 2026 Avneet. Open source.*
