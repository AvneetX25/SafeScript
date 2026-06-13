# Model Evaluation Results

## Dataset

| Property        | Value                        |
|-----------------|------------------------------|
| Total rows      | 7,866                        |
| Train / Val     | 6,686 / 1,180 (stratified)   |
| Vulnerable      | 2,622 (33%)                  |
| Safe            | 5,244 (67%)                  |
| Class ratio     | 1 : 2 (vuln : safe)          |
| Base model      | `microsoft/codebert-base`    |

---

## Overview — Two Training Runs

This week involved two distinct training runs. The first (v1) optimised for F1.
After reviewing results, the goal was revised to **maximise recall on the Vulnerable
class** — a missed vulnerability reaching production is far more costly than a
false alarm that the downstream LLM stage can filter. A second run (v2) was
designed around this constraint.

---

## Run v1 — F1-Optimised Baseline (Original)

### Design choices
- Loss function: CrossEntropyLoss (default)
- Decision threshold: 0.50 (default argmax)
- Best-model metric: F1
- Split: random 85/15

### Before / After Fine-Tuning (v1)

| Metric    | Baseline (before) | Fine-tuned (after) | Δ         |
|-----------|-------------------|--------------------|-----------|
| Precision | 0.3314            | 0.8247             | +49.3 pp  |
| Recall    | 1.0000            | 0.8184             | −18.2 pp  |
| F1        | 0.4978            | 0.8216             | +32.4 pp  |
| Loss      | 0.7379            | 0.3136             | −57.5%    |

> Baseline flagged every sample as Vulnerable (random classifier head) —
> precision 0.33, recall 1.0 is expected behaviour before any fine-tuning.

### Epoch-by-Epoch Progression (v1)

| Epoch | Precision | Recall | F1     | Val Loss |
|-------|-----------|--------|--------|----------|
| 1     | 0.7214    | 0.8875 | 0.7959 | 0.3276   |
| 2     | 0.7985    | 0.8210 | 0.8096 | 0.3046   |
| 3     | 0.8247    | 0.8184 | 0.8216 | 0.3136   |

Best checkpoint: Epoch 3 (highest F1).

### Final Classification Report — v1 (threshold = 0.50)

```
              precision    recall  f1-score   support

    Safe (0)       0.91      0.91      0.91       789
    Vuln (1)       0.82      0.82      0.82       391

    accuracy                           0.88      1180
   macro avg       0.87      0.87      0.87      1180
weighted avg       0.88      0.88      0.88      1180
```

### Why v1 was not sufficient

Recall on the Vulnerable class was **0.82** — meaning roughly **1 in 5
vulnerabilities was silently missed**. For a security scanner, a missed
vulnerability is an undetected CVE in production. Precision errors, by contrast,
are handled cheaply by the LLM fix-suggestion stage downstream.

**Decision: retrain with recall as the primary objective.**

---

## Run v2 — Recall-Optimised (Current)

### Design changes from v1

| Component            | v1                   | v2                                          |
|----------------------|----------------------|---------------------------------------------|
| Loss function        | CrossEntropyLoss     | Focal Loss (α=0.667, γ=2.0)                 |
| Class weighting      | None                 | Inverse-frequency weights (safe=0.75, vuln=1.50) |
| Focal alpha          | —                    | Derived from class weights (0.667)          |
| Decision threshold   | 0.50 (argmax)        | 0.30 (sweep-selected)                       |
| Best-model metric    | F1                   | F2 (weights recall 2× over precision)       |
| Train/val split      | Random 85/15         | Stratified 85/15                            |

**Focal Loss** down-weights easy/confident predictions so the model focuses its
training budget on hard, ambiguous vulnerability cases. Alpha 0.667 gives the
Vulnerable class ~2× the penalty weight of the Safe class.

**Threshold sweep** was run post-training over [0.50 → 0.20] to find the highest
threshold still satisfying recall ≥ 0.95, avoiding the trivial recall=1.0 of
always predicting Vulnerable.

### Epoch-by-Epoch Progression (v2)

| Epoch    | Recall (vuln) | Precision (vuln) | F2     | Val Loss |
|----------|---------------|------------------|--------|----------|
| Baseline | 1.0000        | 0.3331           | 0.7140 | 0.0764   |
| 1        | 0.9822        | 0.5147           | 0.8312 | 0.0480   |
| 2        | **0.9491**    | **0.6420**       | **0.8662** | **0.0396** ← best |
| 3        | 0.9262        | 0.6741           | 0.8617 | 0.0415   |

Best checkpoint auto-selected: **Epoch 2** (highest F2).
Epoch 3 showed slight overfitting toward the Safe class (recall dropped, precision
rose) — `load_best_model_at_end=True` correctly reverted to Epoch 2.

### Threshold Sweep Results (v2, on Val set)

Sweep direction: high → low. Selected the **highest** threshold still achieving
recall ≥ 0.95 to maximise precision without sacrificing the recall floor.

| Threshold | Recall | Precision | F2     |           |
|-----------|--------|-----------|--------|-----------|
| 0.50      | 0.8702 | 0.7170    | 0.8346 |           |
| 0.45      | 0.9033 | 0.6801    | 0.8477 |           |
| 0.40      | 0.9338 | 0.6661    | 0.8643 |           |
| 0.35      | 0.9491 | 0.6420    | 0.8662 |           |
| **0.30**  | **0.9796** | **0.6250** | **0.8798** | ← selected |
| 0.25      | 0.9822 | 0.5938    | 0.8686 |           |
| 0.20      | 0.9873 | 0.5615    | 0.8573 |           |

**Selected threshold: 0.30** — saved to `model/checkpoints/final/threshold.json`
and used by `inference.py` automatically.

### Final Classification Report — v2 (threshold = 0.30)

```
                 precision    recall  f1-score   support

      Safe (0)       0.99      0.71      0.82       787
Vulnerable (1)       0.62      0.98      0.76       393

      accuracy                           0.80      1180
     macro avg       0.81      0.84      0.79      1180
  weighted avg       0.87      0.80      0.80      1180
```

### What these numbers mean in practice

Given 100 Safe samples and 100 Vulnerable samples at threshold=0.30:

| Actual Class  | Predicted Vulnerable | Predicted Safe |
|---------------|----------------------|----------------|
| 100 Safe      | ~29 (false alarm)    | ~71 ✅          |
| 100 Vulnerable| ~98 ✅               | ~2 (missed)    |

- **2 missed vulnerabilities** out of 100 — the critical number for a security scanner.
- **29 false alarms** out of 100 safe samples — passed to the LLM stage for filtering.
- Total flagged for LLM review: 127 out of 200 samples, of which 29 are noise.

This tradeoff is intentional: the cost of an undetected CVE in production
outweighs the cost of an extra LLM API call on a false alarm.

---

## v1 vs v2 — Head-to-Head Comparison

| Metric                | v1 (F1-opt) | v2 (Recall-opt) | Δ         |
|-----------------------|-------------|-----------------|-----------|
| Recall — Vulnerable   | 0.82        | **0.98**        | +16 pp    |
| Precision — Vulnerable| 0.82        | 0.62            | −20 pp    |
| F2 — Vulnerable       | —           | **0.88**        | —         |
| F1 — overall          | **0.88**    | 0.80            | −8 pp     |
| Missed vulns / 100    | ~18         | **~2**          | −16       |
| False alarms / 100    | ~18         | ~29             | +11       |
| Decision threshold    | 0.50        | 0.30            | —         |

v2 deliberately trades overall F1 and some precision for a 9× reduction in
missed vulnerabilities — the correct tradeoff for the security scanner use case.

---

## Training Configuration — v2

| Parameter              | Value                        |
|------------------------|------------------------------|
| Base model             | `microsoft/codebert-base`    |
| Epochs                 | 3 (best at epoch 2)          |
| Batch size             | 16                           |
| Max sequence length    | 512                          |
| Loss function          | Focal Loss (α=0.667, γ=2.0)  |
| Learning rate          | 2e-5                         |
| Warmup steps           | 10% of total steps           |
| Weight decay           | 0.01                         |
| Mixed precision (fp16) | Yes                          |
| Eval strategy          | Per epoch                    |
| Best-model metric      | F2 (vuln)                    |
| Decision threshold     | 0.30 (sweep-selected)        |
| Train/val split        | Stratified 85/15             |

---

## Saved Artifacts

| Artifact                  | Path                               |
|---------------------------|------------------------------------|
| Fine-tuned model (v2)     | `model/checkpoints/final/`         |
| Raw results (JSON)        | `evaluation/results.json`          |
| This report               | `evaluation/results.md`            |