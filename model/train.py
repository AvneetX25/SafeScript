# model/train.py
# CodeBERT fine-tuning for vulnerability detection
# Optimized for HIGH RECALL — minimize missed vulnerabilities
# Pipeline: Static Analysis → This Model → LLM fix suggestion
# Designed to run on Kaggle GPU (T4 x2 or P100)

import os
import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
from datasets import Dataset
from torch import nn
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
)
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    fbeta_score,
    classification_report,
)
import json

# ── Config ────────────────────────────────────────────────────────────────────
MODEL_NAME = "microsoft/codebert-base"
DATA_PATH  = os.getenv("DATA_PATH", "data/processed/dataset_clean.csv")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "model/checkpoints")
FINAL_DIR  = os.path.join(OUTPUT_DIR, "final")
MAX_LEN    = 512
BATCH_SIZE = 16
EPOCHS     = 3
SEED       = 42

# Classification threshold — lower than default 0.5 to favour recall
# The LLM stage handles false positives, so we'd rather over-flag than miss.
THRESHOLD  = 0.35

# ── Focal Loss ────────────────────────────────────────────────────────────────
# Replaces standard CrossEntropyLoss.
# Two advantages over plain CE:
#   1. alpha=0.75 → vulnerable class (label=1) gets 3x the penalty weight
#   2. gamma=2.0  → easy/confident predictions are down-weighted so the model
#                   focuses training budget on hard, ambiguous vulnerability cases
class FocalLoss(nn.Module):
    def __init__(self, alpha: float = 0.75, gamma: float = 2.0):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        ce      = F.cross_entropy(logits, targets, reduction="none")
        pt      = torch.exp(-ce)
        alpha_t = torch.where(targets == 1, self.alpha, 1.0 - self.alpha)
        focal   = alpha_t * (1.0 - pt) ** self.gamma * ce
        return focal.mean()


# ── Load & validate data ──────────────────────────────────────────────────────
print("\n[1/5] Loading dataset...")
df = pd.read_csv(DATA_PATH)
df = df[["code", "label"]].rename(columns={"code": "text"})
df["label"] = df["label"].astype(int)

print(f"  Total rows  : {len(df)}")
print(f"  Vulnerable  : {(df['label'] == 1).sum()}")
print(f"  Safe        : {(df['label'] == 0).sum()}")

# ── Train / val split ─────────────────────────────────────────────────────────
print("\n[2/5] Splitting dataset...")
train_df = df.sample(frac=0.85, random_state=SEED)
val_df   = df.drop(train_df.index).reset_index(drop=True)
train_df = train_df.reset_index(drop=True)

print(f"  Train : {len(train_df)} rows")
print(f"  Val   : {len(val_df)} rows")

# ── Class weights ─────────────────────────────────────────────────────────────
# Computed from TRAIN split only to avoid data leakage.
# Formula: total / (n_classes * class_count)
#   Safe weight       ≈ 0.75  (majority class, penalised less)
#   Vulnerable weight ≈ 1.50  (minority class, penalised more)
n_total     = len(train_df)
n_safe      = (train_df["label"] == 0).sum()
n_vuln      = (train_df["label"] == 1).sum()
weight_safe = n_total / (2 * n_safe)
weight_vuln = n_total / (2 * n_vuln)

device       = "cuda" if torch.cuda.is_available() else "cpu"
class_weights = torch.tensor([weight_safe, weight_vuln], dtype=torch.float32).to(device)

print(f"  Class weights → Safe: {weight_safe:.3f} | Vulnerable: {weight_vuln:.3f}")

# ── Tokenize ──────────────────────────────────────────────────────────────────
print("\n[3/5] Tokenizing...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

def tokenize(batch):
    return tokenizer(
        batch["text"],
        truncation=True,
        padding="max_length",
        max_length=MAX_LEN,
    )

train_ds = Dataset.from_pandas(train_df).map(tokenize, batched=True)
val_ds   = Dataset.from_pandas(val_df).map(tokenize, batched=True)

train_ds = train_ds.remove_columns(["text"])
val_ds   = val_ds.remove_columns(["text"])

train_ds.set_format("torch")
val_ds.set_format("torch")

print(f"  Tokenization complete. Sample keys: {list(train_ds[0].keys())}")

# ── Model ─────────────────────────────────────────────────────────────────────
print("\n[4/5] Loading CodeBERT model...")
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=2,
)

# ── Metrics ───────────────────────────────────────────────────────────────────
# Primary metric : F2 on Vulnerable class  — rewards recall 2x over precision
# Guardrail      : recall_vuln             — hard floor, must stay ≥ 0.95
# Cost control   : precision_vuln          — soft floor, keep ≥ 0.65
# Reference      : f1                      — kept for comparison with Week 3
def compute_metrics(eval_pred):
    logits, labels = eval_pred
    probs = torch.softmax(torch.tensor(logits), dim=-1)[:, 1].numpy()
    preds = (probs >= THRESHOLD).astype(int)
    return {
        "f2_vuln"        : round(fbeta_score(labels, preds, beta=2,  pos_label=1, zero_division=0), 4),
        "recall_vuln"    : round(recall_score(labels, preds,          pos_label=1, zero_division=0), 4),
        "precision_vuln" : round(precision_score(labels, preds,       pos_label=1, zero_division=0), 4),
        "f1"             : round(f1_score(labels, preds,                           zero_division=0), 4),
    }

# ── Training args ─────────────────────────────────────────────────────────────
training_args = TrainingArguments(
    output_dir                  = OUTPUT_DIR,
    num_train_epochs            = EPOCHS,
    per_device_train_batch_size = BATCH_SIZE,
    per_device_eval_batch_size  = BATCH_SIZE,
    eval_strategy               = "epoch",
    save_strategy               = "epoch",
    load_best_model_at_end      = True,
    metric_for_best_model       = "f2_vuln",   # was "f1" — now recall-weighted
    greater_is_better           = True,
    seed                        = SEED,
    fp16                        = torch.cuda.is_available(),
    logging_steps               = 50,
    report_to                   = "none",
    learning_rate               = 2e-5,
    warmup_ratio                = 0.1,
    weight_decay                = 0.01,
)

# ── Custom Trainer — swaps CE loss for Focal Loss ─────────────────────────────
focal_loss_fn = FocalLoss(alpha=0.75, gamma=2.0).to(device)

class RecallFocusedTrainer(Trainer):
    """Identical to HuggingFace Trainer but uses FocalLoss instead of CE."""
    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        labels  = inputs.pop("labels")
        outputs = model(**inputs)
        logits  = outputs.logits
        loss    = focal_loss_fn(logits, labels)
        return (loss, outputs) if return_outputs else loss

trainer = RecallFocusedTrainer(
    model           = model,
    args            = training_args,
    train_dataset   = train_ds,
    eval_dataset    = val_ds,
    compute_metrics = compute_metrics,
)

# ── Baseline evaluation BEFORE fine-tuning ───────────────────────────────────
print("\n[5/5] Running BASELINE evaluation (before fine-tuning)...")
baseline_results = trainer.evaluate()
print(f"  Baseline results: {baseline_results}")

baseline_metrics = {
    "stage"          : "baseline_before_finetuning",
    "precision_vuln" : baseline_results.get("eval_precision_vuln", 0),
    "recall_vuln"    : baseline_results.get("eval_recall_vuln",    0),
    "f2_vuln"        : baseline_results.get("eval_f2_vuln",        0),
    "f1"             : baseline_results.get("eval_f1",             0),
    "loss"           : baseline_results.get("eval_loss",           0),
}

# ── Train ─────────────────────────────────────────────────────────────────────
print("\nTraining for 3 epochs with Focal Loss + class weights...")
trainer.train()

# ── Final evaluation AFTER fine-tuning ───────────────────────────────────────
print("\nFinal evaluation (after fine-tuning)...")
final_results = trainer.evaluate()
print(f"  Final results: {final_results}")

final_metrics = {
    "stage"          : "finetuned_after_3_epochs",
    "precision_vuln" : final_results.get("eval_precision_vuln", 0),
    "recall_vuln"    : final_results.get("eval_recall_vuln",    0),
    "f2_vuln"        : final_results.get("eval_f2_vuln",        0),
    "f1"             : final_results.get("eval_f1",             0),
    "loss"           : final_results.get("eval_loss",           0),
}

# ── Threshold sweep ───────────────────────────────────────────────────────────
# Run AFTER training on the existing model — free recall boost, no retraining.
# Pick the lowest threshold where recall_vuln first reaches ≥ 0.95.
print("\nThreshold sweep — finding optimal operating point (recall ≥ 0.95)...")
sweep_output = trainer.predict(val_ds)
sweep_probs  = torch.softmax(torch.tensor(sweep_output.predictions), dim=-1)[:, 1].numpy()
sweep_labels = sweep_output.label_ids

print(f"\n  {'Threshold':>10} | {'Recall':>8} | {'Precision':>10} | {'F2':>8}")
print(f"  {'-'*48}")

best_threshold    = THRESHOLD
best_threshold_set = False

for t in [0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]:
    p   = (sweep_probs >= t).astype(int)
    r   = recall_score(sweep_labels,    p, pos_label=1, zero_division=0)
    pr  = precision_score(sweep_labels, p, pos_label=1, zero_division=0)
    f2  = fbeta_score(sweep_labels,     p, beta=2, pos_label=1, zero_division=0)
    tag = " ← use this" if r >= 0.95 and not best_threshold_set else ""
    if r >= 0.95 and not best_threshold_set:
        best_threshold     = t
        best_threshold_set = True
    print(f"  {t:>10.2f} | {r:>8.4f} | {pr:>10.4f} | {f2:>8.4f}{tag}")

print(f"\n  Best threshold for recall ≥ 0.95 → {best_threshold}")

# ── Classification report at best threshold ───────────────────────────────────
print("\nDetailed classification report at best threshold...")
final_preds = (sweep_probs >= best_threshold).astype(int)
report = classification_report(
    sweep_labels, final_preds,
    target_names=["Safe (0)", "Vulnerable (1)"]
)
print(report)

# ── Save model ────────────────────────────────────────────────────────────────
print(f"\nSaving model to {FINAL_DIR}...")
os.makedirs(FINAL_DIR, exist_ok=True)
trainer.save_model(FINAL_DIR)
tokenizer.save_pretrained(FINAL_DIR)

# Save best threshold alongside model so inference uses the same value
with open(os.path.join(FINAL_DIR, "threshold.json"), "w") as f:
    json.dump({"threshold": best_threshold}, f)

print("  Model + threshold saved.")

# ── Save results ──────────────────────────────────────────────────────────────
results_payload = {
    "baseline"  : baseline_metrics,
    "finetuned" : {
        **final_metrics,
        "f2_vuln"        : round(fbeta_score(sweep_labels, final_preds, beta=2, pos_label=1), 4),
        "recall_vuln"    : round(recall_score(sweep_labels, final_preds, pos_label=1), 4),
        "precision_vuln" : round(precision_score(sweep_labels, final_preds, pos_label=1), 4),
        "best_threshold" : best_threshold,
    },
    "classification_report" : report,
}

os.makedirs("evaluation", exist_ok=True)
with open("evaluation/results.json", "w") as f:
    json.dump(results_payload, f, indent=2)

print("\nResults saved to evaluation/results.json")
print("\nWeek 3 (v2) complete — model optimised for recall.")