# model/train.py
# CodeBERT fine-tuning for vulnerability detection
# Designed to run on Kaggle GPU (T4 x2 or P100)
# Dataset pulled from GitHub repo
import os
import numpy as np
import pandas as pd
from datasets import Dataset
from torch import nn
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
)
from sklearn.metrics import precision_score, recall_score, f1_score, classification_report
import json

# ── Config ────────────────────────────────────────────────────────────────────
MODEL_NAME   = "microsoft/codebert-base"
DATA_PATH    = os.getenv("DATA_PATH", "data/processed/dataset_clean.csv")
OUTPUT_DIR   = os.getenv("OUTPUT_DIR", "model/checkpoints")
FINAL_DIR    = os.path.join(OUTPUT_DIR, "final")
MAX_LEN      = 512
BATCH_SIZE   = 16
EPOCHS       = 3
SEED         = 42

# ── Load & validate data ──────────────────────────────────────────────────────
print("\n[1/5] Loading dataset...")
df = pd.read_csv(DATA_PATH)

# map to standard column names
df = df[["code", "label"]].rename(columns={"code": "text"})
df["label"] = df["label"].astype(int)

print(f"  Total rows  : {len(df)}")
print(f"  Vulnerable  : {(df['label']==1).sum()}")
print(f"  Safe        : {(df['label']==0).sum()}")

# ── Train / val split ─────────────────────────────────────────────────────────
print("\n[2/5] Splitting dataset...")
train_df = df.sample(frac=0.85, random_state=SEED)
val_df   = df.drop(train_df.index).reset_index(drop=True)
train_df = train_df.reset_index(drop=True)

print(f"  Train : {len(train_df)} rows")
print(f"  Val   : {len(val_df)} rows")

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
def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=1)
    return {
        "precision" : round(precision_score(labels, preds, zero_division=0), 4),
        "recall"    : round(recall_score(labels, preds, zero_division=0), 4),
        "f1"        : round(f1_score(labels, preds, zero_division=0), 4),
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
    metric_for_best_model       = "f1",
    greater_is_better           = True,
    seed                        = SEED,
    fp16                        = True,
    logging_steps               = 50,
    report_to                   = "none",
    learning_rate               = 2e-5,   # standard for CodeBERT fine-tuning
    warmup_ratio                = 0.1,    # 10% of steps warm up gradually
    weight_decay                = 0.01,   # mild regularization
)
class WeightedTrainer(Trainer):
    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        labels = inputs.pop("labels")
        outputs = model(**inputs)
        # upweight vulnerable class (label=1) by 2x
        weights = torch.tensor([1.0, 2.0], device=model.device)
        loss_fn = nn.CrossEntropyLoss(weight=weights)
        loss = loss_fn(outputs.logits, labels)
        return (loss, outputs) if return_outputs else loss
    
    
# ── Trainer ───────────────────────────────────────────────────────────────────
trainer = WeightedTrainer(
    model           = model,
    args            = training_args,
    train_dataset   = train_ds,
    eval_dataset    = val_ds,
    compute_metrics = compute_metrics,
)

# ── Run baseline BEFORE fine-tuning ──────────────────────────────────────────
print("\n[5/5] Running BASELINE evaluation (before fine-tuning)...")
baseline_results = trainer.evaluate()
print(f"  Baseline results: {baseline_results}")

baseline_metrics = {
    "stage"     : "baseline_before_finetuning",
    "precision" : baseline_results.get("eval_precision", 0),
    "recall"    : baseline_results.get("eval_recall", 0),
    "f1"        : baseline_results.get("eval_f1", 0),
    "loss"      : baseline_results.get("eval_loss", 0),
}

# ── Train ─────────────────────────────────────────────────────────────────────
print("\n Training for 3 epochs...")
trainer.train()

# ── Evaluate AFTER fine-tuning ────────────────────────────────────────────────
print("\n Final evaluation (after fine-tuning)...")
final_results = trainer.evaluate()
print(f"  Final results: {final_results}")

final_metrics = {
    "stage"     : "finetuned_after_3_epochs",
    "precision" : final_results.get("eval_precision", 0),
    "recall"    : final_results.get("eval_recall", 0),
    "f1"        : final_results.get("eval_f1", 0),
    "loss"      : final_results.get("eval_loss", 0),
}

# ── Full classification report ────────────────────────────────────────────────
print("\n Detailed classification report...")
predictions = trainer.predict(val_ds)
preds = np.argmax(predictions.predictions, axis=1)
report = classification_report(
    predictions.label_ids, preds,
    target_names=["Safe (0)", "Vulnerable (1)"]
)
print(report)

# ── Save model ────────────────────────────────────────────────────────────────
print(f"\n Saving model to {FINAL_DIR}...")
os.makedirs(FINAL_DIR, exist_ok=True)
trainer.save_model(FINAL_DIR)
tokenizer.save_pretrained(FINAL_DIR)
print("  Model saved.")

# ── Save results to JSON ──────────────────────────────────────────────────────
results_payload = {
    "baseline" : baseline_metrics,
    "finetuned": final_metrics,
    "classification_report": report,
}

os.makedirs("evaluation", exist_ok=True)
with open("evaluation/results.json", "w") as f:
    json.dump(results_payload, f, indent=2)

print("\n Results saved to evaluation/results.json")
print("\n Week 3 complete.")