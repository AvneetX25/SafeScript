# scanner/classifier.py
import json
import torch
from pathlib import Path
import os
from dotenv import load_dotenv
from transformers import AutoTokenizer, AutoModelForSequenceClassification
load_dotenv()


class VulnerabilityClassifier:
    def __init__(self, model_path: str = 'model/checkpoints/final_v2'):
        # Resolve model source:
        # 1. Explicit argument passed in code
        # 2. HF_MODEL_REPO env var (works locally + Streamlit Cloud)
        # 3. Local path fallback for dev without .env
        hf_repo = os.getenv("HF_MODEL_REPO", "Avneetx25/codebert-vulnerability-scanner")

        if model_path is not None and Path(model_path).exists():
            source = str(model_path)
            print(f"[INFO] Loading classifier from local path: {source}")
        else:
            source = hf_repo
            print(f"[INFO] Loading classifier from HF Hub: {source}")

        # Load threshold — check local path first, then download from Hub
        threshold_loaded = False
        if model_path is not None and (Path(model_path) / "threshold.json").exists():
            with open(Path(model_path) / "threshold.json", "r") as f:
                data = json.load(f)
            self.threshold = data.get("threshold", 0.30)
            threshold_loaded = True

        if not threshold_loaded:
            try:
                from huggingface_hub import hf_hub_download
                threshold_file = hf_hub_download(repo_id=source, filename="threshold.json")
                with open(threshold_file, "r") as f:
                    data = json.load(f)
                self.threshold = data.get("threshold", 0.30)
                print(f"[INFO] Threshold loaded from Hub: {self.threshold}")
            except Exception as e:
                print(f"[WARN] Could not load threshold.json: {e}, using default 0.30")
                self.threshold = 0.30

        print(f"[INFO] Using threshold={self.threshold}")

        self.tokenizer = AutoTokenizer.from_pretrained(source)
        self.model = AutoModelForSequenceClassification.from_pretrained(source)
        self.model.eval()

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)

        print(f"[INFO] Classifier ready on {self.device}")
    

    def classify(self, code: str) -> dict:
        """
        Classify a code chunk.
        Returns:
            {
                'vulnerable': bool,
                'confidence': float,   # probability of the predicted class
                'vuln_probability': float,  # always the probability of class 1 (Vulnerable)
                'threshold_used': float
            }
        """
        inputs = self.tokenizer(
            code,
            return_tensors='pt',
            truncation=True,
            max_length=512,
            padding=True
        )
        # Move inputs to same device as model
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self.model(**inputs)

        probs = torch.softmax(outputs.logits, dim=1)[0]
        vuln_prob = probs[1].item()  # index 1 = Vulnerable class

        # Apply sweep-selected threshold from Week 3
        is_vulnerable = vuln_prob >= self.threshold

        return {
            'vulnerable': bool(is_vulnerable),
            'confidence': round(vuln_prob, 4),
            'vuln_probability': round(vuln_prob, 4),
            'threshold_used': self.threshold
        }