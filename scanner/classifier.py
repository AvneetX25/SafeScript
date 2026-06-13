# scanner/classifier.py
# scanner/classifier.py
import json
import torch
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification


class VulnerabilityClassifier:
    def __init__(self, model_path: str = 'model/checkpoints/final_v2'):
        model_path = Path(model_path)

        # Load threshold from threshold.json saved during Week 3
        threshold_file = model_path / 'threshold.json'
        if threshold_file.exists():
            with open(threshold_file, 'r') as f:
                data = json.load(f)
            self.threshold = data.get('threshold', 0.30)
        else:
            print(f"[WARN] threshold.json not found at {threshold_file}, using default 0.30")
            self.threshold = 0.30

        print(f"[INFO] Loading classifier from {model_path} (threshold={self.threshold})")

        self.tokenizer = AutoTokenizer.from_pretrained(str(model_path))
        self.model = AutoModelForSequenceClassification.from_pretrained(str(model_path))
        self.model.eval()

        # Use GPU if available
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
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