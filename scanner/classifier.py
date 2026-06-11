# scanner/classifier.py

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification


class VulnerabilityClassifier:
    def __init__(self, model_path: str = 'model/checkpoints/final'):
        print(f"[INFO] Loading fine-tuned model from {model_path} ...")
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
        self.model.eval()
        print("[INFO] Model loaded successfully.")

    def classify(self, code: str) -> dict:
        """
        Classify a code chunk as vulnerable or safe.
        Returns:
            {
                'vulnerable': bool,
                'confidence': float,   # confidence in the predicted class
                'vuln_score': float    # raw probability of being vulnerable (class 1)
            }
        """
        inputs = self.tokenizer(
            code,
            return_tensors='pt',
            truncation=True,
            max_length=512,
            padding=True
        )

        with torch.no_grad():
            outputs = self.model(**inputs)
            print("Raw logits:", outputs.logits)

        probs = torch.softmax(outputs.logits, dim=1)[0]  # [safe_prob, vuln_prob]
        label = torch.argmax(probs).item()               # 0 = safe, 1 = vulnerable
        confidence = probs[label].item()
        vuln_score = probs[1].item()                     # always the vuln probability

        return {
            'vulnerable': bool(label == 1),
            'confidence': round(confidence, 4),
            'vuln_score': round(vuln_score, 4)
        }