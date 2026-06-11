# paste this as audit.py and run it
import torch
from transformers import AutoModelForSequenceClassification

model = AutoModelForSequenceClassification.from_pretrained('model/checkpoints/final')

# Check the classifier head bias — this is the smoking gun
classifier_bias = model.classifier.out_proj.bias  # for RoBERTa-based models
# or try:
# classifier_bias = model.classifier.bias  # for BERT-based models

print("Classifier bias:", classifier_bias)
print("Bias difference (1 - 0):", (classifier_bias[1] - classifier_bias[0]).item())