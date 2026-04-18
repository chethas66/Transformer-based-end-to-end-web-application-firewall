import torch
from torch.utils.data import Dataset, DataLoader
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    EvalPrediction
)
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
import numpy as np
import pandas as pd
from typing import List, Dict, Tuple
import json
import os


class WAFDataset(Dataset):

    def __init__(self, texts: List[str], labels: List[int], tokenizer, max_length: int = 512):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = self.texts[idx]
        label = self.labels[idx]

        encoding = self.tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )

        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }


class WAFTransformerTrainer:

    def __init__(
        self,
        model_name: str = "distilbert-base-uncased",
        output_dir: str = "./models/waf_transformer",
        max_length: int = 512
    ):
        self.model_name = model_name
        self.output_dir = output_dir
        self.max_length = max_length

        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = None

        os.makedirs(output_dir, exist_ok=True)

    def load_data_from_csv(self, csv_path: str) -> Tuple[List[str], List[int]]:
        df = pd.read_csv(csv_path)

        if 'normalized_request' not in df.columns or 'label' not in df.columns:
            raise ValueError("CSV must contain 'normalized_request' and 'label' columns")

        texts = df['normalized_request'].tolist()
        labels = df['label'].tolist()

        return texts, labels

    def load_data_from_supabase(self, supabase_client, limit: int = 10000) -> Tuple[List[str], List[int]]:
        response = supabase_client.table('waf_requests') \
            .select('normalized_request, prediction') \
            .not_.is_('normalized_request', 'null') \
            .not_.is_('prediction', 'null') \
            .limit(limit) \
            .execute()

        texts = []
        labels = []
        for record in response.data:
            texts.append(record['normalized_request'])
            labels.append(1 if record['prediction'] == 'malicious' else 0)

        return texts, labels

    def generate_synthetic_training_data(self) -> Tuple[List[str], List[int]]:
        benign_samples = [
            "GET /api/users/<ID>",
            "POST /api/auth/login BODY:{\"email\":\"<EMAIL>\",\"password\":\"<PASSWORD>\"}",
            "GET /api/products?category=electronics&page=<ID>",
            "PUT /api/profile/<UUID> BODY:{\"name\":\"<USER>\",\"bio\":\"Hello world\"}",
            "DELETE /api/posts/<UUID>",
            "GET /static/images/logo.png",
            "POST /api/search BODY:{\"query\":\"laptop\",\"filters\":{\"price\":\"<ID>\"}}",
            "GET /api/orders/<UUID>/status",
            "GET /dashboard?date=<TIMESTAMP>",
            "POST /api/comments BODY:{\"text\":\"Great product!\",\"rating\":<ID>}",
        ]

        malicious_samples = [
            "GET /api/users?id=1 OR 1=1--",
            "POST /api/search BODY:{\"query\":\"<script>alert(1)</script>\"}",
            "GET /api/file?path=../../../etc/passwd",
            "POST /api/exec BODY:{\"cmd\":\"ls; cat /etc/passwd\"}",
            "GET /api/products?id=1 UNION SELECT username,password FROM users--",
            "POST /login BODY:{\"user\":\"admin'--\",\"pass\":\"x\"}",
            "GET /api/data?url=http://169.254.169.254/latest/meta-data/",
            "POST /api/xml BODY:<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
            "GET /api/img?src=javascript:alert(document.cookie)",
            "GET /api/search?q=<img src=x onerror=alert(1)>",
            "POST /api/update BODY:{\"sql\":\"'; DROP TABLE users--\"}",
            "GET /api/page?redirect=file:///etc/passwd",
            "POST /api/eval BODY:{\"code\":\"eval(atob('YWxlcnQoMSk='))\"}",
            "GET /api/../admin/config",
            "POST /api/inject BODY:{\"param\":\"x' AND SLEEP(5)--\"}",
        ]

        texts = benign_samples * 10 + malicious_samples * 10
        labels = [0] * (len(benign_samples) * 10) + [1] * (len(malicious_samples) * 10)

        combined = list(zip(texts, labels))
        np.random.shuffle(combined)
        texts, labels = zip(*combined)

        return list(texts), list(labels)

    def compute_metrics(self, pred: EvalPrediction) -> Dict[str, float]:
        labels = pred.label_ids
        preds = pred.predictions.argmax(-1)

        precision, recall, f1, _ = precision_recall_fscore_support(
            labels, preds, average='binary'
        )
        acc = accuracy_score(labels, preds)

        cm = confusion_matrix(labels, preds)
        tn, fp, fn, tp = cm.ravel()

        return {
            'accuracy': acc,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'true_positives': int(tp),
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
        }

    def train(
        self,
        texts: List[str],
        labels: List[int],
        test_size: float = 0.2,
        epochs: int = 3,
        batch_size: int = 16,
        learning_rate: float = 2e-5
    ):
        train_texts, val_texts, train_labels, val_labels = train_test_split(
            texts, labels, test_size=test_size, random_state=42, stratify=labels
        )

        print(f"Training samples: {len(train_texts)}")
        print(f"Validation samples: {len(val_texts)}")
        print(f"Malicious samples: {sum(labels)} ({sum(labels)/len(labels)*100:.1f}%)")

        train_dataset = WAFDataset(train_texts, train_labels, self.tokenizer, self.max_length)
        val_dataset = WAFDataset(val_texts, val_labels, self.tokenizer, self.max_length)

        self.model = AutoModelForSequenceClassification.from_pretrained(
            self.model_name,
            num_labels=2,
            problem_type="single_label_classification"
        )

        training_args = TrainingArguments(
            output_dir=self.output_dir,
            num_train_epochs=epochs,
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=batch_size,
            warmup_steps=500,
            weight_decay=0.01,
            logging_dir=f'{self.output_dir}/logs',
            logging_steps=10,
            eval_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="f1",
            learning_rate=learning_rate,
            fp16=torch.cuda.is_available(),
        )

        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=self.compute_metrics,
        )

        print("\n🚀 Starting training...")
        trainer.train()

        print("\n📊 Evaluating model...")
        eval_results = trainer.evaluate()
        print("\nEvaluation Results:")
        for key, value in eval_results.items():
            print(f"  {key}: {value:.4f}")

        self.model.save_pretrained(self.output_dir)
        self.tokenizer.save_pretrained(self.output_dir)

        print(f"\n✅ Model and tokenizer saved to {self.output_dir}")

        return eval_results

    def export_to_onnx(self, onnx_path: str = None):
        if onnx_path is None:
            onnx_path = os.path.join(self.output_dir, "model.onnx")

        if self.model is None:
            self.model = AutoModelForSequenceClassification.from_pretrained(self.output_dir)

        dummy_input = self.tokenizer(
            "GET /api/test",
            return_tensors="pt",
            padding='max_length',
            max_length=self.max_length,
            truncation=True
        )

        self.model.eval()

        torch.onnx.export(
            self.model,
            (dummy_input['input_ids'], dummy_input['attention_mask']),
            onnx_path,
            input_names=['input_ids', 'attention_mask'],
            output_names=['logits'],
            dynamic_axes={
                'input_ids': {0: 'batch_size', 1: 'sequence'},
                'attention_mask': {0: 'batch_size', 1: 'sequence'},
                'logits': {0: 'batch_size'}
            },
            opset_version=14
        )

        print(f"\n✅ Model exported to ONNX: {onnx_path}")
        return onnx_path


if __name__ == "__main__":
    print("=== WAF Transformer Training Pipeline ===\n")

    trainer = WAFTransformerTrainer(
        model_name="distilbert-base-uncased",
        output_dir="./models/waf_transformer"
    )

    print("Generating synthetic training data...")
    texts, labels = trainer.generate_synthetic_training_data()

    print(f"\nDataset size: {len(texts)} samples")
    print(f"Benign: {sum(1 for l in labels if l == 0)}")
    print(f"Malicious: {sum(1 for l in labels if l == 1)}")

    eval_results = trainer.train(
        texts=texts,
        labels=labels,
        test_size=0.2,
        epochs=3,
        batch_size=16,
        learning_rate=2e-5
    )

    print("\n📦 Exporting model to ONNX...")
    trainer.export_to_onnx()

    print("\n🎉 Training pipeline completed successfully!")
