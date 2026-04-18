import onnxruntime as ort
import numpy as np
from transformers import AutoTokenizer
from typing import Tuple, Dict, Optional
import time
import os
from dataclasses import dataclass


@dataclass
class InferenceResult:
    prediction: str
    confidence: float
    latency_ms: float
    logits: np.ndarray


class ONNXInferenceEngine:

    def __init__(
        self,
        model_path: str,
        tokenizer_path: str,
        max_length: int = 512,
        use_gpu: bool = False
    ):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"ONNX model not found at {model_path}")

        providers = ['CUDAExecutionProvider', 'CPUExecutionProvider'] if use_gpu else ['CPUExecutionProvider']

        sess_options = ort.SessionOptions()
        sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        sess_options.intra_op_num_threads = 4
        sess_options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL

        self.session = ort.InferenceSession(
            model_path,
            sess_options=sess_options,
            providers=providers
        )

        self.tokenizer = AutoTokenizer.from_pretrained(tokenizer_path)
        self.max_length = max_length

        self.input_names = [input.name for input in self.session.get_inputs()]
        self.output_names = [output.name for output in self.session.get_outputs()]

        print(f"✅ ONNX Runtime initialized")
        print(f"   Providers: {self.session.get_providers()}")
        print(f"   Input names: {self.input_names}")
        print(f"   Output names: {self.output_names}")

    def preprocess(self, text: str) -> Dict[str, np.ndarray]:
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='np'
        )

        return {
            'input_ids': encoding['input_ids'].astype(np.int64),
            'attention_mask': encoding['attention_mask'].astype(np.int64)
        }

    def predict(self, normalized_request: str) -> InferenceResult:
        start_time = time.perf_counter()

        inputs = self.preprocess(normalized_request)

        onnx_inputs = {
            self.input_names[0]: inputs['input_ids'],
            self.input_names[1]: inputs['attention_mask']
        }

        outputs = self.session.run(self.output_names, onnx_inputs)
        logits = outputs[0][0]

        probabilities = self._softmax(logits)
        predicted_class = int(np.argmax(probabilities))
        confidence = float(probabilities[predicted_class])

        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000

        prediction = "malicious" if predicted_class == 1 else "benign"

        return InferenceResult(
            prediction=prediction,
            confidence=confidence,
            latency_ms=latency_ms,
            logits=logits
        )

    def predict_batch(self, normalized_requests: list) -> list:
        batch_inputs = []
        for text in normalized_requests:
            inputs = self.preprocess(text)
            batch_inputs.append(inputs)

        input_ids = np.concatenate([inp['input_ids'] for inp in batch_inputs], axis=0)
        attention_mask = np.concatenate([inp['attention_mask'] for inp in batch_inputs], axis=0)

        start_time = time.perf_counter()

        onnx_inputs = {
            self.input_names[0]: input_ids,
            self.input_names[1]: attention_mask
        }

        outputs = self.session.run(self.output_names, onnx_inputs)
        logits_batch = outputs[0]

        end_time = time.perf_counter()
        total_latency_ms = (end_time - start_time) * 1000

        results = []
        for i, logits in enumerate(logits_batch):
            probabilities = self._softmax(logits)
            predicted_class = int(np.argmax(probabilities))
            confidence = float(probabilities[predicted_class])
            prediction = "malicious" if predicted_class == 1 else "benign"

            results.append(InferenceResult(
                prediction=prediction,
                confidence=confidence,
                latency_ms=total_latency_ms / len(normalized_requests),
                logits=logits
            ))

        return results

    def _softmax(self, logits: np.ndarray) -> np.ndarray:
        exp_logits = np.exp(logits - np.max(logits))
        return exp_logits / exp_logits.sum()

    def benchmark(self, test_requests: list, iterations: int = 100) -> Dict[str, float]:
        latencies = []

        for request in test_requests:
            for _ in range(iterations):
                result = self.predict(request)
                latencies.append(result.latency_ms)

        return {
            'mean_latency_ms': np.mean(latencies),
            'median_latency_ms': np.median(latencies),
            'p95_latency_ms': np.percentile(latencies, 95),
            'p99_latency_ms': np.percentile(latencies, 99),
            'min_latency_ms': np.min(latencies),
            'max_latency_ms': np.max(latencies),
            'total_requests': len(latencies)
        }


class CachedInferenceEngine:

    def __init__(self, inference_engine: ONNXInferenceEngine, cache_size: int = 10000):
        self.engine = inference_engine
        self.cache: Dict[str, InferenceResult] = {}
        self.cache_size = cache_size
        self.cache_hits = 0
        self.cache_misses = 0

    def predict(self, normalized_request: str) -> InferenceResult:
        cache_key = hash(normalized_request)

        if cache_key in self.cache:
            self.cache_hits += 1
            return self.cache[cache_key]

        self.cache_misses += 1
        result = self.engine.predict(normalized_request)

        if len(self.cache) >= self.cache_size:
            first_key = next(iter(self.cache))
            del self.cache[first_key]

        self.cache[cache_key] = result
        return result

    def get_cache_stats(self) -> Dict[str, float]:
        total = self.cache_hits + self.cache_misses
        hit_rate = self.cache_hits / total if total > 0 else 0
        return {
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'hit_rate': hit_rate,
            'cache_size': len(self.cache)
        }


if __name__ == "__main__":
    print("=== ONNX Inference Engine Test ===\n")

    model_path = "./models/waf_transformer/model.onnx"
    tokenizer_path = "./models/waf_transformer"

    if not os.path.exists(model_path):
        print(f"❌ Model not found at {model_path}")
        print("Please run waf_training.py first to train and export the model.")
        exit(1)

    print("Loading ONNX model...")
    engine = ONNXInferenceEngine(
        model_path=model_path,
        tokenizer_path=tokenizer_path,
        use_gpu=False
    )

    test_requests = [
        "GET /api/users/<ID>",
        "GET /api/users?id=1 OR 1=1--",
        "POST /api/search BODY:{\"query\":\"<script>alert(1)</script>\"}",
        "GET /api/file?path=../../../etc/passwd",
        "GET /dashboard?date=<TIMESTAMP>",
    ]

    print("\n=== Single Request Inference ===\n")
    for i, request in enumerate(test_requests, 1):
        result = engine.predict(request)
        print(f"Request {i}: {request[:60]}...")
        print(f"  Prediction: {result.prediction}")
        print(f"  Confidence: {result.confidence:.4f}")
        print(f"  Latency: {result.latency_ms:.2f}ms")
        print()

    print("=== Benchmark Results ===\n")
    benchmark_results = engine.benchmark(test_requests, iterations=50)
    for metric, value in benchmark_results.items():
        print(f"{metric}: {value:.2f}")

    print("\n=== Testing Cached Inference ===\n")
    cached_engine = CachedInferenceEngine(engine)

    for _ in range(3):
        for request in test_requests[:2]:
            cached_engine.predict(request)

    cache_stats = cached_engine.get_cache_stats()
    print("Cache Statistics:")
    for key, value in cache_stats.items():
        print(f"  {key}: {value}")
