from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, Optional, Any
import time
import os
from datetime import datetime

from waf_normalizer import HTTPRequestNormalizer
from waf_fast_path import FastPathFilter
from waf_inference import ONNXInferenceEngine, CachedInferenceEngine
from waf_decision_engine import WAFDecisionEngine, ActionType
from waf_config import config

app = FastAPI(
    title="Transformer-based WAF API",
    description="High-performance Web Application Firewall with ML-powered threat detection",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    method: str = Field(..., description="HTTP method (GET, POST, etc.)")
    path: str = Field(..., description="Request path")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    body: str = Field(default="", description="Request body")
    source_ip: str = Field(..., description="Client IP address")


class AnalyzeResponse(BaseModel):
    action: str
    threat_level: str
    confidence: float
    fast_path_blocked: bool
    fast_path_rule: Optional[str]
    transformer_prediction: Optional[str]
    transformer_confidence: Optional[float]
    reasoning: str
    latency_ms: float
    normalized_request: str
    metadata: Dict[str, Any]


class FeedbackRequest(BaseModel):
    request_id: str
    corrected_label: str
    notes: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    mode: str
    version: str


class WAFState:
    def __init__(self):
        self.normalizer: Optional[HTTPRequestNormalizer] = None
        self.fast_path_filter: Optional[FastPathFilter] = None
        self.inference_engine: Optional[ONNXInferenceEngine] = None
        self.cached_engine: Optional[CachedInferenceEngine] = None
        self.decision_engine: Optional[WAFDecisionEngine] = None
        self.supabase_client: Optional[Any] = None
        self.model_loaded = False

    def initialize(self):
        try:
            from supabase import create_client

            self.supabase_client = create_client(
                config.supabase_url,
                config.supabase_anon_key
            )
            print("✅ Supabase client initialized")
        except Exception as e:
            print(f"⚠️  Supabase initialization failed: {e}")

        self.normalizer = HTTPRequestNormalizer()
        print("✅ Normalizer initialized")

        self.fast_path_filter = FastPathFilter()
        print("✅ Fast-path filter initialized")

        self.decision_engine = WAFDecisionEngine(
            mode=config.waf_mode,
            block_threshold=config.waf_threshold,
            flag_threshold=0.75,
            max_latency_ms=config.waf_max_latency_ms
        )
        print(f"✅ Decision engine initialized (mode: {config.waf_mode})")

        if os.path.exists(config.model_path) and os.path.exists(config.tokenizer_path):
            try:
                self.inference_engine = ONNXInferenceEngine(
                    model_path=config.model_path,
                    tokenizer_path=config.tokenizer_path,
                    use_gpu=False
                )
                self.cached_engine = CachedInferenceEngine(self.inference_engine)
                self.model_loaded = True
                print("✅ ONNX inference engine loaded")
            except Exception as e:
                print(f"⚠️  Model loading failed: {e}")
                self.model_loaded = False
        else:
            print("⚠️  Model files not found. Run waf_training.py to train the model.")
            self.model_loaded = False


waf_state = WAFState()


@app.on_event("startup")
async def startup_event():
    print("🚀 Initializing WAF components...")
    waf_state.initialize()
    print("✅ WAF API ready")


async def log_to_supabase(
    request_data: AnalyzeRequest,
    normalized_request: str,
    decision_result: Any,
    prediction: Optional[str],
    confidence: Optional[float],
    latency_ms: float
):
    if waf_state.supabase_client is None:
        return

    try:
        waf_state.supabase_client.table('waf_requests').insert({
            "timestamp": datetime.utcnow().isoformat(),
            "method": request_data.method,
            "path": request_data.path,
            "headers": request_data.headers,
            "body": request_data.body,
            "source_ip": request_data.source_ip,
            "normalized_request": normalized_request,
            "fast_path_blocked": decision_result.fast_path_blocked,
            "fast_path_rule": decision_result.fast_path_rule,
            "transformer_score": confidence,
            "prediction": prediction,
            "action_taken": decision_result.action.value,
            "latency_ms": latency_ms
        }).execute()
    except Exception as e:
        print(f"Failed to log to Supabase: {e}")


@app.post("/api/waf/analyze", response_model=AnalyzeResponse)
async def analyze_request(
    request: AnalyzeRequest,
    background_tasks: BackgroundTasks
):
    start_time = time.perf_counter()

    if waf_state.normalizer is None:
        raise HTTPException(status_code=503, detail="WAF not initialized")

    normalized_request, metadata = waf_state.normalizer.normalize_http_request(
        method=request.method,
        path=request.path,
        headers=request.headers,
        body=request.body
    )

    fast_path_result = waf_state.fast_path_filter.check(normalized_request)
    header_result = waf_state.fast_path_filter.check_headers(request.headers)

    if header_result.blocked:
        fast_path_result = header_result

    transformer_prediction = None
    transformer_confidence = None
    transformer_latency_ms = 0.0

    if not fast_path_result.blocked and waf_state.model_loaded:
        inference_result = waf_state.cached_engine.predict(normalized_request)
        transformer_prediction = inference_result.prediction
        transformer_confidence = inference_result.confidence
        transformer_latency_ms = inference_result.latency_ms

    total_latency_ms = (time.perf_counter() - start_time) * 1000

    decision_result = waf_state.decision_engine.decide(
        fast_path_blocked=fast_path_result.blocked,
        fast_path_rule=fast_path_result.rule_name,
        fast_path_confidence=fast_path_result.confidence,
        transformer_prediction=transformer_prediction,
        transformer_confidence=transformer_confidence,
        transformer_latency_ms=transformer_latency_ms,
        total_latency_ms=total_latency_ms
    )

    background_tasks.add_task(
        log_to_supabase,
        request,
        normalized_request,
        decision_result,
        transformer_prediction,
        transformer_confidence,
        total_latency_ms
    )

    return AnalyzeResponse(
        action=decision_result.action.value,
        threat_level=decision_result.threat_level.value,
        confidence=decision_result.final_score,
        fast_path_blocked=decision_result.fast_path_blocked,
        fast_path_rule=decision_result.fast_path_rule,
        transformer_prediction=transformer_prediction,
        transformer_confidence=transformer_confidence,
        reasoning=decision_result.reasoning,
        latency_ms=total_latency_ms,
        normalized_request=normalized_request,
        metadata=decision_result.metadata
    )


@app.post("/api/waf/feedback")
async def submit_feedback(feedback: FeedbackRequest):
    if waf_state.supabase_client is None:
        raise HTTPException(status_code=503, detail="Supabase not configured")

    try:
        request_record = waf_state.supabase_client.table('waf_requests') \
            .select('*') \
            .eq('id', feedback.request_id) \
            .maybeSingle() \
            .execute()

        if not request_record.data:
            raise HTTPException(status_code=404, detail="Request not found")

        original_prediction = request_record.data.get('prediction', 'unknown')

        feedback_type = 'false_positive' if original_prediction == 'malicious' and feedback.corrected_label == 'benign' else 'false_negative'

        waf_state.supabase_client.table('waf_feedback').insert({
            "request_id": feedback.request_id,
            "original_prediction": original_prediction,
            "corrected_label": feedback.corrected_label,
            "feedback_type": feedback_type,
            "notes": feedback.notes
        }).execute()

        return {"status": "success", "message": "Feedback recorded"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to submit feedback: {str(e)}")


@app.get("/api/waf/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="healthy",
        model_loaded=waf_state.model_loaded,
        mode=config.waf_mode,
        version="1.0.0"
    )


@app.get("/api/waf/stats")
async def get_statistics():
    if waf_state.supabase_client is None:
        raise HTTPException(status_code=503, detail="Supabase not configured")

    try:
        requests_stats = waf_state.supabase_client.rpc('get_waf_stats').execute()

        cache_stats = {}
        if waf_state.cached_engine:
            cache_stats = waf_state.cached_engine.get_cache_stats()

        return {
            "requests": requests_stats.data if requests_stats.data else {},
            "cache": cache_stats,
            "config": waf_state.decision_engine.get_config()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")


@app.post("/api/waf/config")
async def update_config(
    mode: Optional[str] = None,
    block_threshold: Optional[float] = None,
    flag_threshold: Optional[float] = None
):
    if waf_state.decision_engine is None:
        raise HTTPException(status_code=503, detail="Decision engine not initialized")

    try:
        if mode:
            waf_state.decision_engine.switch_mode(mode)

        if block_threshold is not None and flag_threshold is not None:
            waf_state.decision_engine.update_thresholds(block_threshold, flag_threshold)

        return {
            "status": "success",
            "config": waf_state.decision_engine.get_config()
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
