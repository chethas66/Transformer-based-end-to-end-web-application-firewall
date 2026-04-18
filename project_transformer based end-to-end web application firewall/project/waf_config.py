from pydantic_settings import BaseSettings
from typing import Optional


class WAFConfig(BaseSettings):
    supabase_url: str
    supabase_anon_key: str

    waf_mode: str = "shadow"
    waf_threshold: float = 0.95
    waf_max_latency_ms: int = 10

    redis_url: Optional[str] = None

    model_path: str = "./models/waf_model.onnx"
    tokenizer_path: str = "./models/tokenizer"

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "allow"


config = WAFConfig()
