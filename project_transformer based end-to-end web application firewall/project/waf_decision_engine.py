from dataclasses import dataclass
from typing import Optional, Dict, Any
from enum import Enum
import time


class ThreatLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(Enum):
    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


@dataclass
class DecisionResult:
    action: ActionType
    threat_level: ThreatLevel
    final_score: float
    fast_path_blocked: bool
    fast_path_rule: Optional[str]
    transformer_prediction: Optional[str]
    transformer_confidence: Optional[float]
    reasoning: str
    total_latency_ms: float
    metadata: Dict[str, Any]


class WAFDecisionEngine:

    def __init__(
        self,
        mode: str = "shadow",
        block_threshold: float = 0.95,
        flag_threshold: float = 0.75,
        fast_path_weight: float = 1.0,
        transformer_weight: float = 0.9,
        max_latency_ms: float = 10.0
    ):
        self.mode = mode
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold
        self.fast_path_weight = fast_path_weight
        self.transformer_weight = transformer_weight
        self.max_latency_ms = max_latency_ms

        if mode not in ["shadow", "active", "learning"]:
            raise ValueError("Mode must be 'shadow', 'active', or 'learning'")

    def decide(
        self,
        fast_path_blocked: bool,
        fast_path_rule: Optional[str],
        fast_path_confidence: float,
        transformer_prediction: Optional[str],
        transformer_confidence: Optional[float],
        transformer_latency_ms: float,
        total_latency_ms: float
    ) -> DecisionResult:

        if fast_path_blocked:
            final_score = fast_path_confidence * self.fast_path_weight
            threat_level = self._calculate_threat_level(final_score)

            reasoning = f"Blocked by fast-path filter: {fast_path_rule}"

            if self.mode == "shadow":
                action = ActionType.FLAG
                reasoning += " (Shadow mode: flagged instead of blocked)"
            else:
                action = ActionType.BLOCK

            return DecisionResult(
                action=action,
                threat_level=threat_level,
                final_score=final_score,
                fast_path_blocked=True,
                fast_path_rule=fast_path_rule,
                transformer_prediction=transformer_prediction,
                transformer_confidence=transformer_confidence,
                reasoning=reasoning,
                total_latency_ms=total_latency_ms,
                metadata={
                    "fast_path_triggered": True,
                    "transformer_analyzed": False,
                    "mode": self.mode
                }
            )

        if transformer_prediction is None or transformer_confidence is None:
            return DecisionResult(
                action=ActionType.ALLOW,
                threat_level=ThreatLevel.SAFE,
                final_score=0.0,
                fast_path_blocked=False,
                fast_path_rule=None,
                transformer_prediction=None,
                transformer_confidence=None,
                reasoning="No analysis performed",
                total_latency_ms=total_latency_ms,
                metadata={
                    "fast_path_triggered": False,
                    "transformer_analyzed": False,
                    "mode": self.mode
                }
            )

        if transformer_prediction == "malicious":
            final_score = transformer_confidence * self.transformer_weight
        else:
            final_score = (1.0 - transformer_confidence) * self.transformer_weight

        threat_level = self._calculate_threat_level(final_score)

        if final_score >= self.block_threshold:
            if self.mode == "shadow":
                action = ActionType.FLAG
                reasoning = f"Transformer detected threat (confidence: {transformer_confidence:.2f}) - Shadow mode: flagged"
            elif self.mode == "learning":
                action = ActionType.FLAG
                reasoning = f"Transformer detected threat (confidence: {transformer_confidence:.2f}) - Learning mode: flagged"
            else:
                action = ActionType.BLOCK
                reasoning = f"Transformer detected threat (confidence: {transformer_confidence:.2f})"

        elif final_score >= self.flag_threshold:
            action = ActionType.FLAG
            reasoning = f"Suspicious activity detected (confidence: {transformer_confidence:.2f})"

        else:
            action = ActionType.ALLOW
            reasoning = f"Request appears safe (confidence: {1.0 - transformer_confidence:.2f})"

        if transformer_latency_ms > self.max_latency_ms:
            reasoning += f" [WARNING: Inference latency {transformer_latency_ms:.2f}ms exceeded target {self.max_latency_ms}ms]"

        return DecisionResult(
            action=action,
            threat_level=threat_level,
            final_score=final_score,
            fast_path_blocked=False,
            fast_path_rule=None,
            transformer_prediction=transformer_prediction,
            transformer_confidence=transformer_confidence,
            reasoning=reasoning,
            total_latency_ms=total_latency_ms,
            metadata={
                "fast_path_triggered": False,
                "transformer_analyzed": True,
                "transformer_latency_ms": transformer_latency_ms,
                "latency_within_target": transformer_latency_ms <= self.max_latency_ms,
                "mode": self.mode
            }
        )

    def _calculate_threat_level(self, score: float) -> ThreatLevel:
        if score >= 0.95:
            return ThreatLevel.CRITICAL
        elif score >= 0.85:
            return ThreatLevel.HIGH
        elif score >= 0.70:
            return ThreatLevel.MEDIUM
        elif score >= 0.50:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.SAFE

    def update_thresholds(self, block_threshold: float, flag_threshold: float):
        if not (0 <= flag_threshold <= block_threshold <= 1.0):
            raise ValueError("Thresholds must satisfy: 0 <= flag_threshold <= block_threshold <= 1.0")

        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold

    def switch_mode(self, new_mode: str):
        if new_mode not in ["shadow", "active", "learning"]:
            raise ValueError("Mode must be 'shadow', 'active', or 'learning'")

        self.mode = new_mode

    def get_config(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "block_threshold": self.block_threshold,
            "flag_threshold": self.flag_threshold,
            "fast_path_weight": self.fast_path_weight,
            "transformer_weight": self.transformer_weight,
            "max_latency_ms": self.max_latency_ms
        }


if __name__ == "__main__":
    print("=== WAF Decision Engine Test ===\n")

    test_scenarios = [
        {
            "name": "Fast-path SQLi Detection",
            "fast_path_blocked": True,
            "fast_path_rule": "SQLi:SQL_OR_TAUTOLOGY",
            "fast_path_confidence": 1.0,
            "transformer_prediction": None,
            "transformer_confidence": None,
            "transformer_latency_ms": 0.0,
            "total_latency_ms": 0.5
        },
        {
            "name": "High-confidence Malicious (Transformer)",
            "fast_path_blocked": False,
            "fast_path_rule": None,
            "fast_path_confidence": 0.0,
            "transformer_prediction": "malicious",
            "transformer_confidence": 0.98,
            "transformer_latency_ms": 8.5,
            "total_latency_ms": 9.0
        },
        {
            "name": "Medium-confidence Suspicious",
            "fast_path_blocked": False,
            "fast_path_rule": None,
            "fast_path_confidence": 0.0,
            "transformer_prediction": "malicious",
            "transformer_confidence": 0.78,
            "transformer_latency_ms": 7.2,
            "total_latency_ms": 7.5
        },
        {
            "name": "Benign Request",
            "fast_path_blocked": False,
            "fast_path_rule": None,
            "fast_path_confidence": 0.0,
            "transformer_prediction": "benign",
            "transformer_confidence": 0.95,
            "transformer_latency_ms": 6.8,
            "total_latency_ms": 7.0
        },
        {
            "name": "Slow Inference (Latency Warning)",
            "fast_path_blocked": False,
            "fast_path_rule": None,
            "fast_path_confidence": 0.0,
            "transformer_prediction": "malicious",
            "transformer_confidence": 0.85,
            "transformer_latency_ms": 15.3,
            "total_latency_ms": 16.0
        }
    ]

    for mode in ["shadow", "active"]:
        print(f"\n{'='*60}")
        print(f"Mode: {mode.upper()}")
        print(f"{'='*60}\n")

        engine = WAFDecisionEngine(
            mode=mode,
            block_threshold=0.95,
            flag_threshold=0.75
        )

        for scenario in test_scenarios:
            result = engine.decide(**{k: v for k, v in scenario.items() if k != 'name'})

            print(f"Scenario: {scenario['name']}")
            print(f"  Action: {result.action.value}")
            print(f"  Threat Level: {result.threat_level.value}")
            print(f"  Final Score: {result.final_score:.3f}")
            print(f"  Reasoning: {result.reasoning}")
            print(f"  Latency: {result.total_latency_ms:.2f}ms")
            print()
