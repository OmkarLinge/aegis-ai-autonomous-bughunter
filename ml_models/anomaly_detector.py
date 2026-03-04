"""
Aegis AI — Anomaly Detection Agent
Uses Isolation Forest to detect unusual server behavior patterns.
This helps identify blind vulnerabilities like blind SQL injection or
command injection through timing/response anomalies.
"""
import numpy as np
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))
from utils.logger import get_logger

logger = get_logger(__name__, "ANOMALY")

MODEL_DIR = Path(__file__).parent / "trained"
MODEL_DIR.mkdir(exist_ok=True)


@dataclass
class AnomalyResult:
    """Result of anomaly detection analysis."""
    is_anomalous: bool
    anomaly_score: float         # Higher = more anomalous (0 to 1)
    isolation_score: float       # Raw Isolation Forest score
    contributing_factors: List[str]
    interpretation: str


class ResponseProfiler:
    """
    Profiles server responses to establish normal behavior baseline.
    Collects statistical features to train the Isolation Forest.
    """

    def __init__(self):
        self.response_history: List[Dict] = []

    def record(
        self,
        response_time_ms: float,
        response_size: int,
        status_code: int,
        header_count: int,
    ):
        """Record a response measurement for profiling."""
        self.response_history.append({
            "response_time_ms": response_time_ms,
            "response_size": response_size,
            "status_code": status_code,
            "header_count": header_count,
        })

    def get_statistics(self) -> Dict[str, float]:
        """Calculate baseline statistics from recorded responses."""
        if not self.response_history:
            return {}

        times = [r["response_time_ms"] for r in self.response_history]
        sizes = [r["response_size"] for r in self.response_history]

        return {
            "mean_time": np.mean(times),
            "std_time": np.std(times),
            "mean_size": np.mean(sizes),
            "std_size": np.std(sizes),
            "sample_count": len(self.response_history),
        }

    def to_feature_matrix(self) -> np.ndarray:
        """Convert response history to feature matrix for training."""
        rows = []
        for r in self.response_history:
            rows.append([
                r["response_time_ms"],
                r["response_size"],
                1 if 200 <= r["status_code"] < 300 else 0,
                r["header_count"],
            ])
        return np.array(rows, dtype=float)


class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector for HTTP response patterns.

    Isolation Forest works by randomly partitioning feature space.
    Anomalous points (those that differ from normal patterns) require
    fewer partitions to isolate, resulting in lower anomaly scores.

    Usage:
    1. Initialize with baseline responses (normal behavior)
    2. Call detect() on each test response
    3. Results indicate if the response is anomalous
    """

    MODEL_PATH = MODEL_DIR / "anomaly_detector.joblib"
    SCALER_PATH = MODEL_DIR / "anomaly_scaler.joblib"

    def __init__(self, contamination: float = 0.1):
        """
        Initialize anomaly detector.

        Args:
            contamination: Expected fraction of anomalies in baseline data (0.0-0.5)
        """
        self.contamination = contamination
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.profiler = ResponseProfiler()
        self.is_fitted = False
        self.baseline_stats: Dict[str, float] = {}

    def add_baseline_response(
        self,
        response_time_ms: float,
        response_size: int,
        status_code: int,
        header_count: int,
    ):
        """Add a baseline (normal) response to the profiler."""
        self.profiler.record(response_time_ms, response_size, status_code, header_count)

    def fit(self):
        """
        Train the Isolation Forest on recorded baseline responses.
        Should be called after collecting sufficient baseline samples.
        """
        if not SKLEARN_AVAILABLE:
            logger.warning("scikit-learn not available — using statistical anomaly detection")
            self.baseline_stats = self.profiler.get_statistics()
            self.is_fitted = True
            return

        if len(self.profiler.response_history) < 5:
            logger.debug("Not enough baseline samples, using statistical detection")
            self.baseline_stats = self.profiler.get_statistics()
            self.is_fitted = True
            return

        try:
            X = self.profiler.to_feature_matrix()
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)

            self.model = IsolationForest(
                contamination=self.contamination,
                n_estimators=100,
                random_state=42,
                n_jobs=-1,
            )
            self.model.fit(X_scaled)
            self.baseline_stats = self.profiler.get_statistics()
            self.is_fitted = True

            logger.info(
                f"Anomaly detector fitted on {len(X)} baseline responses | "
                f"mean_time={self.baseline_stats.get('mean_time', 0):.0f}ms"
            )

        except Exception as e:
            logger.warning(f"Isolation Forest training failed: {e}")
            self.baseline_stats = self.profiler.get_statistics()
            self.is_fitted = True

    def detect(
        self,
        response_time_ms: float,
        response_size: int,
        status_code: int,
        header_count: int,
    ) -> AnomalyResult:
        """
        Detect if a response is anomalous compared to baseline.

        Args:
            response_time_ms: Response time in milliseconds
            response_size: Response body size in bytes
            status_code: HTTP status code
            header_count: Number of response headers

        Returns:
            AnomalyResult with anomaly score and interpretation
        """
        if not self.is_fitted:
            self.fit()

        features = np.array([[
            response_time_ms, response_size,
            1 if 200 <= status_code < 300 else 0,
            header_count,
        ]], dtype=float)

        contributing_factors = []

        # Statistical checks (always available)
        stats = self.baseline_stats
        if stats:
            mean_time = stats.get("mean_time", 0)
            std_time = stats.get("std_time", 0) or 1
            mean_size = stats.get("mean_size", 0)
            std_size = stats.get("std_size", 0) or 1

            time_z = abs(response_time_ms - mean_time) / std_time
            size_z = abs(response_size - mean_size) / std_size

            if time_z > 3:
                contributing_factors.append(
                    f"Response time {response_time_ms:.0f}ms is {time_z:.1f}σ from baseline"
                )
            if size_z > 3:
                contributing_factors.append(
                    f"Response size {response_size} bytes is {size_z:.1f}σ from baseline"
                )
            if status_code >= 500:
                contributing_factors.append(f"Server error status code: {status_code}")

        # ML-based detection
        isolation_score = 0.0
        if self.model is not None and self.scaler is not None:
            try:
                X_scaled = self.scaler.transform(features)
                # score_samples returns negative values; more negative = more anomalous
                raw_score = self.model.score_samples(X_scaled)[0]
                # Convert to 0-1 scale where 1 = most anomalous
                isolation_score = max(0.0, min(1.0, -raw_score))
                prediction = self.model.predict(X_scaled)[0]
                is_anomalous_ml = prediction == -1  # -1 = anomaly in sklearn
            except Exception:
                is_anomalous_ml = len(contributing_factors) > 0
        else:
            # Pure statistical fallback
            is_anomalous_ml = len(contributing_factors) > 0
            isolation_score = 0.8 if is_anomalous_ml else 0.1

        # Combine signals
        anomaly_score = isolation_score
        if len(contributing_factors) > 0:
            anomaly_score = max(anomaly_score, 0.6)

        is_anomalous = anomaly_score > 0.5 or len(contributing_factors) > 0

        # Generate human-readable interpretation
        if anomaly_score > 0.8:
            interpretation = (
                "High anomaly detected — server behavior significantly deviates from baseline. "
                "Possible blind injection or unusual server-side processing."
            )
        elif anomaly_score > 0.5:
            interpretation = (
                "Moderate anomaly detected — response pattern differs from baseline. "
                "Manual review recommended."
            )
        else:
            interpretation = "Response appears normal relative to established baseline."

        return AnomalyResult(
            is_anomalous=is_anomalous,
            anomaly_score=round(anomaly_score, 3),
            isolation_score=round(isolation_score, 3),
            contributing_factors=contributing_factors,
            interpretation=interpretation,
        )

    def detect_time_delay(
        self,
        baseline_time_ms: float,
        test_time_ms: float,
        threshold_multiplier: float = 3.0,
    ) -> AnomalyResult:
        """
        Specifically detect time-delay based blind injection.

        Used for detecting blind SQL injection, sleep-based payloads, etc.
        """
        ratio = test_time_ms / max(baseline_time_ms, 1)
        delta = test_time_ms - baseline_time_ms

        factors = []
        if ratio >= threshold_multiplier:
            factors.append(
                f"Response time {test_time_ms:.0f}ms is {ratio:.1f}x baseline "
                f"({baseline_time_ms:.0f}ms) — possible time-based injection"
            )

        is_anomalous = ratio >= threshold_multiplier
        score = min(1.0, (ratio - 1) / 10)

        if is_anomalous:
            interp = (
                f"Time delay anomaly detected: {test_time_ms:.0f}ms vs "
                f"baseline {baseline_time_ms:.0f}ms. "
                "Possible blind SQL injection or command injection with sleep payload."
            )
        else:
            interp = f"Response time normal: {test_time_ms:.0f}ms (ratio: {ratio:.2f}x)"

        return AnomalyResult(
            is_anomalous=is_anomalous,
            anomaly_score=round(score, 3),
            isolation_score=round(score, 3),
            contributing_factors=factors,
            interpretation=interp,
        )
