"""End-to-end orchestration: simulate/ingest -> extract -> detect -> attribute
-> explain, plus the time-aware evaluation split used throughout the paper.
"""
from __future__ import annotations

import dataclasses
import time as _time

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from .attribution import global_importance, local_attribution
from .detector import LucidDetector
from .explain import LLMBackend, TriageRecord, explain_alert
from .features import extract_window_features
from .simulator import SimulationConfig, generate_dataset

ATTACK_FAMILIES = ["unauthorized_write", "replay", "sensor_spoofing", "recon_scan", "dos_flood"]


@dataclasses.dataclass
class EvalMetrics:
    binary_precision: float
    binary_recall: float
    binary_f1: float
    binary_roc_auc: float
    family_accuracy: float
    family_macro_f1: float
    mean_explanation_latency_ms: float
    n_train_windows: int
    n_test_windows: int
    # Per-attack-family recall on the family classifier (of windows truly
    # belonging to family X, the fraction correctly labeled X) -- reported
    # per trial so recall variance can be attributed to a specific family
    # rather than only inspected via one trial's confusion matrix.
    family_recall: dict[str, float] = dataclasses.field(default_factory=dict)


def time_split(features: pd.DataFrame, train_frac: float = 0.6):
    """Contiguous time-block split (not a random shuffle) so the detector is
    never trained on windows that temporally leak information about the
    test-period attacks -- the correct way to validate a time-series
    detector."""
    cut = int(len(features) * train_frac)
    return features.iloc[:cut].reset_index(drop=True), features.iloc[cut:].reset_index(drop=True)


def run_pipeline(
    sim_config: SimulationConfig | None = None,
    window_s: float = 5.0,
    train_frac: float = 0.6,
    backend: LLMBackend | None = None,
) -> tuple[EvalMetrics, list[TriageRecord], pd.DataFrame]:
    events = generate_dataset(sim_config)
    features = extract_window_features(events, window_s=window_s)
    train, test = time_split(features, train_frac)

    detector = LucidDetector().fit(train)
    result = detector.predict(test)

    y_true = test["is_attack"].to_numpy()
    y_pred = (result.predicted_family != "normal").astype(int)
    y_family_true = test["attack_type"].to_numpy()

    metrics = EvalMetrics(
        binary_precision=precision_score(y_true, y_pred, zero_division=0),
        binary_recall=recall_score(y_true, y_pred, zero_division=0),
        binary_f1=f1_score(y_true, y_pred, zero_division=0),
        binary_roc_auc=roc_auc_score(y_true, result.risk_score) if len(set(y_true)) > 1 else float("nan"),
        family_accuracy=accuracy_score(y_family_true, result.predicted_family),
        family_macro_f1=f1_score(y_family_true, result.predicted_family, average="macro", zero_division=0),
        mean_explanation_latency_ms=0.0,  # filled in below
        n_train_windows=len(train),
        n_test_windows=len(test),
        family_recall=dict(zip(
            ATTACK_FAMILIES,
            recall_score(y_family_true, result.predicted_family, labels=ATTACK_FAMILIES,
                         average=None, zero_division=0).tolist(),
        )),
    )

    records: list[TriageRecord] = []
    latencies = []
    for i in range(len(test)):
        row = result.features.iloc[i]
        attr = local_attribution(detector, row)
        t0 = _time.perf_counter()
        rec = explain_alert(
            window=int(row["window"]), t_start=float(row["t_start"]),
            attack_type=str(result.predicted_family[i]), risk_score=float(result.risk_score[i]),
            family_confidence=float(result.family_confidence[i]), attribution=attr, backend=backend,
        )
        latencies.append((_time.perf_counter() - t0) * 1000.0)
        records.append(rec)

    metrics.mean_explanation_latency_ms = float(np.mean(latencies)) if latencies else 0.0

    importance = global_importance(detector, test)
    importance_df = importance.rename("importance").reset_index().rename(columns={"index": "feature"})

    return metrics, records, importance_df
