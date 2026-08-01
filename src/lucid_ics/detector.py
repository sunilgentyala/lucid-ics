"""Two-stage ML anomaly detector: unsupervised novelty scoring + supervised
attack-family classification, combined into a single triage risk score.

Design rationale (see paper Section IV-B): a purely unsupervised detector
(IsolationForest) is what a real deployment would run against traffic it has
never seen labeled, so it anchors the headline detection metrics. The
supervised RandomForestClassifier is trained on the labeled synthetic attack
families to demonstrate attack-family attribution, which the explanation
layer (explain.py) needs to generate a *specific* natural-language narrative
rather than a generic "anomaly detected."
"""
from __future__ import annotations

import dataclasses

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from .features import FEATURE_COLUMNS


@dataclasses.dataclass
class DetectionResult:
    features: pd.DataFrame        # original feature rows, index-aligned
    anomaly_score: np.ndarray     # higher = more anomalous, roughly in [0, 1]
    predicted_family: np.ndarray  # classifier's predicted attack_type label
    family_confidence: np.ndarray
    risk_score: np.ndarray        # combined triage score in [0, 1]


class LucidDetector:
    """Time-aware train/predict wrapper around the two underlying models."""

    def __init__(self, contamination: float = 0.15, n_estimators: int = 300, random_state: int = 13):
        self.scaler = StandardScaler()
        self.iso = IsolationForest(
            n_estimators=n_estimators, contamination=contamination, random_state=random_state
        )
        self.clf = RandomForestClassifier(
            n_estimators=n_estimators, max_depth=12, random_state=random_state, class_weight="balanced"
        )
        self._normal_mean = None
        self._normal_std = None
        self.classes_: list[str] = []

    def fit(self, train_features: pd.DataFrame) -> "LucidDetector":
        X = train_features[FEATURE_COLUMNS].to_numpy()
        Xs = self.scaler.fit_transform(X)
        self.iso.fit(Xs)
        self.clf.fit(Xs, train_features["attack_type"].to_numpy())
        self.classes_ = list(self.clf.classes_)

        normal_mask = train_features["attack_type"] == "normal"
        self._normal_mean = X[normal_mask].mean(axis=0)
        self._normal_std = X[normal_mask].std(axis=0) + 1e-6
        return self

    def predict(self, features: pd.DataFrame) -> DetectionResult:
        X = features[FEATURE_COLUMNS].to_numpy()
        Xs = self.scaler.transform(X)

        raw_scores = -self.iso.score_samples(Xs)  # higher = more anomalous
        anomaly_score = _minmax(raw_scores)

        proba = self.clf.predict_proba(Xs)
        pred_idx = proba.argmax(axis=1)
        predicted_family = np.array(self.classes_)[pred_idx]
        family_confidence = proba.max(axis=1)

        is_attack_pred = predicted_family != "normal"
        risk_score = anomaly_score * 0.5 + family_confidence * is_attack_pred * 0.5

        return DetectionResult(
            features=features.reset_index(drop=True),
            anomaly_score=anomaly_score,
            predicted_family=predicted_family,
            family_confidence=family_confidence,
            risk_score=risk_score,
        )

    def z_scores(self, feature_row: pd.Series) -> pd.Series:
        """Per-feature deviation (in std-devs) from the fitted normal-traffic
        distribution -- the statistical basis for local attribution in
        attribution.py."""
        x = feature_row[FEATURE_COLUMNS].to_numpy(dtype=float)
        z = (x - self._normal_mean) / self._normal_std
        return pd.Series(z, index=FEATURE_COLUMNS)


def _minmax(x: np.ndarray) -> np.ndarray:
    lo, hi = x.min(), x.max()
    if hi - lo < 1e-9:
        return np.zeros_like(x)
    return (x - lo) / (hi - lo)
