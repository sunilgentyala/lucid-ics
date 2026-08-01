"""Feature attribution for detector output.

Two complementary views, both computed with well-established, dependency-light
techniques rather than a black-box "trust me" score:

* Global: permutation importance (Breiman 2001; sklearn.inspection) on the
  fitted RandomForestClassifier -- which features the model relies on overall.
* Local: per-alert z-score deviation from the fitted normal-traffic
  distribution -- which features are unusual about *this specific* window.
  This is what feeds the natural-language explanation for a single alert.
"""
from __future__ import annotations

import dataclasses

import pandas as pd
from sklearn.inspection import permutation_importance

from .detector import LucidDetector
from .features import FEATURE_COLUMNS


@dataclasses.dataclass
class LocalAttribution:
    top_features: list[tuple[str, float]]  # (feature_name, z_score), sorted by |z|


def global_importance(detector: LucidDetector, holdout_features: pd.DataFrame, n_repeats: int = 15) -> pd.Series:
    X = detector.scaler.transform(holdout_features[FEATURE_COLUMNS].to_numpy())
    y = holdout_features["attack_type"].to_numpy()
    result = permutation_importance(
        detector.clf, X, y, n_repeats=n_repeats, random_state=13, n_jobs=-1
    )
    return pd.Series(result.importances_mean, index=FEATURE_COLUMNS).sort_values(ascending=False)


def local_attribution(detector: LucidDetector, feature_row: pd.Series, top_k: int = 3) -> LocalAttribution:
    z = detector.z_scores(feature_row)
    ranked = z.reindex(z.abs().sort_values(ascending=False).index)
    top = [(name, float(val)) for name, val in ranked.head(top_k).items()]
    return LocalAttribution(top_features=top)
