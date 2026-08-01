"""Sliding-window feature extraction over raw ICS protocol event streams.

Turns a flat event log (one row per Modbus request/response) into fixed-width
statistical + protocol features per time window, which is the representation
the anomaly detector and classifier operate on. Windowing is deliberate: a
single packet is rarely enough context to distinguish, e.g., a legitimate
retry from a replay attack; the aggregate pattern within a window is.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

ACTUATOR_REGISTERS = {40003, 1}
LEGITIMATE_SOURCE = "HMI-1"

FEATURE_COLUMNS = [
    "n_events",
    "n_unique_src",
    "n_unique_function_codes",
    "write_ratio",
    "unauthorized_write_count",
    "register_address_entropy",
    "value_std",
    "value_max_delta",
    "response_time_mean",
    "response_time_std",
    "response_time_p95",
    "inter_arrival_mean",
    "inter_arrival_std",
    "duplicate_value_ratio",
    "request_rate",
]


def _entropy(counts: pd.Series) -> float:
    p = counts / counts.sum()
    return float(-(p * np.log2(p + 1e-12)).sum())


def extract_window_features(events: pd.DataFrame, window_s: float = 5.0) -> pd.DataFrame:
    """Aggregate raw events into `window_s`-second windows of ML-ready features.

    The dominant `attack_type` label within each window is carried through
    for supervised training/evaluation; a window is only labeled with an
    attack family if that family accounts for the majority of its events,
    which keeps window boundaries from producing ambiguous labels.
    """
    events = events.copy()
    events["window"] = (events["t"] // window_s).astype(int)
    events = events.sort_values("t")

    rows = []
    for win_id, g in events.groupby("window", sort=True):
        g = g.sort_values("t")
        n = len(g)
        iat = g["t"].diff().dropna()
        writes = g["function_code"].isin([5, 6, 16])
        unauthorized = writes & (g["register"].isin(ACTUATOR_REGISTERS)) & (g["src"] != LEGITIMATE_SOURCE)
        dup_ratio = 1.0 - (g["value"].round(3).nunique() / max(n, 1))

        feats = {
            "window": win_id,
            "t_start": g["t"].iloc[0],
            "n_events": n,
            "n_unique_src": g["src"].nunique(),
            "n_unique_function_codes": g["function_code"].nunique(),
            "write_ratio": float(writes.mean()),
            "unauthorized_write_count": int(unauthorized.sum()),
            "register_address_entropy": _entropy(g["register"].value_counts()),
            "value_std": float(g["value"].std(ddof=0)) if n > 1 else 0.0,
            "value_max_delta": float(g["value"].diff().abs().max()) if n > 1 else 0.0,
            "response_time_mean": float(g["response_time_ms"].mean()),
            "response_time_std": float(g["response_time_ms"].std(ddof=0)) if n > 1 else 0.0,
            "response_time_p95": float(g["response_time_ms"].quantile(0.95)),
            "inter_arrival_mean": float(iat.mean()) if len(iat) else window_s,
            "inter_arrival_std": float(iat.std(ddof=0)) if len(iat) > 1 else 0.0,
            "duplicate_value_ratio": float(dup_ratio),
            "request_rate": n / window_s,
        }
        label_counts = g["attack_type"].value_counts()
        feats["attack_type"] = label_counts.idxmax()
        feats["is_attack"] = int(feats["attack_type"] != "normal")
        rows.append(feats)

    out = pd.DataFrame(rows).fillna(0.0)
    return out.sort_values("window").reset_index(drop=True)
