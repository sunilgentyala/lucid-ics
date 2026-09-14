"""Runs the multi-trial evaluation reported in the paper and writes metrics,
figures, and qualitative sample alerts to `results/`.

Usage:
    python experiments/run_experiment.py --config experiments/configs/default.yaml
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import yaml
from sklearn.metrics import confusion_matrix, roc_curve

# Reviewer feedback (MILCOM 2026 WS14 camera-ready): figures were too small /
# low-font when printed at IEEE two-column width. Bump base font size and
# figure dimensions for every plot generated below.
plt.rcParams.update({"font.size": 13})

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lucid_ics.pipeline import ATTACK_FAMILIES, run_pipeline  # noqa: E402
from lucid_ics.simulator import SimulationConfig  # noqa: E402

FAMILIES = ["normal"] + ATTACK_FAMILIES


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def run_trials(cfg: dict):
    all_metrics = []
    last_records = None
    last_importance = None

    for trial in range(cfg["n_trials"]):
        seed = cfg["base_seed"] + trial
        sim_cfg = SimulationConfig(
            duration_s=cfg["duration_s"], poll_interval_s=cfg["poll_interval_s"],
            jitter_s=cfg["jitter_s"], setpoint=cfg["setpoint"], noise_std=cfg["noise_std"],
            attack_time_fraction=cfg["attack_time_fraction"], seed=seed,
        )
        metrics, records, importance = run_pipeline(
            sim_config=sim_cfg, window_s=cfg["window_s"], train_frac=cfg["train_frac"]
        )
        row = dataclasses.asdict(metrics)
        family_recall = row.pop("family_recall")
        for fam, val in family_recall.items():
            row[f"recall_{fam}"] = val
        row["seed"] = seed
        all_metrics.append(row)
        print(f"trial {trial+1}/{cfg['n_trials']} (seed={seed}): "
              f"F1={metrics.binary_f1:.3f} AUC={metrics.binary_roc_auc:.3f} "
              f"family_acc={metrics.family_accuracy:.3f}")

        if trial == cfg["n_trials"] - 1:
            last_records = records
            last_importance = importance

    return pd.DataFrame(all_metrics), last_records, last_importance


def rerun_last_trial_with_arrays(cfg: dict):
    """Re-runs the final trial and also returns the raw prediction arrays
    needed for the confusion matrix / ROC plots (pipeline.run_pipeline
    intentionally returns aggregate metrics + records, not raw arrays, to
    keep its public API small; this helper recomputes what the plots need)."""
    from lucid_ics.attribution import local_attribution
    from lucid_ics.detector import LucidDetector
    from lucid_ics.features import extract_window_features
    from lucid_ics.pipeline import time_split
    from lucid_ics.simulator import generate_dataset

    seed = cfg["base_seed"] + cfg["n_trials"] - 1
    sim_cfg = SimulationConfig(
        duration_s=cfg["duration_s"], poll_interval_s=cfg["poll_interval_s"],
        jitter_s=cfg["jitter_s"], setpoint=cfg["setpoint"], noise_std=cfg["noise_std"],
        attack_time_fraction=cfg["attack_time_fraction"], seed=seed,
    )
    events = generate_dataset(sim_cfg)
    feats = extract_window_features(events, window_s=cfg["window_s"])
    train, test = time_split(feats, cfg["train_frac"])
    detector = LucidDetector().fit(train)
    result = detector.predict(test)
    return test, result, detector


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(os.path.dirname(__file__), "configs", "default.yaml"))
    args = ap.parse_args()

    cfg = load_config(args.config)
    out_dir = os.path.normpath(os.path.join(os.path.dirname(args.config), "..", cfg["output_dir"]))
    fig_dir = os.path.join(out_dir, "figures")
    os.makedirs(fig_dir, exist_ok=True)

    metrics_df, records, importance = run_trials(cfg)
    metrics_df.to_csv(os.path.join(out_dir, "metrics_per_trial.csv"), index=False)

    summary = {
        col: {"mean": float(metrics_df[col].mean()), "std": float(metrics_df[col].std())}
        for col in ["binary_precision", "binary_recall", "binary_f1", "binary_roc_auc",
                    "family_accuracy", "family_macro_f1", "mean_explanation_latency_ms"]
    }
    summary["family_recall"] = {
        fam: {
            "mean": float(metrics_df[f"recall_{fam}"].mean()),
            "std": float(metrics_df[f"recall_{fam}"].std()),
            "min": float(metrics_df[f"recall_{fam}"].min()),
            "max": float(metrics_df[f"recall_{fam}"].max()),
        }
        for fam in ATTACK_FAMILIES
    }
    summary["n_trials"] = cfg["n_trials"]
    summary["duration_s_per_trial"] = cfg["duration_s"]
    with open(os.path.join(out_dir, "metrics_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print("\n== Summary (mean +/- std over", cfg["n_trials"], "trials) ==")
    for k, v in summary.items():
        if k == "family_recall":
            continue
        if isinstance(v, dict):
            print(f"  {k}: {v['mean']:.4f} +/- {v['std']:.4f}")
    print("\n== Per-family recall (attack-family classifier, mean +/- std, min-max) ==")
    for fam, v in summary["family_recall"].items():
        print(f"  {fam}: {v['mean']:.4f} +/- {v['std']:.4f}  (range {v['min']:.4f}-{v['max']:.4f})")

    importance.to_csv(os.path.join(out_dir, "feature_importance.csv"), index=False)

    # -- qualitative sample alerts from the final trial ---------------------
    # One representative alert per attack family (first occurrence in the
    # trial), rather than the first N records, so the released artifact
    # illustrates every narrative type instead of whichever family happens
    # to appear first in the window ordering.
    sample = []
    seen_families: set[str] = set()
    for r in records:
        if r.attack_type != "normal" and r.attack_type not in seen_families:
            sample.append(r)
            seen_families.add(r.attack_type)
        if len(seen_families) == len(ATTACK_FAMILIES):
            break
    with open(os.path.join(out_dir, "sample_alerts.md"), "w", encoding="utf-8") as f:
        f.write("# Sample LUCID-ICS triage alerts (final trial, seed="
                f"{cfg['base_seed'] + cfg['n_trials'] - 1})\n\n")
        for r in sample:
            f.write(f"## Window {r.window} (t={r.t_start:.0f}s) -- {r.attack_type}\n\n")
            f.write(f"- Risk score: {r.risk_score:.2f}, classifier confidence: {r.family_confidence:.2f}\n")
            if r.technique:
                f.write(f"- ATT&CK for ICS: {r.technique.attck_id} ({r.technique.attck_name})\n")
            f.write(f"\n**Narrative:** {r.narrative}\n\n**Response playbook:**\n")
            for step in r.playbook:
                f.write(f"- {step}\n")
            f.write("\n---\n\n")

    # -- plots from a fresh re-run that exposes raw arrays -----------------
    test, result, detector = rerun_last_trial_with_arrays(cfg)
    y_true_bin = test["is_attack"].to_numpy()
    y_pred_family = result.predicted_family
    y_true_family = test["attack_type"].to_numpy()

    # confusion matrix (attack family)
    cm = confusion_matrix(y_true_family, y_pred_family, labels=FAMILIES)
    fig, ax = plt.subplots(figsize=(8.4, 7.2))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(FAMILIES)), FAMILIES, rotation=45, ha="right", fontsize=13)
    ax.set_yticks(range(len(FAMILIES)), FAMILIES, fontsize=13)
    ax.set_xlabel("Predicted family", fontsize=15)
    ax.set_ylabel("True family", fontsize=15)
    ax.set_title("LUCID-ICS attack-family confusion matrix (held-out test windows)", fontsize=14)
    for i in range(len(FAMILIES)):
        for j in range(len(FAMILIES)):
            ax.text(j, i, cm[i, j], ha="center", va="center",
                     color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=13)
    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.ax.tick_params(labelsize=12)
    fig.tight_layout()
    fig.savefig(os.path.join(fig_dir, "confusion_matrix.png"), dpi=220)
    plt.close(fig)

    # ROC curve (binary attack vs normal, risk_score as decision function)
    fpr, tpr, _ = roc_curve(y_true_bin, result.risk_score)
    fig, ax = plt.subplots(figsize=(7.2, 6.2))
    ax.plot(fpr, tpr, lw=2.5, label="LUCID-ICS risk score")
    ax.plot([0, 1], [0, 1], "--", color="gray", lw=1.5, label="chance")
    ax.set_xlabel("False positive rate", fontsize=15)
    ax.set_ylabel("True positive rate", fontsize=15)
    ax.set_title("ROC -- binary attack detection", fontsize=15)
    ax.tick_params(labelsize=13)
    ax.legend(fontsize=13)
    fig.tight_layout()
    fig.savefig(os.path.join(fig_dir, "roc_curve.png"), dpi=220)
    plt.close(fig)

    # feature importance (global, permutation)
    fig, ax = plt.subplots(figsize=(8.6, 5.8))
    top = importance.head(10).iloc[::-1]
    ax.barh(top["feature"], top["importance"], color="#3b6fa0")
    ax.set_xlabel("Permutation importance (mean accuracy drop)", fontsize=15)
    ax.set_title("Global feature importance -- attack-family classifier", fontsize=15)
    ax.tick_params(labelsize=13)
    fig.tight_layout()
    fig.savefig(os.path.join(fig_dir, "feature_importance.png"), dpi=220)
    plt.close(fig)

    # risk score distribution by ground-truth class
    fig, ax = plt.subplots(figsize=(8.0, 5.8))
    ax.hist(result.risk_score[y_true_bin == 0], bins=30, alpha=0.6, label="normal", color="#4c9a6b")
    ax.hist(result.risk_score[y_true_bin == 1], bins=30, alpha=0.6, label="attack", color="#c0504d")
    ax.set_xlabel("LUCID-ICS risk score", fontsize=15)
    ax.set_ylabel("Window count", fontsize=15)
    ax.set_title("Risk-score separation between normal and attack windows", fontsize=15)
    ax.tick_params(labelsize=13)
    ax.legend(fontsize=13)
    fig.tight_layout()
    fig.savefig(os.path.join(fig_dir, "risk_score_distribution.png"), dpi=220)
    plt.close(fig)

    print(f"\nWrote metrics, figures, and sample alerts to {out_dir}")


if __name__ == "__main__":
    main()
