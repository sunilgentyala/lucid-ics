"""Command-line entry point: `python -m lucid_ics.cli --duration 3600`."""
from __future__ import annotations

import argparse
import dataclasses
import json

from .pipeline import run_pipeline
from .simulator import SimulationConfig


def main() -> None:
    p = argparse.ArgumentParser(description="LUCID-ICS: explainable ML+LLM triage for ICS/SCADA IDS")
    p.add_argument("--duration", type=float, default=3600.0, help="simulated seconds of traffic")
    p.add_argument("--window", type=float, default=5.0, help="feature window size in seconds")
    p.add_argument("--show-alerts", type=int, default=5, help="number of sample alerts to print")
    args = p.parse_args()

    metrics, records, importance = run_pipeline(
        sim_config=SimulationConfig(duration_s=args.duration), window_s=args.window
    )

    print(json.dumps(dataclasses.asdict(metrics), indent=2))

    attacks = [r for r in records if r.attack_type != "normal"][: args.show_alerts]
    for rec in attacks:
        print("\n---")
        print(rec.narrative)
        for step in rec.playbook:
            print(f"  - {step}")


if __name__ == "__main__":
    main()
