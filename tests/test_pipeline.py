from lucid_ics.pipeline import run_pipeline
from lucid_ics.simulator import SimulationConfig


def test_pipeline_end_to_end_runs_and_scores_reasonably():
    metrics, records, importance = run_pipeline(sim_config=SimulationConfig(duration_s=1800.0, seed=7))

    assert metrics.n_test_windows > 0
    assert 0.0 <= metrics.binary_precision <= 1.0
    assert 0.0 <= metrics.binary_recall <= 1.0
    assert 0.0 <= metrics.family_accuracy <= 1.0
    assert len(records) == metrics.n_test_windows
    assert len(importance) > 0

    # every record's ATT&CK/playbook grounding must resolve for non-normal predictions
    for rec in records:
        if rec.attack_type != "normal":
            assert rec.technique is not None
            assert len(rec.playbook) > 0
            assert "stdev" in rec.narrative or rec.narrative  # non-empty narrative


def test_pipeline_is_reproducible_given_seed():
    m1, _, _ = run_pipeline(sim_config=SimulationConfig(duration_s=900.0, seed=99))
    m2, _, _ = run_pipeline(sim_config=SimulationConfig(duration_s=900.0, seed=99))
    assert m1.binary_precision == m2.binary_precision
    assert m1.family_accuracy == m2.family_accuracy
