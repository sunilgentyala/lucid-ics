from lucid_ics.simulator import SimulationConfig, generate_dataset


def test_generates_events_with_expected_schema():
    df = generate_dataset(SimulationConfig(duration_s=120.0, seed=1))
    assert len(df) > 0
    for col in ["t", "src", "dst", "function_code", "register", "value",
                "response_time_ms", "attack_type", "is_attack"]:
        assert col in df.columns


def test_contains_multiple_attack_families():
    df = generate_dataset(SimulationConfig(duration_s=1800.0, seed=2))
    families = set(df.loc[df["is_attack"] == 1, "attack_type"].unique())
    assert "normal" not in families
    assert len(families) >= 3


def test_normal_traffic_dominates():
    df = generate_dataset(SimulationConfig(duration_s=1800.0, seed=3))
    normal_frac = (df["attack_type"] == "normal").mean()
    assert 0.5 < normal_frac < 0.99


def test_deterministic_with_seed():
    a = generate_dataset(SimulationConfig(duration_s=200.0, seed=42))
    b = generate_dataset(SimulationConfig(duration_s=200.0, seed=42))
    assert a["value"].tolist() == b["value"].tolist()
