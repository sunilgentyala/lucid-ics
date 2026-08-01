from lucid_ics.features import FEATURE_COLUMNS, extract_window_features
from lucid_ics.simulator import SimulationConfig, generate_dataset


def test_feature_extraction_shape():
    events = generate_dataset(SimulationConfig(duration_s=600.0, seed=5))
    feats = extract_window_features(events, window_s=5.0)
    assert len(feats) > 0
    for col in FEATURE_COLUMNS + ["attack_type", "is_attack", "window", "t_start"]:
        assert col in feats.columns
    assert not feats[FEATURE_COLUMNS].isna().any().any()


def test_window_labels_are_valid_attack_types():
    events = generate_dataset(SimulationConfig(duration_s=600.0, seed=6))
    feats = extract_window_features(events, window_s=5.0)
    valid = {"normal", "unauthorized_write", "replay", "sensor_spoofing", "recon_scan", "dos_flood"}
    assert set(feats["attack_type"].unique()) <= valid
