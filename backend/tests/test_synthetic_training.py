import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.models.training import (
    SyntheticGenerationConfig,
    count_attack_categories,
    build_stratified_training_sample,
    generate_synthetic_dataset,
    normalize_cols,
)


def _make_fake_clean_csv(path: Path, n_normal: int = 300, n_per_attack: int = 120, seed: int = 42) -> None:
    """Genera un CSV pequeño con la misma forma que un *_full_clean.csv
    real del TFM1: attack_cat/label + un puñado de columnas numéricas."""
    rng = np.random.RandomState(seed)
    rows = []

    def _row(attack_cat, label):
        return {
            "attack_cat": attack_cat,
            "label": label,
            "flow_duration": rng.exponential(1000),
            "total_fwd_packets": rng.poisson(10),
            "total_backward_packets": rng.poisson(8),
        }

    for _ in range(n_normal):
        rows.append(_row("Normal", 0))
    for cat in ("DoS", "PortScan"):
        for _ in range(n_per_attack):
            rows.append(_row(cat, 1))

    df = pd.DataFrame(rows).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    df.to_csv(path, index=False)


@pytest.fixture
def fake_real_csv(tmp_path):
    p = tmp_path / "FAKE_full_clean.csv"
    _make_fake_clean_csv(p)
    return p


def test_normalize_cols_matches_ingestion_convention():
    assert normalize_cols(["Destination Port", "Flow-Duration", "Foo/Bar"]) == [
        "destination_port", "flow_duration", "foo_bar",
    ]


def test_count_attack_categories(fake_real_csv):
    counts = count_attack_categories(fake_real_csv, chunk_size=1000)
    assert counts["Normal"] == 300
    assert counts["DoS"] == 120
    assert counts["PortScan"] == 120


def test_build_stratified_training_sample_respects_quotas(fake_real_csv):
    config = SyntheticGenerationConfig(
        random_state=42, chunk_size=1000,
        train_total_n=200, train_normal_max=100, train_attack_min_each=40,
    )
    df_train = build_stratified_training_sample(fake_real_csv, ["DoS", "PortScan"], config)

    counts = df_train["attack_cat"].value_counts().to_dict()
    assert counts.get("DoS", 0) >= 40
    assert counts.get("PortScan", 0) >= 40
    assert counts.get("Normal", 0) <= 100
    assert len(df_train) <= config.train_total_n


def test_build_stratified_sample_fails_without_attack_cat(tmp_path):
    p = tmp_path / "no_taxonomy.csv"
    pd.DataFrame({"foo": [1, 2, 3]}).to_csv(p, index=False)
    with pytest.raises(ValueError):
        build_stratified_training_sample(p, ["DoS"], SyntheticGenerationConfig())


def test_generate_synthetic_dataset_end_to_end(fake_real_csv, tmp_path):
    """Ejercita el pipeline completo, incluido el ajuste real de SDV,
    con cuotas deliberadamente pequeñas para que el test sea rápido."""
    out_csv = tmp_path / "synthetic_FAKE.csv"
    config = SyntheticGenerationConfig(
        random_state=42, chunk_size=1000,
        train_total_n=150, train_normal_max=80, train_attack_min_each=30,
        normal_n=20, attack_n_each=10,
    )

    summary = generate_synthetic_dataset("fake_source", fake_real_csv, out_csv, config)

    assert set(summary.attack_categories_found) == {"DoS", "PortScan"}
    assert summary.output_path == str(out_csv)
    assert out_csv.exists()

    df_syn = pd.read_csv(out_csv)
    assert set(df_syn.columns) >= {"attack_cat", "label", "flow_duration"}
    # Normal + 2 clases de ataque, cada una con su cuota exacta
    assert (df_syn["attack_cat"] == "Normal").sum() == 20
    assert (df_syn["attack_cat"] == "DoS").sum() == 10
    assert (df_syn["attack_cat"] == "PortScan").sum() == 10
    # label siempre coherente con attack_cat, también en lo sintético
    assert ((df_syn["attack_cat"] == "Normal") == (df_syn["label"] == 0)).all()
