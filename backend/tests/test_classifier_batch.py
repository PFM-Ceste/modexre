import sys
import time
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.models.classifier import (
    train_multiclass_from_labels,
    train_xgboost_classifier,
    save_model_artifact,
    FrozenClassifier,
)


def _multiclass_dataset(seed=42, n_per_class=60):
    rng = np.random.RandomState(seed)
    X_parts, y_parts = [], []
    for i, loc in enumerate([0, 20, 50]):
        X_parts.append(rng.normal(loc=loc, scale=1, size=(n_per_class, 3)))
        y_parts += [f"Clase{i}"] * n_per_class
    return np.vstack(X_parts), y_parts


def test_predict_batch_matches_individual_predict(tmp_path):
    X, labels = _multiclass_dataset()
    model, metrics, encoder = train_multiclass_from_labels(X, labels, random_state=42)
    save_model_artifact(model, ["f0", "f1", "f2"], metrics, "v1_batch_test", tmp_path, encoder.classes_.tolist())
    frozen = FrozenClassifier(tmp_path, version="v1_batch_test")

    sample = X[:10]
    individual = [frozen.predict(row) for row in sample]
    batch = frozen.predict_batch(sample)

    assert len(batch) == 10
    for ind, bat in zip(individual, batch):
        assert ind["label"] == bat["label"]
        assert ind["attack_cat"] == bat["attack_cat"]
        assert abs(ind["probability"] - bat["probability"]) < 1e-6


def test_explain_batch_matches_individual_explain(tmp_path):
    X, labels = _multiclass_dataset()
    model, metrics, encoder = train_multiclass_from_labels(X, labels, random_state=42)
    save_model_artifact(model, ["f0", "f1", "f2"], metrics, "v1_batch_explain", tmp_path, encoder.classes_.tolist())
    frozen = FrozenClassifier(tmp_path, version="v1_batch_explain")

    sample = X[:5]
    individual = [frozen.explain(row, top_n=3) for row in sample]
    batch = frozen.explain_batch(sample, top_n=3)

    assert len(batch) == 5
    for ind, bat in zip(individual, batch):
        ind_feats = {f["feature"]: f["shap_value"] for f in ind["top_features"]}
        bat_feats = {f["feature"]: f["shap_value"] for f in bat["top_features"]}
        assert ind_feats.keys() == bat_feats.keys()
        for feat in ind_feats:
            assert abs(ind_feats[feat] - bat_feats[feat]) < 1e-4


def test_explain_batch_faster_than_individual_loop(tmp_path):
    """No es solo una cuestión de correctitud: el lote debe ser
    sustancialmente más rápido que el bucle fila a fila, que es
    justo el problema real que motivó este cambio (90.000 eventos
    tardando minutos/horas con el bucle individual)."""
    X, labels = _multiclass_dataset(n_per_class=100)
    model, metrics, encoder = train_multiclass_from_labels(X, labels, random_state=42)
    save_model_artifact(model, ["f0", "f1", "f2"], metrics, "v1_batch_speed", tmp_path, encoder.classes_.tolist())
    frozen = FrozenClassifier(tmp_path, version="v1_batch_speed")

    sample = X[:150]

    t0 = time.time()
    for row in sample:
        frozen.explain(row)
    individual_time = time.time() - t0

    t0 = time.time()
    frozen.explain_batch(sample)
    batch_time = time.time() - t0

    assert batch_time < individual_time
