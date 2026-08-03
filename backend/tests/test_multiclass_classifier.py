import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.models.classifier import (
    train_multiclass_from_labels,
    save_model_artifact,
    FrozenClassifier,
)


def _sample_multiclass_dataset(seed=42):
    """3 clases claramente separables por una sola feature dominante,
    para poder verificar que predict()/explain() identifican la clase
    correcta de forma determinista."""
    rng = np.random.RandomState(seed)
    X_parts, y_parts = [], []

    # Normal: valores bajos
    X_parts.append(rng.normal(loc=0, scale=1, size=(60, 2)))
    y_parts += ["Normal"] * 60

    # PortScan: valores medios
    X_parts.append(rng.normal(loc=20, scale=1, size=(60, 2)))
    y_parts += ["PortScan"] * 60

    # DDoS: valores altos
    X_parts.append(rng.normal(loc=50, scale=1, size=(60, 2)))
    y_parts += ["DDoS"] * 60

    X = np.vstack(X_parts)
    return X, y_parts


def test_train_multiclass_from_labels_returns_encoder():
    X, labels = _sample_multiclass_dataset()
    model, metrics, encoder = train_multiclass_from_labels(X, labels, random_state=42)

    assert metrics.f1_macro > 0.9
    assert set(encoder.classes_) == {"Normal", "PortScan", "DDoS"}


def test_save_and_load_multiclass_model_predicts_class_names(tmp_path):
    X, labels = _sample_multiclass_dataset()
    model, metrics, encoder = train_multiclass_from_labels(X, labels, random_state=42)

    save_model_artifact(
        model, feature_names=["f0", "f1"], metrics=metrics,
        version="v1_multiclass_test", output_dir=tmp_path,
        class_names=encoder.classes_.tolist(),
    )

    frozen = FrozenClassifier(tmp_path, version="v1_multiclass_test")
    assert frozen.class_names == sorted(["Normal", "PortScan", "DDoS"])

    # Caso claramente de tipo DDoS (valores altos)
    ddos_vector = np.array([50.0, 50.0])
    prediction = frozen.predict(ddos_vector)
    assert prediction["attack_cat"] == "DDoS"
    assert "class_probabilities" in prediction
    assert set(prediction["class_probabilities"].keys()) == {"Normal", "PortScan", "DDoS"}
    # Las probabilidades de las 3 clases deben sumar ~1
    assert abs(sum(prediction["class_probabilities"].values()) - 1.0) < 1e-4


def test_multiclass_explain_returns_shap_for_predicted_class(tmp_path):
    X, labels = _sample_multiclass_dataset()
    model, metrics, encoder = train_multiclass_from_labels(X, labels, random_state=42)
    save_model_artifact(
        model, feature_names=["f0", "f1"], metrics=metrics,
        version="v1_multiclass_shap", output_dir=tmp_path,
        class_names=encoder.classes_.tolist(),
    )
    frozen = FrozenClassifier(tmp_path, version="v1_multiclass_shap")

    portscan_vector = np.array([20.0, 20.0])
    prediction = frozen.predict(portscan_vector)
    assert prediction["attack_cat"] == "PortScan"

    explanation = frozen.explain(portscan_vector, top_n=2)
    assert len(explanation["top_features"]) == 2
    assert all("feature" in f and "shap_value" in f for f in explanation["top_features"])


def test_binary_model_without_class_names_still_works(tmp_path):
    """Retrocompatibilidad: un modelo binario simple (sin class_names)
    debe seguir funcionando exactamente igual que antes."""
    rng = np.random.RandomState(0)
    X = np.vstack([rng.normal(0, 1, (40, 2)), rng.normal(10, 1, (40, 2))])
    y = np.array([0] * 40 + [1] * 40)

    from app.models.classifier import train_xgboost_classifier
    model, metrics = train_xgboost_classifier(X, y, random_state=42)
    save_model_artifact(model, ["f0", "f1"], metrics, "v1_binary_test", tmp_path)

    frozen = FrozenClassifier(tmp_path, version="v1_binary_test")
    assert frozen.class_names is None

    prediction = frozen.predict(np.array([10.0, 10.0]))
    assert prediction["label"] == 1
    assert "attack_cat" not in prediction
