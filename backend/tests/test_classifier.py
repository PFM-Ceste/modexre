import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.features.feature_engineering import (
    ocsf_event_to_feature_dict,
    extract_label,
    build_feature_matrix,
)
from app.ocsf.mappers import event_to_ocsf
from app.models.classifier import (
    train_xgboost_classifier,
    save_model_artifact,
    FrozenClassifier,
    ModelIntegrityError,
)


def _sample_ocsf_events(n_normal=60, n_attack=60, seed=42):
    rng = np.random.RandomState(seed)
    events = []
    for _ in range(n_normal):
        raw = {
            "attack_cat": "Normal", "label": 0,
            "flow_duration": rng.exponential(500),
            "total_fwd_packets": rng.poisson(5),
            "total_backward_packets": rng.poisson(4),
        }
        events.append(event_to_ocsf("cicids2017", raw))
    for _ in range(n_attack):
        raw = {
            "attack_cat": "DDoS", "label": 1,
            "flow_duration": rng.exponential(3000) + 2000,  # distribución claramente distinta
            "total_fwd_packets": rng.poisson(50) + 30,
            "total_backward_packets": rng.poisson(40) + 20,
        }
        events.append(event_to_ocsf("cicids2017", raw))
    return events


# ---------- Feature engineering ----------

def test_ocsf_event_to_feature_dict_extracts_numeric_fields():
    raw = {"attack_cat": "Normal", "label": 0, "flow_duration": 1000, "total_fwd_packets": 5}
    ocsf = event_to_ocsf("cicids2017", raw)
    features = ocsf_event_to_feature_dict(ocsf)
    # total_fwd_packets se renombra a packets_out en el mapper OCSF
    # (ver app/ocsf/mappers.py, _KNOWN_FIELDS_BY_SOURCE); flow_duration
    # a 'duration'. Se comprueba el nombre OCSF, no el original.
    assert features["packets_out"] == 5.0
    assert features["duration"] == 1000.0
    assert "attack_cat" not in features
    assert "label" not in features


def test_extract_label_reads_from_unmapped():
    raw = {"attack_cat": "DDoS", "label": 1, "flow_duration": 100}
    ocsf = event_to_ocsf("cicids2017", raw)
    assert extract_label(ocsf) == 1


def test_absolute_timestamp_fields_excluded_from_features():
    """Los campos de timestamp ABSOLUTO se excluyen del vector de
    features (prevención de fuga de información): en Kitsune se
    comprobó empíricamente que incluir 'time' hacía que el modelo
    aprendiera la sesión de captura en vez del patrón de tráfico
    (F1 macro 0.98 con 'time' -> 0.66 sin él, ver memoria TFM2).
    'duration' (una diferencia de tiempo, no un timestamp absoluto)
    NO debe excluirse: sigue siendo una feature legítima.
    """
    raw = {"attack_cat": "DDoS", "label": 1, "time": 1_753_700_000.0, "sport": 443, "dport": 8080}
    ocsf = event_to_ocsf("kitsune", raw)
    features = ocsf_event_to_feature_dict(ocsf)
    assert "time" not in features
    assert features["sport"] == 443.0
    assert features["dport"] == 8080.0

    raw_duration = {"attack_cat": "Normal", "label": 0, "flow_duration": 1500}
    ocsf_duration = event_to_ocsf("cicids2017", raw_duration)
    assert "duration" in ocsf_event_to_feature_dict(ocsf_duration)


def test_build_feature_matrix_shape_and_consistency():
    events = _sample_ocsf_events(n_normal=5, n_attack=5)
    matrix, feature_names = build_feature_matrix(events)
    assert matrix.shape[0] == 10
    assert matrix.shape[1] == len(feature_names)

    # Reutilizar feature_names fijos (caso inferencia) da la misma columna count
    matrix2, names2 = build_feature_matrix(events[:3], feature_names=feature_names)
    assert names2 == feature_names
    assert matrix2.shape == (3, len(feature_names))


# ---------- Entrenamiento + inferencia congelada (end-to-end) ----------

def test_end_to_end_train_freeze_infer_explain(tmp_path):
    events = _sample_ocsf_events(n_normal=80, n_attack=80)
    X, feature_names = build_feature_matrix(events)
    y = np.array([extract_label(e) for e in events])

    model, metrics = train_xgboost_classifier(X, y, random_state=42)
    # Con distribuciones claramente separadas, el modelo debe generalizar bien
    assert metrics.f1_macro > 0.9

    manifest = save_model_artifact(model, feature_names, metrics, version="v1_test", output_dir=tmp_path)
    assert (tmp_path / manifest["model_file"]).exists()

    frozen = FrozenClassifier(tmp_path, version="v1_test")
    assert frozen.feature_names == feature_names

    # Caso de inferencia nuevo, claramente de tipo ataque
    attack_raw = {
        "attack_cat": "DDoS", "label": 1,
        "flow_duration": 9000, "total_fwd_packets": 90, "total_backward_packets": 70,
    }
    attack_ocsf = event_to_ocsf("cicids2017", attack_raw)
    x_vector, _ = build_feature_matrix([attack_ocsf], feature_names=feature_names)

    prediction = frozen.predict(x_vector[0])
    assert prediction["label"] == 1
    assert prediction["model_version"] == "v1_test"

    explanation = frozen.explain(x_vector[0], top_n=3)
    assert len(explanation["top_features"]) == 3
    assert all("feature" in f and "shap_value" in f for f in explanation["top_features"])


def test_frozen_classifier_detects_tampered_model_file(tmp_path):
    events = _sample_ocsf_events(n_normal=20, n_attack=20)
    X, feature_names = build_feature_matrix(events)
    y = np.array([extract_label(e) for e in events])
    model, metrics = train_xgboost_classifier(X, y)
    save_model_artifact(model, feature_names, metrics, version="v_tamper", output_dir=tmp_path)

    # Simula sustitución del fichero de modelo tras la certificación
    model_file = tmp_path / "model_v_tamper.ubj"
    model_file.write_bytes(b"contenido manipulado, no es un modelo valido")

    with pytest.raises(ModelIntegrityError):
        FrozenClassifier(tmp_path, version="v_tamper")


def test_frozen_classifier_missing_version_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        FrozenClassifier(tmp_path, version="no_existe")
