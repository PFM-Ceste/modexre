import json
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.custody.chain import CustodyChain
from app.features.feature_engineering import build_feature_matrix, extract_label
from app.models.classifier import train_xgboost_classifier, save_model_artifact, FrozenClassifier
from app.ocsf.mappers import event_to_ocsf
from app.pipeline.formal_pipeline import FormalCaseRunner


def _train_and_freeze(tmp_path) -> FrozenClassifier:
    rng = np.random.RandomState(42)
    events = []
    for _ in range(40):
        raw = {"attack_cat": "Normal", "label": 0, "flow_duration": rng.exponential(500),
               "total_fwd_packets": rng.poisson(5), "total_backward_packets": rng.poisson(4)}
        events.append(event_to_ocsf("cicids2017", raw))
    for _ in range(40):
        raw = {"attack_cat": "PortScan", "label": 1, "flow_duration": rng.exponential(3000) + 2000,
               "total_fwd_packets": rng.poisson(50) + 30, "total_backward_packets": rng.poisson(40) + 20}
        events.append(event_to_ocsf("cicids2017", raw))
    X, feature_names = build_feature_matrix(events)
    y = np.array([extract_label(e) for e in events])
    model, metrics = train_xgboost_classifier(X, y, random_state=42)
    save_model_artifact(model, feature_names, metrics, version="v1_progress_test", output_dir=tmp_path)
    return FrozenClassifier(tmp_path, version="v1_progress_test")


def test_on_step_callback_fires_in_order_with_expected_steps(tmp_path):
    alert = {
        "timestamp": "2026-07-28T10:15:23.123456+0000", "flow_id": 1, "event_type": "alert",
        "src_ip": "10.0.0.5", "src_port": 1234, "dest_ip": "203.0.113.7", "dest_port": 22,
        "proto": "TCP",
        "alert": {"action": "allowed", "gid": 1, "signature_id": 1, "rev": 1,
                   "signature": "Test", "category": "Test", "severity": 2},
        "flow": {"pkts_toserver": 90, "pkts_toclient": 70, "bytes_toserver": 50000, "bytes_toclient": 40000},
    }
    eve_path = tmp_path / "eve.json"
    eve_path.write_text(json.dumps(alert) + "\n")

    classifier = _train_and_freeze(tmp_path / "model")
    chain = CustodyChain(tmp_path / "case.db")
    runner = FormalCaseRunner(chain, classifier)

    seen_steps = []

    def on_step(step_name, info):
        assert "label" in info and "detail" in info
        seen_steps.append(step_name)

    report = runner.run(case_id="case_progress", source_type="suricata_eve", path=eve_path, on_step=on_step)

    assert seen_steps == ["ingest", "ocsf_normalize", "aggregate", "feature_extract", "classify", "verify"]
    assert len(report.findings) == 1


def test_on_step_is_optional_and_backward_compatible(tmp_path):
    """Llamar a run() sin on_step debe funcionar exactamente igual
    que antes de añadir esta funcionalidad."""
    alert = {
        "timestamp": "2026-07-28T10:15:23.123456+0000", "flow_id": 1, "event_type": "alert",
        "src_ip": "10.0.0.5", "src_port": 1234, "dest_ip": "203.0.113.7", "dest_port": 22,
        "proto": "TCP",
        "alert": {"action": "allowed", "gid": 1, "signature_id": 1, "rev": 1,
                   "signature": "Test", "category": "Test", "severity": 2},
        "flow": {"pkts_toserver": 90, "pkts_toclient": 70, "bytes_toserver": 50000, "bytes_toclient": 40000},
    }
    eve_path = tmp_path / "eve.json"
    eve_path.write_text(json.dumps(alert) + "\n")

    classifier = _train_and_freeze(tmp_path / "model")
    chain = CustodyChain(tmp_path / "case.db")
    runner = FormalCaseRunner(chain, classifier)

    report = runner.run(case_id="case_no_callback", source_type="suricata_eve", path=eve_path)
    assert len(report.findings) == 1


def test_on_step_fires_correctly_on_empty_ocsf_events(tmp_path):
    """Si ningún evento sobrevive la normalización OCSF (p.ej. un
    fichero solo con eventos 'flow', sin 'alert'), el callback debe
    recibir 'done' en vez de continuar con pasos que no ocurren."""
    flow_only = {
        "timestamp": "2026-07-28T10:15:24.000000+0000", "flow_id": 2, "event_type": "flow",
        "src_ip": "10.0.0.6", "dest_ip": "203.0.113.8", "proto": "UDP",
    }
    eve_path = tmp_path / "eve_no_alerts.json"
    eve_path.write_text(json.dumps(flow_only) + "\n")

    classifier = _train_and_freeze(tmp_path / "model")
    chain = CustodyChain(tmp_path / "case.db")
    runner = FormalCaseRunner(chain, classifier)

    seen_steps = []
    report = runner.run(
        case_id="case_empty", source_type="suricata_eve", path=eve_path,
        on_step=lambda step, info: seen_steps.append(step),
    )

    assert seen_steps == ["ingest", "ocsf_normalize", "done"]
    assert report.findings == []
