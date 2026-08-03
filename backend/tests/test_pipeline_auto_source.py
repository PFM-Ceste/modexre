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
    save_model_artifact(model, feature_names, metrics, version="v1_auto_test", output_dir=tmp_path)
    return FrozenClassifier(tmp_path, version="v1_auto_test")


def test_run_with_auto_source_type_suricata(tmp_path):
    """El pipeline debe funcionar igual con source_type='auto' que con
    el tipo explícito, cuando el fichero es detectable sin ambigüedad."""
    alert = {
        "timestamp": "2026-07-28T10:15:23.123456+0000", "flow_id": 1, "event_type": "alert",
        "src_ip": "10.0.0.5", "src_port": 1234, "dest_ip": "203.0.113.7", "dest_port": 22, "proto": "TCP",
        "alert": {"action": "allowed", "gid": 1, "signature_id": 1, "rev": 1,
                   "signature": "Test", "category": "Test", "severity": 2},
        "flow": {"pkts_toserver": 90, "pkts_toclient": 70, "bytes_toserver": 50000, "bytes_toclient": 40000},
    }
    eve_path = tmp_path / "eve.json"
    eve_path.write_text(json.dumps(alert) + "\n")

    classifier = _train_and_freeze(tmp_path / "model")
    chain = CustodyChain(tmp_path / "case.db")
    runner = FormalCaseRunner(chain, classifier)

    report = runner.run(case_id="case_auto_suricata", source_type="auto", path=eve_path)

    assert len(report.findings) == 1
    assert report.custody_verification["valid"] is True
    operations = [r.operation for r in chain.get_chain("case_auto_suricata")]
    assert operations == ["ingest", "ocsf_normalize", "aggregate", "feature_extract", "classify"]


def test_run_with_auto_source_type_unlabeled_csv(tmp_path):
    """El caso que motivó el ingestor universal: un CSV con columnas
    estilo CICIDS pero SIN attack_cat/label (evidencia real), subido
    directamente al modo Formal con auto-detección."""
    csv_content = (
        "Destination Port,Protocol,Flow Duration,Total Fwd Packets,Total Backward Packets\n"
        "22,6,3200,55,40\n"
        "443,6,150,3,2\n"
    )
    csv_path = tmp_path / "evidencia_real.csv"
    csv_path.write_text(csv_content)

    classifier = _train_and_freeze(tmp_path / "model")
    chain = CustodyChain(tmp_path / "case.db")
    runner = FormalCaseRunner(chain, classifier)

    report = runner.run(case_id="case_auto_csv", source_type="auto", path=csv_path)

    assert len(report.findings) == 2
    assert report.custody_verification["valid"] is True
    # El eslabón de ingesta debe reflejar que se detectó un CSV sin etiquetar
    chain_records = chain.get_chain("case_auto_csv")
    assert "csv_unlabeled" in chain_records[0].notes
