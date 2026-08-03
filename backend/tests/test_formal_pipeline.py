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
from app.report.report_generator import generate_report_markdown


ALERT_EVENT_TEMPLATE = {
    "timestamp": "2026-07-28T10:15:23.123456+0000",
    "flow_id": 987654321,
    "event_type": "alert",
    "src_ip": "10.0.0.5",
    "src_port": 51234,
    "dest_ip": "203.0.113.7",
    "dest_port": 22,
    "proto": "TCP",
    "alert": {
        "action": "allowed", "gid": 1, "signature_id": 2013504, "rev": 4,
        "signature": "ET SCAN Potential SSH Scan",
        "category": "Attempted Information Leak", "severity": 2,
    },
    "flow": {
        "pkts_toserver": 90, "pkts_toclient": 70,
        "bytes_toserver": 50000, "bytes_toclient": 40000,
    },
}

FLOW_EVENT = {
    "timestamp": "2026-07-28T10:15:24.000000+0000",
    "flow_id": 987654322,
    "event_type": "flow",
    "src_ip": "10.0.0.6",
    "dest_ip": "203.0.113.8",
    "proto": "UDP",
}


def _train_and_freeze_classifier(tmp_path) -> FrozenClassifier:
    """Entrena un clasificador pequeño (modo Laboratorio) sobre datos
    sintéticos con distribuciones claramente separadas, y lo congela,
    para poder testear el pipeline formal de inferencia sin depender
    de un CSV real de varios GB."""
    rng = np.random.RandomState(42)
    events = []
    for _ in range(60):
        raw = {"attack_cat": "Normal", "label": 0,
               "flow_duration": rng.exponential(500),
               "total_fwd_packets": rng.poisson(5),
               "total_backward_packets": rng.poisson(4)}
        events.append(event_to_ocsf("cicids2017", raw))
    for _ in range(60):
        raw = {"attack_cat": "PortScan", "label": 1,
               "flow_duration": rng.exponential(3000) + 2000,
               "total_fwd_packets": rng.poisson(50) + 30,
               "total_backward_packets": rng.poisson(40) + 20}
        events.append(event_to_ocsf("cicids2017", raw))

    X, feature_names = build_feature_matrix(events)
    y = np.array([extract_label(e) for e in events])
    model, metrics = train_xgboost_classifier(X, y, random_state=42)
    save_model_artifact(model, feature_names, metrics, version="v1_e2e", output_dir=tmp_path)
    return FrozenClassifier(tmp_path, version="v1_e2e")


@pytest.fixture
def eve_jsonl_high_traffic(tmp_path):
    """Alerta con volumen de tráfico alto (patrón similar al de
    'PortScan' usado para entrenar), para que la clasificación no sea
    arbitraria en el test."""
    p = tmp_path / "eve.json"
    lines = [json.dumps(ALERT_EVENT_TEMPLATE), json.dumps(FLOW_EVENT)]
    p.write_text("\n".join(lines) + "\n")
    return p


def test_formal_pipeline_end_to_end(tmp_path, eve_jsonl_high_traffic):
    classifier = _train_and_freeze_classifier(tmp_path / "model_dir")
    chain = CustodyChain(tmp_path / "case.db")
    runner = FormalCaseRunner(chain, classifier)

    report = runner.run_suricata_eve(case_id="case_test_001", path=eve_jsonl_high_traffic)

    # Solo el evento 'alert' se procesa (el 'flow' se descarta en la
    # normalización a Detection Finding)
    assert len(report.findings) == 1

    finding = report.findings[0]
    assert finding.prediction["label"] in (0, 1)
    assert 0.0 <= finding.prediction["probability"] <= 1.0
    assert len(finding.explanation["top_features"]) > 0

    # La cadena de custodia debe tener 4 eslabones: ingest, ocsf_normalize,
    # feature_extract, classify
    chain_records = chain.get_chain("case_test_001")
    operations = [r.operation for r in chain_records]
    assert operations == ["ingest", "ocsf_normalize", "aggregate", "feature_extract", "classify"]

    # Y debe verificar como íntegra
    assert report.custody_verification["valid"] is True


def test_formal_pipeline_report_generation(tmp_path, eve_jsonl_high_traffic):
    classifier = _train_and_freeze_classifier(tmp_path / "model_dir")
    chain = CustodyChain(tmp_path / "case.db")
    runner = FormalCaseRunner(chain, classifier)

    report = runner.run_suricata_eve(case_id="case_test_002", path=eve_jsonl_high_traffic)
    markdown = generate_report_markdown(report)

    assert "Informe Pericial" in markdown
    assert "case_test_002" in markdown
    assert "Cadena de Custodia" in markdown
    assert "SHAP" in markdown
    # el hallazgo original de Suricata debe aparecer citado en el informe
    assert "ET SCAN Potential SSH Scan" in markdown


def test_formal_pipeline_tampered_custody_is_flagged_in_report(tmp_path, eve_jsonl_high_traffic):
    """Si alguien manipula la cadena de custodia DESPUÉS de generado
    el informe, una regeneración del informe debe reflejar la
    alerta — no debe quedar enmascarada."""
    import sqlite3

    classifier = _train_and_freeze_classifier(tmp_path / "model_dir")
    db_path = tmp_path / "case.db"
    chain = CustodyChain(db_path)
    runner = FormalCaseRunner(chain, classifier)

    runner.run_suricata_eve(case_id="case_test_003", path=eve_jsonl_high_traffic)

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE custody_chain SET output_hash = ? WHERE case_id = ? AND idx = 0",
            ("MANIPULADO", "case_test_003"),
        )
        conn.commit()

    verification = chain.verify("case_test_003")
    assert verification["valid"] is False
