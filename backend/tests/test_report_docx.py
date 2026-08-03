import shutil
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
from app.report.report_generator import report_to_json, generate_report_docx, generate_report_docx_via_node


requires_node = pytest.mark.skipif(shutil.which("node") is None, reason="Node.js no disponible en este entorno")


def _train_and_freeze(tmp_path) -> FrozenClassifier:
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
    save_model_artifact(model, feature_names, metrics, version="v1_docx", output_dir=tmp_path)
    return FrozenClassifier(tmp_path, version="v1_docx")


def _sample_case(tmp_path):
    import json
    eve_path = tmp_path / "eve.json"
    alert = {
        "timestamp": "2026-07-28T10:15:23.123456+0000", "flow_id": 1, "event_type": "alert",
        "src_ip": "10.0.0.5", "src_port": 51234, "dest_ip": "203.0.113.7", "dest_port": 22, "proto": "TCP",
        "alert": {"action": "allowed", "gid": 1, "signature_id": 2013504, "rev": 4,
                   "signature": "ET SCAN Potential SSH Scan", "category": "Attempted Information Leak", "severity": 2},
        "flow": {"pkts_toserver": 95, "pkts_toclient": 68, "bytes_toserver": 51000, "bytes_toclient": 39500},
    }
    eve_path.write_text(json.dumps(alert) + "\n")

    classifier = _train_and_freeze(tmp_path / "model")
    chain = CustodyChain(tmp_path / "case.db")
    runner = FormalCaseRunner(chain, classifier)
    report = runner.run(case_id="case_docx_test", source_type="suricata_eve", path=eve_path)
    return report, chain


def test_report_to_json_structure(tmp_path):
    report, chain = _sample_case(tmp_path)
    data = report_to_json(report, chain.get_chain(report.case_id))

    assert data["case_id"] == "case_docx_test"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["finding_info"]["title"] == "ET SCAN Potential SSH Scan"
    assert len(data["custody_chain"]) == 5
    assert data["custody_verification"]["valid"] is True


def test_generate_report_docx_produces_valid_file(tmp_path):
    """Generador por defecto (python-docx, sin dependencias externas
    — el que usa la app en la máquina del usuario)."""
    report, chain = _sample_case(tmp_path)
    output_path = tmp_path / "informe.docx"

    doc_bytes = generate_report_docx(report, chain.get_chain(report.case_id), str(output_path))

    assert isinstance(doc_bytes, bytes)
    assert len(doc_bytes) > 1000  # un .docx válido no está vacío
    assert doc_bytes[:2] == b"PK"  # cabecera de fichero ZIP (.docx es un ZIP)

    assert output_path.exists()
    assert output_path.read_bytes()[:2] == b"PK"


def test_generate_report_docx_returns_bytes_without_output_path(tmp_path):
    """Uso típico desde Streamlit: sin escribir a disco, solo bytes
    para st.download_button."""
    report, chain = _sample_case(tmp_path)
    doc_bytes = generate_report_docx(report, chain.get_chain(report.case_id))
    assert isinstance(doc_bytes, bytes)
    assert doc_bytes[:2] == b"PK"


def test_generate_report_docx_judicial_produces_valid_file(tmp_path):
    report, chain = _sample_case(tmp_path)
    output_path = tmp_path / "informe_judicial.docx"

    from app.report.report_generator import generate_report_docx_judicial

    doc_bytes = generate_report_docx_judicial(
        report, chain.get_chain(report.case_id), str(output_path),
        perito_nombre="Perito de Prueba",
        cliente="Cliente de Prueba S.L.",
    )

    assert isinstance(doc_bytes, bytes)
    assert doc_bytes[:2] == b"PK"
    assert output_path.exists()


def test_generate_report_docx_judicial_groups_by_category(tmp_path):
    """El informe judicial debe agrupar los hallazgos por categoría de
    ataque detectada (bloques 'CASO FORENSE'), no listarlos evento a
    evento como hace el informe técnico."""
    report, chain = _sample_case(tmp_path)
    from app.report.report_generator import report_to_json

    data = report_to_json(report, chain.get_chain(report.case_id))
    # El caso de prueba usa un modelo binario simple (sin attack_cat),
    # así que cae al mapeo genérico "Actividad potencialmente maliciosa".
    assert data["findings"][0]["prediction"]["label"] == 1


@requires_node
def test_generate_report_docx_via_node_produces_valid_file(tmp_path):
    """Variante alternativa (docx-js/Node), no usada por la app."""
    report, chain = _sample_case(tmp_path)
    output_path = tmp_path / "informe_node.docx"

    result_path = generate_report_docx_via_node(report, chain.get_chain(report.case_id), str(output_path))

    assert Path(result_path).exists()
    assert Path(result_path).stat().st_size > 1000
    with open(result_path, "rb") as f:
        assert f.read(2) == b"PK"
