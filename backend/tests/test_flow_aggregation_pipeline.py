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


def _train_classifier_with_agg_features(tmp_path) -> FrozenClassifier:
    """Entrena un clasificador cuyo espacio de features incluye las
    variables de agregación (agg_distinct_dst_ports, etc.), simulando
    eventos de entrenamiento etiquetados ya con esas variables — como
    ocurriría si se entrenara sobre evidencia real pre-agregada."""
    rng = np.random.RandomState(42)
    events = []
    for _ in range(60):
        raw = {"attack_cat": "Normal", "label": 0,
               "flow_duration": rng.exponential(500),
               "total_fwd_packets": rng.poisson(5),
               "total_backward_packets": rng.poisson(4)}
        ocsf = event_to_ocsf("cicids2017", raw)
        ocsf["unmapped"]["raw_flow_features"]["agg_distinct_dst_ports"] = rng.poisson(1) + 1
        ocsf["unmapped"]["raw_flow_features"]["agg_events_in_window"] = rng.poisson(2) + 1
        events.append(ocsf)
    for _ in range(60):
        raw = {"attack_cat": "PortScan", "label": 1,
               "flow_duration": rng.exponential(100),
               "total_fwd_packets": rng.poisson(2),
               "total_backward_packets": rng.poisson(1)}
        ocsf = event_to_ocsf("cicids2017", raw)
        ocsf["unmapped"]["raw_flow_features"]["agg_distinct_dst_ports"] = rng.poisson(20) + 10
        ocsf["unmapped"]["raw_flow_features"]["agg_events_in_window"] = rng.poisson(20) + 10
        events.append(ocsf)

    X, feature_names = build_feature_matrix(events)
    y = np.array([extract_label(e) for e in events])
    model, metrics = train_xgboost_classifier(X, y, random_state=42)
    save_model_artifact(model, feature_names, metrics, version="v1_agg_test", output_dir=tmp_path)
    return FrozenClassifier(tmp_path, version="v1_agg_test")


def _make_eve_alert(src_ip, dst_port, timestamp, flow_id):
    return {
        "timestamp": timestamp, "flow_id": flow_id, "event_type": "alert",
        "src_ip": src_ip, "src_port": 40000 + flow_id, "dest_ip": "203.0.113.7",
        "dest_port": dst_port, "proto": "TCP",
        "alert": {"action": "allowed", "gid": 1, "signature_id": flow_id, "rev": 1,
                   "signature": "ET SCAN probe", "category": "Attempted Recon", "severity": 2},
        "flow": {"pkts_toserver": 2, "pkts_toclient": 1, "bytes_toserver": 60, "bytes_toclient": 40},
    }


def test_aggregation_signal_present_in_scan_case(tmp_path):
    """Caso real: 8 alertas del mismo origen a 8 puertos distintos en
    pocos segundos (patrón de escaneo). La agregación debe reflejar
    esto en el último evento, y el eslabón de custodia 'aggregate'
    debe existir."""
    classifier = _train_classifier_with_agg_features(tmp_path / "model")

    eve_path = tmp_path / "scan_eve.json"
    alerts = [
        _make_eve_alert("10.0.0.5", port, f"2026-07-28T10:00:0{i}+00:00", i)
        for i, port in enumerate([22, 23, 80, 443, 3389, 8080, 8443, 3306])
    ]
    eve_path.write_text("\n".join(json.dumps(a) for a in alerts) + "\n")

    chain = CustodyChain(tmp_path / "case.db")
    runner = FormalCaseRunner(chain, classifier, aggregation_window_seconds=60)
    report = runner.run(case_id="case_scan_pattern", source_type="suricata_eve", path=eve_path)

    assert len(report.findings) == 8

    operations = [r.operation for r in chain.get_chain("case_scan_pattern")]
    assert "aggregate" in operations

    # El último evento de la secuencia debe ver los 8 puertos distintos
    last_finding = report.findings[-1]
    agg_ports = last_finding.ocsf_event["unmapped"]["raw_flow_features"]["agg_distinct_dst_ports"]
    assert agg_ports == 8

    # El primer evento solo se ve a sí mismo (agregación causal)
    first_finding = report.findings[0]
    agg_ports_first = first_finding.ocsf_event["unmapped"]["raw_flow_features"]["agg_distinct_dst_ports"]
    assert agg_ports_first == 1

    assert report.custody_verification["valid"] is True


def test_aggregation_distinguishes_scan_from_repeated_normal_traffic(tmp_path):
    """Contraste directo: mismo número de eventos (5), pero uno es un
    patrón de escaneo (5 puertos distintos) y el otro es tráfico
    normal repetido (mismo puerto 5 veces). La agregación debe
    distinguirlos claramente."""
    classifier = _train_classifier_with_agg_features(tmp_path / "model")

    scan_path = tmp_path / "scan.json"
    scan_alerts = [
        _make_eve_alert("10.0.0.5", port, f"2026-07-28T10:00:0{i}+00:00", i)
        for i, port in enumerate([22, 23, 80, 443, 3389])
    ]
    scan_path.write_text("\n".join(json.dumps(a) for a in scan_alerts) + "\n")

    normal_path = tmp_path / "normal.json"
    normal_alerts = [
        _make_eve_alert("10.0.0.9", 443, f"2026-07-28T10:00:0{i}+00:00", i + 100)
        for i in range(5)
    ]
    normal_path.write_text("\n".join(json.dumps(a) for a in normal_alerts) + "\n")

    chain = CustodyChain(tmp_path / "case.db")
    runner = FormalCaseRunner(chain, classifier, aggregation_window_seconds=60)

    scan_report = runner.run(case_id="case_scan", source_type="suricata_eve", path=scan_path)
    normal_report = runner.run(case_id="case_normal", source_type="suricata_eve", path=normal_path)

    scan_last_ports = scan_report.findings[-1].ocsf_event["unmapped"]["raw_flow_features"]["agg_distinct_dst_ports"]
    normal_last_ports = normal_report.findings[-1].ocsf_event["unmapped"]["raw_flow_features"]["agg_distinct_dst_ports"]

    assert scan_last_ports == 5
    assert normal_last_ports == 1
    assert scan_last_ports > normal_last_ports
