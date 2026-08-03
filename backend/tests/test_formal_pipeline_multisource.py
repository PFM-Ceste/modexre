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


def _train_and_freeze_classifier(tmp_path) -> FrozenClassifier:
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
    save_model_artifact(model, feature_names, metrics, version="v1_multi", output_dir=tmp_path)
    return FrozenClassifier(tmp_path, version="v1_multi")


def test_run_rejects_unknown_source_type(tmp_path):
    classifier = _train_and_freeze_classifier(tmp_path / "model")
    chain = CustodyChain(tmp_path / "case.db")
    runner = FormalCaseRunner(chain, classifier)
    with pytest.raises(ValueError):
        runner.run(case_id="x", source_type="fuente_no_soportada", path=tmp_path / "nada.txt")


def test_run_firewall_cef(tmp_path):
    cef_line = (
        "<134>Jul 28 2026 10:15:23 fw01 CEF:0|PaloAltoNetworks|PAN-OS|10.1|"
        "THREAT-SCAN|Suspicious Port Scan Detected|8|"
        "src=10.0.0.5 spt=51234 dst=203.0.113.7 dpt=22 proto=TCP act=blocked"
    )
    log_path = tmp_path / "firewall.log"
    log_path.write_text(cef_line + "\n")

    classifier = _train_and_freeze_classifier(tmp_path / "model")
    chain = CustodyChain(tmp_path / "case.db")
    runner = FormalCaseRunner(chain, classifier)

    report = runner.run(case_id="case_fw_001", source_type="firewall_cef", path=log_path)

    assert report.source_name == "firewall_cef"
    assert len(report.findings) == 1
    operations = [r.operation for r in chain.get_chain("case_fw_001")]
    assert operations == ["ingest", "ocsf_normalize", "aggregate", "feature_extract", "classify"]
    assert report.custody_verification["valid"] is True


def test_run_pcap(tmp_path):
    from scapy.all import IP, TCP, wrpcap
    import time

    pcap_path = tmp_path / "sample.pcap"
    packets = []
    t0 = time.time()
    for i in range(3):
        packets.append(IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=51000, dport=80, seq=i) / b"GET /")
        packets.append(IP(src="10.0.0.9", dst="10.0.0.5") / TCP(sport=80, dport=51000, seq=i) / b"OK")
    for p in packets:
        p.time = t0
    wrpcap(str(pcap_path), packets)

    classifier = _train_and_freeze_classifier(tmp_path / "model")
    chain = CustodyChain(tmp_path / "case.db")
    runner = FormalCaseRunner(chain, classifier)

    report = runner.run(case_id="case_pcap_001", source_type="pcap", path=pcap_path)

    assert report.source_name == "pcap"
    assert len(report.findings) == 1  # un único flujo TCP agregado
    operations = [r.operation for r in chain.get_chain("case_pcap_001")]
    assert operations == ["ingest", "ocsf_normalize", "aggregate", "feature_extract", "classify"]
    assert report.custody_verification["valid"] is True


def test_run_suricata_eve_backward_compatible_alias(tmp_path):
    import json

    eve_path = tmp_path / "eve.json"
    alert = {
        "timestamp": "2026-07-28T10:15:23.123456+0000", "flow_id": 1, "event_type": "alert",
        "src_ip": "10.0.0.5", "src_port": 1234, "dest_ip": "203.0.113.7", "dest_port": 22,
        "proto": "TCP",
        "alert": {"action": "allowed", "gid": 1, "signature_id": 1, "rev": 1,
                   "signature": "Test", "category": "Test", "severity": 2},
        "flow": {"pkts_toserver": 90, "pkts_toclient": 70, "bytes_toserver": 50000, "bytes_toclient": 40000},
    }
    eve_path.write_text(json.dumps(alert) + "\n")

    classifier = _train_and_freeze_classifier(tmp_path / "model")
    chain = CustodyChain(tmp_path / "case.db")
    runner = FormalCaseRunner(chain, classifier)

    report_alias = runner.run_suricata_eve(case_id="case_alias", path=eve_path)
    assert report_alias.source_name == "suricata_eve"
    assert len(report_alias.findings) == 1
