import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ingestion.universal import sniff_source_type, sniff_csv_dialect, normalize_any


CICIDS_LABELED_SAMPLE = """attack_cat,label,Destination Port,Protocol,Flow Duration,Total Fwd Packets,Total Backward Packets
Normal,0,80,6,1000,10,8
DDoS,1,443,6,2500,20,15
"""

CICIDS_UNLABELED_SAMPLE = """Destination Port,Protocol,Flow Duration,Total Fwd Packets,Total Backward Packets
80,6,1000,10,8
443,6,2500,20,15
"""

ALERT_LINE = json.dumps({
    "timestamp": "2026-07-28T10:15:23.123456+0000", "flow_id": 1, "event_type": "alert",
    "src_ip": "10.0.0.5", "src_port": 1234, "dest_ip": "203.0.113.7", "dest_port": 22, "proto": "TCP",
    "alert": {"action": "allowed", "gid": 1, "signature_id": 1, "rev": 1,
              "signature": "Test", "category": "Test", "severity": 2},
    "flow": {"pkts_toserver": 10, "pkts_toclient": 8, "bytes_toserver": 500, "bytes_toclient": 400},
})

CEF_LINE = (
    "<134>Jul 28 2026 10:15:23 fw01 CEF:0|PaloAltoNetworks|PAN-OS|10.1|"
    "THREAT-SCAN|Suspicious Port Scan Detected|8|"
    "src=10.0.0.5 spt=51234 dst=203.0.113.7 dpt=22 proto=TCP act=blocked"
)


# ---------- sniff_source_type ----------

def test_sniff_detects_csv_by_extension(tmp_path):
    p = tmp_path / "flujos.csv"
    p.write_text(CICIDS_LABELED_SAMPLE)
    assert sniff_source_type(p) == "csv"


def test_sniff_detects_jsonl_by_extension(tmp_path):
    p = tmp_path / "eve.json"
    p.write_text(ALERT_LINE + "\n")
    assert sniff_source_type(p) == "jsonl"


def test_sniff_detects_pcap_by_extension(tmp_path):
    p = tmp_path / "captura.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    assert sniff_source_type(p) == "pcap"


def test_sniff_detects_cef_by_content_with_ambiguous_extension(tmp_path):
    p = tmp_path / "firewall.log"
    p.write_text(CEF_LINE + "\n")
    assert sniff_source_type(p) == "cef_text"


def test_sniff_detects_jsonl_by_content_with_ambiguous_extension(tmp_path):
    p = tmp_path / "eventos.log"
    p.write_text(ALERT_LINE + "\n")
    assert sniff_source_type(p) == "jsonl"


def test_sniff_raises_on_unrecognizable_content(tmp_path):
    p = tmp_path / "misterioso.dat"
    p.write_bytes(b"\x00\x01\x02\x03binarysinformatoreconocible")
    with pytest.raises(ValueError):
        sniff_source_type(p)


# ---------- sniff_csv_dialect ----------

def test_sniff_csv_dialect_detects_cicids():
    cols = ["destination_port", "protocol", "flow_duration", "total_fwd_packets", "total_backward_packets"]
    assert sniff_csv_dialect(cols) == "cicids2017"


def test_sniff_csv_dialect_detects_unsw():
    cols = ["proto", "dur", "spkts", "dpkts", "sbytes", "dbytes"]
    assert sniff_csv_dialect(cols) == "unsw_nb15"


def test_sniff_csv_dialect_falls_back_to_generic():
    cols = ["columna_rara_1", "columna_rara_2", "campo_desconocido"]
    assert sniff_csv_dialect(cols) == "generic_flow_csv"


# ---------- normalize_any (end-to-end) ----------

def test_normalize_any_csv_labeled(tmp_path):
    """CSV de investigación YA etiquetado (formato TFM1): se detecta
    como tal y conserva la etiqueta en el evento OCSF."""
    p = tmp_path / "labeled.csv"
    p.write_text(CICIDS_LABELED_SAMPLE)

    result = normalize_any(p)
    assert result.is_labeled is True
    assert result.source_type_detected == "csv_labeled"
    assert result.row_count == 2
    assert result.ocsf_events[0]["unmapped"]["attack_cat"] in ("Normal", "DDoS")


def test_normalize_any_csv_unlabeled_real_evidence(tmp_path):
    """Este es el caso que motivó este módulo: un CSV con las mismas
    columnas de CICIDS (p.ej. exportado por el CICFlowMeter propio de
    una empresa) pero SIN attack_cat/label, porque es evidencia real
    sin clasificar. Debe normalizarse igualmente a OCSF, sin
    etiqueta, listo para que el clasificador la use en modo Formal."""
    p = tmp_path / "evidencia_real_cicids_style.csv"
    p.write_text(CICIDS_UNLABELED_SAMPLE)

    result = normalize_any(p)
    assert result.is_labeled is False
    assert result.source_type_detected == "csv_unlabeled:cicids2017"
    assert result.row_count == 2
    # No debe haberse inventado ninguna etiqueta
    assert "attack_cat" not in result.ocsf_events[0]["unmapped"]
    # Pero SÍ debe haber reconocido el dialecto CICIDS y mapeado bien los campos
    assert result.ocsf_events[0]["traffic"]["packets_out"] == 10


def test_normalize_any_suricata_eve(tmp_path):
    p = tmp_path / "eve.json"
    p.write_text(ALERT_LINE + "\n")

    result = normalize_any(p)
    assert result.source_type_detected == "suricata_eve"
    assert result.is_labeled is False
    assert result.row_count == 1
    assert result.ocsf_events[0]["class_uid"] == 2004  # Detection Finding


def test_normalize_any_firewall_cef(tmp_path):
    p = tmp_path / "firewall.log"
    p.write_text(CEF_LINE + "\n")

    result = normalize_any(p)
    assert result.source_type_detected == "firewall_cef"
    assert result.is_labeled is False
    assert result.row_count == 1


def test_normalize_any_pcap(tmp_path):
    from scapy.all import IP, TCP, wrpcap
    import time

    p = tmp_path / "captura.pcap"
    packets = [IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=51000, dport=80)]
    for pkt in packets:
        pkt.time = time.time()
    wrpcap(str(p), packets)

    result = normalize_any(p)
    assert result.source_type_detected == "pcap"
    assert result.is_labeled is False
    assert result.row_count == 1


def test_normalize_any_respects_source_hint(tmp_path):
    """source_hint fuerza el tipo, ignorando la auto-detección."""
    p = tmp_path / "eve.json"
    p.write_text(ALERT_LINE + "\n")

    result = normalize_any(p, source_hint="jsonl")
    assert result.source_type_detected == "suricata_eve"
