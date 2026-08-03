import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ingestion.pcap_reader import read_pcap_flows, FlowKey
from app.ocsf.pcap_flow import pcap_flow_to_ocsf, normalize_pcap_flows_to_ocsf, NETWORK_ACTIVITY_CLASS_UID


def _build_sample_pcap(path: Path) -> None:
    """Genera un PCAP real (no un mock) con dos flujos TCP distintos:
    uno de pocos paquetes ('normal') y otro con muchos paquetes en
    poco tiempo ('escaneo'), usando Scapy tanto para construir como
    para escribir los paquetes."""
    from scapy.all import IP, TCP, wrpcap
    import time

    packets = []
    t0 = time.time()

    # Flujo 1: conversación TCP normal, 4 paquetes, ida y vuelta
    for i in range(2):
        packets.append(IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=51000, dport=80, seq=i) / b"GET / ")
        packets.append(IP(src="10.0.0.9", dst="10.0.0.5") / TCP(sport=80, dport=51000, seq=i) / b"HTTP/1.1 200 OK")

    # Flujo 2: muchos paquetes SYN a puertos distintos desde el mismo origen
    # (cada uno es un 5-tuple distinto -> flujos independientes de 1 paquete)
    for port in range(20000, 20010):
        packets.append(IP(src="10.0.0.5", dst="203.0.113.7") / TCP(sport=port, dport=22, flags="S"))

    for p in packets:
        p.time = t0

    wrpcap(str(path), packets)


@pytest.fixture
def sample_pcap(tmp_path):
    p = tmp_path / "sample.pcap"
    _build_sample_pcap(p)
    return p


def test_flow_key_is_direction_independent():
    key_ab = FlowKey.from_packet("10.0.0.5", "10.0.0.9", 51000, 80, "TCP")
    key_ba = FlowKey.from_packet("10.0.0.9", "10.0.0.5", 80, 51000, "TCP")
    assert key_ab == key_ba


def test_read_pcap_flows_aggregates_correctly(sample_pcap):
    result = read_pcap_flows(sample_pcap)

    # 24 paquetes en total: 4 del flujo HTTP + 10 SYN de puerto único cada uno
    assert result.packets_read == 14
    # 1 flujo HTTP agregado + 10 flujos de un solo paquete (puertos distintos)
    assert result.row_count == 11


def test_read_pcap_flows_computes_bidirectional_stats(sample_pcap):
    result = read_pcap_flows(sample_pcap)
    http_flow = next(f for f in result.events if f["packets_out"] == 2 and f["packets_in"] == 2)
    # el flujo HTTP debe tener 2 paquetes en cada dirección
    assert http_flow["packets_out"] == 2
    assert http_flow["packets_in"] == 2
    assert http_flow["bytes_out"] > 0
    assert http_flow["bytes_in"] > 0


def test_read_pcap_flows_computes_file_hash(sample_pcap):
    result = read_pcap_flows(sample_pcap)
    assert len(result.file_hash) == 64
    assert result.source_name == "pcap"


def test_read_pcap_flows_respects_max_packets(sample_pcap):
    result = read_pcap_flows(sample_pcap, max_packets=4)
    assert result.packets_read == 4


# ---------- Mapper OCSF ----------

def test_pcap_flow_to_ocsf_maps_traffic_fields():
    flow = {
        "src_ip": "10.0.0.5", "src_port": 51000, "dst_ip": "10.0.0.9",
        "protocol": "TCP", "duration": 1.5,
        "packets_out": 2, "packets_in": 2, "bytes_out": 120, "bytes_in": 300,
    }
    ocsf = pcap_flow_to_ocsf(flow)
    assert ocsf["class_uid"] == NETWORK_ACTIVITY_CLASS_UID
    assert ocsf["traffic"]["packets_out"] == 2
    assert ocsf["connection_info"]["duration"] == 1.5
    # los flujos de PCAP no tienen etiqueta: no debe inventarse ninguna
    assert "attack_cat" not in ocsf["unmapped"]


def test_normalize_pcap_flows_end_to_end(sample_pcap):
    result = read_pcap_flows(sample_pcap)
    ocsf_events = normalize_pcap_flows_to_ocsf(result.events)
    assert len(ocsf_events) == result.row_count
    assert all(e["class_uid"] == NETWORK_ACTIVITY_CLASS_UID for e in ocsf_events)
