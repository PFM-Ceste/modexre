"""
Normalización a OCSF — Flujos derivados de PCAP
===================================================

A diferencia de app/ocsf/mappers.py (que traduce eventos YA
etiquetados del TFM1, usados para entrenar), este módulo traduce
flujos agregados a partir de una captura PCAP real
(app/ingestion/pcap_reader.py) a OCSF `Network Activity`, SIN
etiqueta: es tráfico real capturado, no un dataset de investigación
con ground truth. La clasificación la produce el modelo propio de
MODEXRE en inferencia (igual que con Detection Finding de Suricata/
firewall), no esta capa.

Se reutilizan deliberadamente los mismos nombres de campo que ya usa
app/ocsf/mappers.py (duration, packets_out/in, bytes_out/in) para que
el vector de features resultante sea compatible con un modelo
entrenado sobre CICIDS/UNSW/Kitsune, aunque el resto de las ~78
columnas de CICFlowMeter no tengan equivalente aquí (quedan a 0.0 en
inferencia, ver features/feature_engineering.py).
"""

from __future__ import annotations

from typing import Any

NETWORK_ACTIVITY_CLASS_UID = 4001
NETWORK_ACTIVITY_CATEGORY_UID = 4
DEFAULT_ACTIVITY_ID = 6  # "Traffic"


def pcap_flow_to_ocsf(flow: dict[str, Any]) -> dict[str, Any]:
    """Mapea un flujo agregado de PCAP (salida de
    ingestion.pcap_reader.read_pcap_flows) a OCSF Network Activity,
    sin etiqueta de ataque."""
    return {
        "class_uid": NETWORK_ACTIVITY_CLASS_UID,
        "category_uid": NETWORK_ACTIVITY_CATEGORY_UID,
        "activity_id": DEFAULT_ACTIVITY_ID,
        "severity_id": 1,  # Informational: la severidad real la asigna el clasificador, no la captura
        "src_endpoint": {"ip": flow.get("src_ip"), "port": flow.get("src_port")},
        "dst_endpoint": {"ip": flow.get("dst_ip")},
        "connection_info": {
            "protocol_raw": flow.get("protocol"),
            "duration": flow.get("duration"),
        },
        "traffic": {
            "packets_out": flow.get("packets_out"),
            "packets_in": flow.get("packets_in"),
            "bytes_out": flow.get("bytes_out"),
            "bytes_in": flow.get("bytes_in"),
        },
        "metadata": {
            "product": {"name": "MODEXRE PCAP flow aggregator"},
            "version": "1.4.0",
        },
        "unmapped": {
            "source_dataset": "pcap",
            "first_seen": flow.get("first_seen"),
        },
    }


def normalize_pcap_flows_to_ocsf(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Mapea una lista completa de flujos PCAP a OCSF Network Activity."""
    return [pcap_flow_to_ocsf(f) for f in flows]
