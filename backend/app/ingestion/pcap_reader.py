"""
Ingesta de PCAP
==================

A diferencia del resto de fuentes (CSV ya limpios, JSONL de Suricata,
texto CEF de firewall), un PCAP no es un evento por línea: es una
captura de paquetes individuales que hay que AGREGAR en flujos antes
de que tengan sentido para el clasificador (que espera estadísticas
de flujo, no paquetes sueltos — mismo criterio que CICFlowMeter/UNSW).

Este módulo hace una agregación de flujo deliberadamente simple
(5-tupla: IP origen, IP destino, puerto origen, puerto destino,
protocolo; con corte por inactividad `flow_timeout`), no pretende
sustituir a CICFlowMeter en su totalidad. El objetivo es producir
estadísticas compatibles con los nombres de campo ya usados en
app/ocsf/mappers.py (duration, packets_out/in, bytes_out/in), de
forma que un flujo derivado de una captura real pueda pasar por el
mismo pipeline de features/clasificación que los datasets del TFM1
— con la limitación honesta de que la mayoría de las ~78 columnas de
CICFlowMeter no tienen equivalente aquí, y quedarán a 0.0 en el
vector de features (build_feature_matrix ya está diseñado para
tolerar features ausentes, ver features/feature_engineering.py).

Dependencia: scapy (pesada, exclusiva de esta fuente; import diferido
para no penalizar el arranque del resto del backend).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.custody.chain import sha256_file, sha256_json


@dataclass(frozen=True)
class FlowKey:
    ip_a: str
    ip_b: str
    port_a: int
    port_b: int
    protocol: str

    @classmethod
    def from_packet(cls, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> "FlowKey":
        """Normaliza el 5-tuple de forma no direccional (A<B), de modo
        que los paquetes de ida y vuelta de la misma conexión caigan
        en el mismo flujo independientemente de quién inició."""
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return cls(src_ip, dst_ip, src_port, dst_port, protocol)
        return cls(dst_ip, src_ip, dst_port, src_port, protocol)


@dataclass
class _FlowAccumulator:
    initiator_ip: str
    initiator_port: int
    first_ts: float
    last_ts: float
    packets_fwd: int = 0
    packets_bwd: int = 0
    bytes_fwd: int = 0
    bytes_bwd: int = 0


def _extract_5tuple(packet) -> tuple[str, str, int, int, str] | None:
    """Extrae (src_ip, dst_ip, src_port, dst_port, protocol) de un
    paquete Scapy. Devuelve None si no es IP/TCP/UDP (se ignora, p.ej.
    ARP, ICMP sin puertos no forman parte de un 'flujo' en este
    sentido)."""
    from scapy.layers.inet import IP, TCP, UDP

    if IP not in packet:
        return None
    ip_layer = packet[IP]

    if TCP in packet:
        l4 = packet[TCP]
        proto = "TCP"
    elif UDP in packet:
        l4 = packet[UDP]
        proto = "UDP"
    else:
        return None

    return str(ip_layer.src), str(ip_layer.dst), int(l4.sport), int(l4.dport), proto


def read_pcap_flows(
    path: str | Path,
    flow_timeout: float = 120.0,
    max_packets: int | None = None,
) -> "PcapIngestionResult":
    """Lee un fichero PCAP y agrega sus paquetes en flujos por 5-tupla.

    `flow_timeout`: si dos paquetes del mismo 5-tuple están separados
    por más de este tiempo (segundos), se consideran flujos distintos
    (mismo criterio de corte que usan CICFlowMeter/Argus).
    """
    from scapy.all import PcapReader

    path = Path(path)
    accumulators: dict[FlowKey, list[_FlowAccumulator]] = {}

    n_read = 0
    with PcapReader(str(path)) as reader:
        for packet in reader:
            if max_packets is not None and n_read >= max_packets:
                break
            n_read += 1

            tup = _extract_5tuple(packet)
            if tup is None:
                continue
            src_ip, dst_ip, src_port, dst_port, proto = tup
            ts = float(packet.time)
            pkt_len = len(packet)

            key = FlowKey.from_packet(src_ip, dst_ip, src_port, dst_port, proto)
            flows_for_key = accumulators.setdefault(key, [])

            active = flows_for_key[-1] if flows_for_key else None
            if active is None or (ts - active.last_ts) > flow_timeout:
                active = _FlowAccumulator(
                    initiator_ip=src_ip, initiator_port=src_port,
                    first_ts=ts, last_ts=ts,
                )
                flows_for_key.append(active)

            is_forward = (src_ip == active.initiator_ip and src_port == active.initiator_port)
            if is_forward:
                active.packets_fwd += 1
                active.bytes_fwd += pkt_len
            else:
                active.packets_bwd += 1
                active.bytes_bwd += pkt_len
            active.last_ts = ts

    events: list[dict[str, Any]] = []
    for key, flow_list in accumulators.items():
        for acc in flow_list:
            events.append({
                "src_ip": acc.initiator_ip,
                "src_port": acc.initiator_port,
                "dst_ip": key.ip_b if key.ip_a == acc.initiator_ip else key.ip_a,
                "protocol": key.protocol,
                "duration": round(acc.last_ts - acc.first_ts, 6),
                "packets_out": acc.packets_fwd,
                "packets_in": acc.packets_bwd,
                "bytes_out": acc.bytes_fwd,
                "bytes_in": acc.bytes_bwd,
                "first_seen": datetime.fromtimestamp(acc.first_ts, tz=timezone.utc).isoformat(),
            })

    return PcapIngestionResult(
        source_name="pcap",
        file_path=str(path),
        file_hash=sha256_file(path),
        ingested_at=datetime.now(timezone.utc).isoformat(),
        packets_read=n_read,
        row_count=len(events),
        events=events,
        events_hash=sha256_json(events),
    )


@dataclass
class PcapIngestionResult:
    """Mismo contrato que IngestionResult (app/ingestion/connectors.py)
    con un campo adicional (packets_read) propio de PCAP, relevante
    para la cadena de custodia (cuántos paquetes se leyeron del
    fichero original, no solo cuántos flujos resultaron)."""
    source_name: str
    file_path: str
    file_hash: str
    ingested_at: str
    packets_read: int
    row_count: int
    events: list[dict[str, Any]] = field(default_factory=list)
    events_hash: str = ""
