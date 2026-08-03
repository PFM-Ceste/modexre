import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.features.flow_aggregation import enrich_with_aggregation


def _event(src_ip, dst_ip, dst_port, timestamp):
    return {
        "src_endpoint": {"ip": src_ip},
        "dst_endpoint": {"ip": dst_ip, "port": dst_port},
        "time": timestamp,
        "unmapped": {"raw_flow_features": {"packets_out": 1}},
    }


def test_portscan_pattern_produces_high_distinct_ports():
    """Un mismo origen tocando 5 puertos distintos en 10 segundos:
    el último evento debe ver los 5 puertos en su ventana."""
    events = [
        _event("10.0.0.5", "203.0.113.7", port, f"2026-07-28T10:00:0{i}+00:00")
        for i, port in enumerate([22, 23, 80, 443, 8080])
    ]
    enriched = enrich_with_aggregation(events, window_seconds=60)

    last = enriched[-1]["unmapped"]["raw_flow_features"]
    assert last["agg_distinct_dst_ports"] == 5
    assert last["agg_distinct_dst_hosts"] == 1  # mismo destino, distintos puertos
    assert last["agg_events_in_window"] == 5


def test_normal_traffic_pattern_produces_low_distinct_ports():
    """Un origen que repetidamente habla con el mismo puerto (tráfico
    normal, p.ej. varias peticiones HTTPS) no debe activar la señal
    de escaneo."""
    events = [
        _event("10.0.0.9", "8.8.8.8", 443, f"2026-07-28T10:00:0{i}+00:00")
        for i in range(5)
    ]
    enriched = enrich_with_aggregation(events, window_seconds=60)
    last = enriched[-1]["unmapped"]["raw_flow_features"]
    assert last["agg_distinct_dst_ports"] == 1
    assert last["agg_events_in_window"] == 5


def test_aggregation_is_causal_not_looking_into_future():
    """El primer evento de una secuencia de escaneo NO debe ver los
    puertos que se van a tocar después: la agregación es causal
    (solo eventos pasados o simultáneos), como correspondería a un
    sistema operando en tiempo real."""
    events = [
        _event("10.0.0.5", "203.0.113.7", port, f"2026-07-28T10:00:0{i}+00:00")
        for i, port in enumerate([22, 23, 80, 443, 8080])
    ]
    enriched = enrich_with_aggregation(events, window_seconds=60)

    first = enriched[0]["unmapped"]["raw_flow_features"]
    assert first["agg_distinct_dst_ports"] == 1  # solo se ve a sí mismo
    assert first["agg_events_in_window"] == 1


def test_window_excludes_events_too_far_in_the_past():
    """Eventos fuera de la ventana temporal no deben contar, aunque
    sean del mismo origen."""
    events = [
        _event("10.0.0.5", "203.0.113.7", 22, "2026-07-28T10:00:00+00:00"),
        _event("10.0.0.5", "203.0.113.7", 80, "2026-07-28T10:05:00+00:00"),  # 5 min después
    ]
    enriched = enrich_with_aggregation(events, window_seconds=60)  # ventana de solo 60s

    last = enriched[-1]["unmapped"]["raw_flow_features"]
    assert last["agg_distinct_dst_ports"] == 1  # el evento de hace 5 min queda fuera
    assert last["agg_events_in_window"] == 1


def test_different_sources_are_isolated():
    events = [
        _event("10.0.0.5", "203.0.113.7", 22, "2026-07-28T10:00:00+00:00"),
        _event("10.0.0.6", "203.0.113.7", 80, "2026-07-28T10:00:01+00:00"),
        _event("10.0.0.5", "203.0.113.7", 443, "2026-07-28T10:00:02+00:00"),
    ]
    enriched = enrich_with_aggregation(events, window_seconds=60)

    last_from_5 = enriched[2]["unmapped"]["raw_flow_features"]
    assert last_from_5["agg_distinct_dst_ports"] == 2  # solo cuenta sus propios eventos (22, 443)


def test_events_without_timestamp_get_zeroed_but_not_dropped():
    events = [
        {"src_endpoint": {"ip": "10.0.0.5"}, "dst_endpoint": {}, "unmapped": {"raw_flow_features": {}}},
    ]
    enriched = enrich_with_aggregation(events)
    assert len(enriched) == 1
    feats = enriched[0]["unmapped"]["raw_flow_features"]
    assert feats["agg_distinct_dst_ports"] == 0
    assert feats["agg_events_in_window"] == 0


def test_original_events_not_mutated_in_place():
    events = [_event("10.0.0.5", "203.0.113.7", 22, "2026-07-28T10:00:00+00:00")]
    original_unmapped_id = id(events[0]["unmapped"])
    enrich_with_aggregation(events)
    assert id(events[0]["unmapped"]) == original_unmapped_id
    assert "agg_distinct_dst_ports" not in events[0]["unmapped"]["raw_flow_features"]
