import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ocsf.mappers import (
    event_to_ocsf,
    normalize_to_ocsf,
    TaxonomyError,
    NETWORK_ACTIVITY_CLASS_UID,
)


def test_normal_maps_to_low_severity():
    event = {
        "attack_cat": "Normal", "label": 0,
        "destination_port": 80, "protocol": 6, "flow_duration": 1000,
    }
    ocsf = event_to_ocsf("cicids2017", event)
    assert ocsf["class_uid"] == NETWORK_ACTIVITY_CLASS_UID
    assert ocsf["severity_id"] == 1
    assert ocsf["unmapped"]["attack_cat"] == "Normal"


def test_attack_maps_to_higher_severity():
    event = {"attack_cat": "DDoS", "label": 1, "protocol": 6, "flow_duration": 2500}
    ocsf = event_to_ocsf("cicids2017", event)
    assert ocsf["severity_id"] == 3
    assert ocsf["unmapped"]["attack_cat"] == "DDoS"


def test_cicids_extracts_known_traffic_fields():
    event = {
        "attack_cat": "PortScan", "label": 1,
        "total_fwd_packets": 5, "total_backward_packets": 3,
        "flow_duration": 500,
    }
    ocsf = event_to_ocsf("cicids2017", event)
    assert ocsf["traffic"]["packets_out"] == 5
    assert ocsf["traffic"]["packets_in"] == 3
    assert ocsf["connection_info"]["duration"] == 500
    # los campos ya extraídos no deben duplicarse en unmapped
    assert "total_fwd_packets" not in ocsf["unmapped"]["raw_flow_features"]


def test_unsw_nb15_field_mapping():
    event = {"attack_cat": "Exploits", "label": 1, "proto": "tcp", "dur": 1.2, "sbytes": 500, "dbytes": 300}
    ocsf = event_to_ocsf("unsw_nb15", event)
    assert ocsf["connection_info"]["protocol_raw"] == "tcp"
    assert ocsf["traffic"]["bytes_out"] == 500
    assert ocsf["traffic"]["bytes_in"] == 300


def test_kitsune_preserves_full_feature_vector_in_unmapped():
    event = {"attack_cat": "Backdoors", "label": 1, "feature_0": 0.12, "feature_1": 5.6}
    ocsf = event_to_ocsf("kitsune", event)
    assert ocsf["unmapped"]["raw_flow_features"] == {"feature_0": 0.12, "feature_1": 5.6}
    assert ocsf["connection_info"] == {}
    assert ocsf["traffic"] == {}


def test_rejects_attack_cat_outside_closed_taxonomy():
    """Un attack_cat fuera de la taxonomía cerrada del TFM1 indica un
    fallo en la capa de limpieza previa: debe fallar aquí, no
    inventarse una categoría nueva silenciosamente."""
    event = {"attack_cat": "Ransomware_no_normalizado", "label": 1}
    with pytest.raises(TaxonomyError):
        event_to_ocsf("cicids2017", event)


def test_extended_categories_accepted():
    """Regresión: Bot, Worms, Heartbleed, Infiltration y las dos
    variantes de Web Attack se recuperaron como clases propias tras
    detectar, en un pcap real (case_2026_001), que colapsarlas dentro
    de 'Generic' descartaba señal real distinguible por el modelo.
    No deben volver a rechazarse como fuera de taxonomía."""
    for cat in ["Bot", "Worms", "Heartbleed", "Infiltration",
                "Web Attack – Xss", "Web Attack – Sql Injection"]:
        event = {"attack_cat": cat, "label": 1, "protocol": 6, "flow_duration": 1000}
        ocsf = event_to_ocsf("cicids2017", event)
        assert ocsf["unmapped"]["attack_cat"] == cat


def test_missing_attack_cat_raises_key_error():
    with pytest.raises(KeyError):
        event_to_ocsf("cicids2017", {"label": 0, "protocol": 6})


def test_normalize_to_ocsf_dispatch():
    ocsf = normalize_to_ocsf("cicids2017", {"attack_cat": "Normal", "label": 0})
    assert ocsf["class_uid"] == NETWORK_ACTIVITY_CLASS_UID


def test_normalize_to_ocsf_rejects_unknown_source():
    with pytest.raises(ValueError):
        normalize_to_ocsf("fuente_desconocida", {"attack_cat": "Normal", "label": 0})
