import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ingestion.connectors import read_jsonl, read_source
from app.ocsf.detection_finding import (
    suricata_alert_to_ocsf,
    normalize_eve_events_to_ocsf,
    UnsupportedEventTypeError,
    DETECTION_FINDING_CLASS_UID,
)


ALERT_EVENT = {
    "timestamp": "2026-07-28T10:15:23.123456+0000",
    "flow_id": 987654321,
    "event_type": "alert",
    "src_ip": "10.0.0.5",
    "src_port": 51234,
    "dest_ip": "203.0.113.7",
    "dest_port": 22,
    "proto": "TCP",
    "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": 2013504,
        "rev": 4,
        "signature": "ET SCAN Potential SSH Scan",
        "category": "Attempted Information Leak",
        "severity": 2,
    },
    "flow": {
        "pkts_toserver": 4,
        "pkts_toclient": 3,
        "bytes_toserver": 240,
        "bytes_toclient": 180,
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


@pytest.fixture
def eve_jsonl(tmp_path):
    p = tmp_path / "eve.json"
    lines = [json.dumps(ALERT_EVENT), json.dumps(FLOW_EVENT), json.dumps(ALERT_EVENT)]
    p.write_text("\n".join(lines) + "\n")
    return p


# ---------- Ingesta JSONL ----------

def test_read_jsonl_parses_all_lines(eve_jsonl):
    result = read_jsonl("suricata_eve", eve_jsonl)
    assert result.row_count == 3
    assert result.events[0]["event_type"] == "alert"


def test_read_jsonl_computes_hash(eve_jsonl):
    result = read_jsonl("suricata_eve", eve_jsonl)
    assert len(result.file_hash) == 64


def test_read_jsonl_skips_blank_lines(tmp_path):
    p = tmp_path / "eve_with_blanks.json"
    p.write_text(json.dumps(ALERT_EVENT) + "\n\n\n" + json.dumps(FLOW_EVENT) + "\n")
    result = read_jsonl("suricata_eve", p)
    assert result.row_count == 2


def test_read_source_dispatches_suricata_eve(eve_jsonl):
    result = read_source("suricata_eve", eve_jsonl)
    assert result.source_name == "suricata_eve"
    assert result.row_count == 3


def test_read_jsonl_does_not_require_attack_cat(eve_jsonl):
    """A diferencia de los CSV limpios del TFM1, JSONL en bruto no
    debe exigir attack_cat/label — no existen en la fuente."""
    result = read_jsonl("suricata_eve", eve_jsonl)
    assert "attack_cat" not in result.events[0]


def test_read_jsonl_tolerates_bom(tmp_path):
    """Un fichero guardado como 'UTF-8 con BOM' (común al guardar
    desde algunos editores/terminales de Windows) no debe romper el
    parseo. Sin esto, la primera línea deja de empezar por '{' desde
    el punto de vista de json.loads, dando un error confuso que
    apunta a 'columna 2' aunque el JSON en sí sea válido."""
    p = tmp_path / "eve_con_bom.json"
    content = json.dumps(ALERT_EVENT) + "\n"
    p.write_bytes(b"\xef\xbb\xbf" + content.encode("utf-8"))  # BOM UTF-8 + contenido

    result = read_jsonl("suricata_eve", p)
    assert result.row_count == 1
    assert result.events[0]["event_type"] == "alert"


def test_read_jsonl_gives_clear_error_on_invalid_json(tmp_path):
    """Si una línea no es JSON válido, el error debe señalar el
    número de línea y mostrar el contenido problemático, no un
    JSONDecodeError genérico sin contexto."""
    p = tmp_path / "invalid.json"
    p.write_text(json.dumps(ALERT_EVENT) + "\n" + "esto no es JSON\n")

    with pytest.raises(ValueError, match="Línea 2"):
        read_jsonl("suricata_eve", p)


# ---------- Mapper OCSF Detection Finding ----------

def test_alert_maps_to_detection_finding():
    ocsf = suricata_alert_to_ocsf(ALERT_EVENT)
    assert ocsf["class_uid"] == DETECTION_FINDING_CLASS_UID
    assert ocsf["finding_info"]["title"] == "ET SCAN Potential SSH Scan"
    assert ocsf["finding_info"]["uid"] == 2013504
    assert ocsf["src_endpoint"]["ip"] == "10.0.0.5"
    assert ocsf["dst_endpoint"]["port"] == 22


def test_alert_severity_mapping():
    ocsf = suricata_alert_to_ocsf(ALERT_EVENT)
    assert ocsf["severity_id"] == 4  # Suricata severity=2 (media) -> OCSF 4


def test_alert_preserves_traffic_stats():
    ocsf = suricata_alert_to_ocsf(ALERT_EVENT)
    assert ocsf["traffic"]["packets_out"] == 4
    assert ocsf["traffic"]["bytes_in"] == 180


def test_non_alert_event_raises():
    with pytest.raises(UnsupportedEventTypeError):
        suricata_alert_to_ocsf(FLOW_EVENT)


def test_does_not_invent_attack_cat():
    """El mapper de Detection Finding nunca debe rellenar attack_cat:
    esa etiqueta solo la produce el clasificador propio de MODEXRE."""
    ocsf = suricata_alert_to_ocsf(ALERT_EVENT)
    assert "attack_cat" not in ocsf
    assert "attack_cat" not in ocsf["unmapped"]


def test_normalize_eve_events_filters_only_alerts():
    events = [ALERT_EVENT, FLOW_EVENT, ALERT_EVENT]
    ocsf_events = normalize_eve_events_to_ocsf(events)
    assert len(ocsf_events) == 2
    assert all(e["class_uid"] == DETECTION_FINDING_CLASS_UID for e in ocsf_events)
