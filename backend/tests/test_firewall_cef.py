import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ingestion.connectors import read_text_lines, read_source
from app.ocsf.firewall_cef import (
    parse_cef_line,
    cef_event_to_ocsf,
    normalize_cef_lines_to_ocsf,
    CEFParseError,
    DETECTION_FINDING_CLASS_UID,
)


# Línea CEF típica de un firewall (con cabecera syslog delante), estilo
# Palo Alto / genérico ArcSight.
CEF_LINE_THREAT = (
    "<134>Jul 28 2026 10:15:23 fw01 CEF:0|PaloAltoNetworks|PAN-OS|10.1|"
    "THREAT-SCAN|Suspicious Port Scan Detected|8|"
    "src=10.0.0.5 spt=51234 dst=203.0.113.7 dpt=22 proto=TCP "
    "act=blocked cat=Reconnaissance in=240 out=180 "
    "msg=Port scan pattern detected across multiple ports"
)

CEF_LINE_LOW_SEVERITY = (
    "<134>Jul 28 2026 10:16:00 fw01 CEF:0|Fortinet|FortiGate|7.0|"
    "TRAFFIC-ALLOW|Standard allowed connection|Low|"
    "src=192.168.1.10 spt=443 dst=8.8.8.8 dpt=443 proto=UDP act=allowed"
)

NOT_CEF_LINE = "Jul 28 2026 10:17:00 fw01 some unrelated plain syslog message"


@pytest.fixture
def firewall_log_file(tmp_path):
    p = tmp_path / "firewall.log"
    p.write_text("\n".join([CEF_LINE_THREAT, NOT_CEF_LINE, CEF_LINE_LOW_SEVERITY]) + "\n")
    return p


# ---------- Ingesta de texto plano ----------

def test_read_text_lines_preserves_raw_content(firewall_log_file):
    result = read_text_lines("firewall_cef", firewall_log_file)
    assert result.row_count == 3
    assert result.events[0]["raw_line"] == CEF_LINE_THREAT


def test_read_source_dispatches_firewall_cef(firewall_log_file):
    result = read_source("firewall_cef", firewall_log_file)
    assert result.source_name == "firewall_cef"
    assert result.row_count == 3


# ---------- Parser CEF ----------

def test_parse_cef_line_extracts_header_fields():
    parsed = parse_cef_line(CEF_LINE_THREAT)
    assert parsed["device_vendor"] == "PaloAltoNetworks"
    assert parsed["device_product"] == "PAN-OS"
    assert parsed["name"] == "Suspicious Port Scan Detected"
    assert parsed["severity"] == "8"


def test_parse_cef_line_extracts_extension_kv_pairs():
    parsed = parse_cef_line(CEF_LINE_THREAT)
    ext = parsed["extension"]
    assert ext["src"] == "10.0.0.5"
    assert ext["dpt"] == "22"
    assert ext["proto"] == "TCP"
    # el mensaje con espacios debe capturarse completo
    assert ext["msg"] == "Port scan pattern detected across multiple ports"


def test_parse_cef_line_named_severity():
    parsed = parse_cef_line(CEF_LINE_LOW_SEVERITY)
    assert parsed["severity"] == "Low"


def test_parse_cef_line_rejects_non_cef():
    with pytest.raises(CEFParseError):
        parse_cef_line(NOT_CEF_LINE)


# ---------- Mapper OCSF ----------

def test_cef_event_maps_to_detection_finding():
    ocsf = cef_event_to_ocsf(CEF_LINE_THREAT)
    assert ocsf["class_uid"] == DETECTION_FINDING_CLASS_UID
    assert ocsf["src_endpoint"]["ip"] == "10.0.0.5"
    assert ocsf["dst_endpoint"]["port"] == "22"
    assert ocsf["finding_info"]["title"] == "Suspicious Port Scan Detected"


def test_cef_severity_high_maps_correctly():
    ocsf = cef_event_to_ocsf(CEF_LINE_THREAT)
    assert ocsf["severity_id"] == 5  # CEF 8 -> tramo alto


def test_cef_named_severity_low_maps_correctly():
    ocsf = cef_event_to_ocsf(CEF_LINE_LOW_SEVERITY)
    assert ocsf["severity_id"] == 2  # "Low" -> 2


def test_cef_does_not_invent_attack_cat():
    ocsf = cef_event_to_ocsf(CEF_LINE_THREAT)
    assert "attack_cat" not in ocsf
    assert "attack_cat" not in ocsf["unmapped"]


def test_cef_preserves_unmapped_extension():
    ocsf = cef_event_to_ocsf(CEF_LINE_THREAT)
    assert ocsf["unmapped"]["cef_extension_raw"]["act"] == "blocked"
    assert ocsf["unmapped"]["message"] == "Port scan pattern detected across multiple ports"


def test_normalize_cef_lines_skips_invalid_lines(firewall_log_file):
    result = read_text_lines("firewall_cef", firewall_log_file)
    ocsf_events = normalize_cef_lines_to_ocsf(result.events)
    # 3 líneas en el fichero, 1 no es CEF -> 2 eventos OCSF válidos
    assert len(ocsf_events) == 2
    assert all(e["class_uid"] == DETECTION_FINDING_CLASS_UID for e in ocsf_events)
