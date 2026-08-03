"""
Normalización a OCSF — Clase Detection Finding
=================================================

A diferencia de app/ocsf/mappers.py (que traduce FLUJOS de red ya
etiquetados por el TFM1 a la clase `Network Activity`), este módulo
traduce ALERTAS de un IDS/IPS (Suricata EVE JSON) a la clase OCSF
`Detection Finding` (category_uid=2 "Findings", class_uid=2004).

Diferencia conceptual importante: una alerta de Suricata NO es la
etiqueta de entrenamiento del clasificador de MODEXRE. Es la opinión
de OTRO sistema (Suricata, con sus propias reglas) sobre ese tráfico.
Se conserva íntegra en `finding_info` / `unmapped` como contexto, pero
el campo `attack_cat` de la taxonomía cerrada del TFM1 (ver
app/ocsf/mappers.py) solo lo produce el clasificador propio de
MODEXRE, nunca se copia directamente de aquí.

Referencia de esquema: https://schema.ocsf.io/1.4.0/classes/detection_finding
"""

from __future__ import annotations

from typing import Any

DETECTION_FINDING_CLASS_UID = 2004
DETECTION_FINDING_CATEGORY_UID = 2

# activity_id OCSF para Detection Finding: 1 = "Create" (se crea un
# nuevo hallazgo). Suricata no distingue update/close a este nivel.
DEFAULT_ACTIVITY_ID = 1

# Mapeo de severidad Suricata (1=alta ... 3=baja, convención Snort/ET)
# a severity_id OCSF (1=Informational ... 6=Critical). Suricata no usa
# 0 en la práctica; se deja como fallback defensivo.
_SURICATA_SEVERITY_TO_OCSF = {
    1: 5,  # alta -> High
    2: 4,  # media -> Medium
    3: 3,  # baja -> Low
    0: 1,  # desconocida -> Informational
}


class UnsupportedEventTypeError(ValueError):
    """El evento EVE JSON no es de tipo 'alert' (p.ej. es 'flow', 'dns'...)."""


def suricata_alert_to_ocsf(event: dict[str, Any]) -> dict[str, Any]:
    """Mapea un evento Suricata EVE JSON de tipo 'alert' a OCSF
    Detection Finding.

    Lanza UnsupportedEventTypeError si el evento no es una alerta
    (Suricata EVE mezcla varios event_type en el mismo log: alert,
    flow, dns, http... y solo 'alert' representa un hallazgo).
    """
    event_type = event.get("event_type")
    if event_type != "alert":
        raise UnsupportedEventTypeError(
            f"event_type='{event_type}' no es una alerta. Este mapper solo "
            f"traduce eventos EVE de tipo 'alert' a Detection Finding; otros "
            f"tipos (flow, dns, http...) requieren un mapper distinto."
        )

    alert = event.get("alert", {}) or {}
    flow = event.get("flow", {}) or {}

    suricata_severity = alert.get("severity")
    severity_id = _SURICATA_SEVERITY_TO_OCSF.get(suricata_severity, 1)

    return {
        "class_uid": DETECTION_FINDING_CLASS_UID,
        "category_uid": DETECTION_FINDING_CATEGORY_UID,
        "activity_id": DEFAULT_ACTIVITY_ID,
        "severity_id": severity_id,
        "time": event.get("timestamp"),
        "src_endpoint": {
            "ip": event.get("src_ip"),
            "port": event.get("src_port"),
        },
        "dst_endpoint": {
            "ip": event.get("dest_ip"),
            "port": event.get("dest_port"),
        },
        "connection_info": {
            "protocol_raw": event.get("proto"),
        },
        "traffic": {
            "packets_out": flow.get("pkts_toserver"),
            "packets_in": flow.get("pkts_toclient"),
            "bytes_out": flow.get("bytes_toserver"),
            "bytes_in": flow.get("bytes_toclient"),
        },
        "finding_info": {
            "title": alert.get("signature"),
            "uid": alert.get("signature_id"),
            "types": [alert.get("category")] if alert.get("category") else [],
        },
        "metadata": {
            "product": {"name": "Suricata", "vendor_name": "OISF"},
            "version": "1.4.0",
        },
        "unmapped": {
            "source_dataset": "suricata_eve",
            "flow_id": event.get("flow_id"),
            "suricata_action": alert.get("action"),
            "suricata_gid": alert.get("gid"),
            "suricata_rev": alert.get("rev"),
            "suricata_severity_raw": suricata_severity,
            "raw_event": event,
        },
    }


def normalize_eve_events_to_ocsf(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filtra y mapea solo los eventos de tipo 'alert' de una lista de
    eventos EVE JSON (el resto, p.ej. 'flow'/'dns'/'http', se ignora
    por ahora — quedan fuera del alcance de Detection Finding)."""
    return [
        suricata_alert_to_ocsf(e) for e in events if e.get("event_type") == "alert"
    ]
