"""
Normalización a OCSF — Logs de Firewall (CEF / syslog)
==========================================================

CEF (Common Event Format) es el estándar de facto para logs de
firewall de la mayoría de fabricantes (Palo Alto, Fortinet, Cisco
ASA, Check Point...), normalmente envueltos en un encabezado syslog.

Formato de una línea CEF típica:

    <PRI>Mon dd hh:mm:ss host CEF:Version|Vendor|Product|Version|
    SignatureID|Name|Severity|extension_key1=value1 extension_key2=value2 ...

Este módulo NO intenta cubrir cada dialecto propietario de cada
fabricante (esfuerzo desproporcionado para el alcance del TFM2).
Cubre el núcleo del estándar CEF, que es lo que la mayoría de
fabricantes respetan para los campos comunes (src/dst IP, puertos,
protocolo, acción, severidad). Campos de extensión no reconocidos se
preservan íntegros en `unmapped.cef_extension`.

Referencia CEF: Micro Focus ArcSight CEF specification.
Referencia OCSF: https://schema.ocsf.io/1.4.0/classes/detection_finding
"""

from __future__ import annotations

import re
from typing import Any

DETECTION_FINDING_CLASS_UID = 2004
DETECTION_FINDING_CATEGORY_UID = 2
DEFAULT_ACTIVITY_ID = 1  # "Create"

# CEF define severidad 0-10 (entero o "Low"/"Medium"/"High"/"Very-High").
# Se mapea a severity_id OCSF (1=Informational ... 6=Critical).
_CEF_NAMED_SEVERITY = {"low": 2, "medium": 3, "high": 5, "very-high": 6, "unknown": 1}

# Alias de claves de extensión CEF -> nombre legible. CEF define
# abreviaturas oficiales (src, dst, spt, dpt, proto, act) que casi
# todos los fabricantes respetan.
_CEF_EXTENSION_ALIASES = {
    "src": "src_ip", "dst": "dst_ip",
    "spt": "src_port", "dpt": "dst_port",
    "proto": "protocol", "act": "action",
    "cat": "category", "msg": "message",
    "in": "bytes_in", "out": "bytes_out",
}

# Regex de la cabecera CEF: separa por '|' no escapado (CEF permite
# escapar '|' como '\|' dentro de un campo).
_CEF_HEADER_SPLIT_RE = re.compile(r"(?<!\\)\|")

# Regex para tokenizar la extensión (pares clave=valor separados por
# espacio). El valor consume de forma perezosa hasta el siguiente
# "palabra=" reconocible o el final de la cadena: CEF permite espacios
# sin escapar dentro de un valor (p.ej. 'msg=texto con espacios'),
# así que no se puede cortar en el primer espacio.
_CEF_EXTENSION_TOKEN_RE = re.compile(r"(\w+)=(.*?)(?=(?: \w+=)|$)")


class CEFParseError(ValueError):
    """La línea no tiene una cabecera CEF reconocible."""


def _severity_to_ocsf(raw_severity: str) -> int:
    s = raw_severity.strip().lower()
    if s in _CEF_NAMED_SEVERITY:
        return _CEF_NAMED_SEVERITY[s]
    try:
        n = int(s)
    except ValueError:
        return 1
    # Escala CEF 0-10 -> severity_id OCSF 1-6, a tramos.
    if n <= 0:
        return 1
    if n <= 3:
        return 2
    if n <= 5:
        return 3
    if n <= 7:
        return 4
    if n <= 8:
        return 5
    return 6


def parse_cef_line(raw_line: str) -> dict[str, Any]:
    """Parsea una línea CEF (con o sin cabecera syslog previa) a un
    diccionario estructurado. Lanza CEFParseError si no contiene una
    cabecera CEF reconocible."""
    idx = raw_line.find("CEF:")
    if idx == -1:
        raise CEFParseError(f"La línea no contiene una cabecera CEF: '{raw_line[:80]}...'")

    syslog_prefix = raw_line[:idx].strip()
    cef_body = raw_line[idx + len("CEF:"):]

    fields = _CEF_HEADER_SPLIT_RE.split(cef_body, maxsplit=7)
    if len(fields) < 7:
        raise CEFParseError(f"Cabecera CEF incompleta (se esperaban 7 campos): '{raw_line[:120]}'")

    version, vendor, product, product_version, signature_id, name, severity = fields[:7]
    extension_str = fields[7] if len(fields) > 7 else ""

    extension: dict[str, str] = {}
    for match in _CEF_EXTENSION_TOKEN_RE.finditer(extension_str):
        key, value = match.group(1), match.group(2).replace("\\ ", " ")
        extension[key] = value

    return {
        "syslog_prefix": syslog_prefix,
        "cef_version": version,
        "device_vendor": vendor,
        "device_product": product,
        "device_version": product_version,
        "signature_id": signature_id,
        "name": name,
        "severity": severity,
        "extension": extension,
    }


def cef_event_to_ocsf(raw_line: str) -> dict[str, Any]:
    """Mapea una línea de log de firewall en formato CEF a OCSF
    Detection Finding.

    Igual que con Suricata (ver ocsf/detection_finding.py), NO se
    rellena attack_cat: esa etiqueta la produce el clasificador propio
    de MODEXRE, nunca la categoría que el propio firewall se asigna a
    sí mismo.
    """
    parsed = parse_cef_line(raw_line)
    ext = parsed["extension"]

    known_aliased = {}
    for cef_key, friendly_key in _CEF_EXTENSION_ALIASES.items():
        if cef_key in ext:
            known_aliased[friendly_key] = ext[cef_key]

    return {
        "class_uid": DETECTION_FINDING_CLASS_UID,
        "category_uid": DETECTION_FINDING_CATEGORY_UID,
        "activity_id": DEFAULT_ACTIVITY_ID,
        "severity_id": _severity_to_ocsf(parsed["severity"]),
        "src_endpoint": {
            "ip": known_aliased.get("src_ip"),
            "port": known_aliased.get("src_port"),
        },
        "dst_endpoint": {
            "ip": known_aliased.get("dst_ip"),
            "port": known_aliased.get("dst_port"),
        },
        "connection_info": {
            "protocol_raw": known_aliased.get("protocol"),
        },
        "traffic": {
            "bytes_in": known_aliased.get("bytes_in"),
            "bytes_out": known_aliased.get("bytes_out"),
        },
        "finding_info": {
            "title": parsed["name"],
            "uid": parsed["signature_id"],
            "types": [known_aliased["category"]] if "category" in known_aliased else [],
        },
        "metadata": {
            "product": {"name": parsed["device_product"], "vendor_name": parsed["device_vendor"]},
            "version": "1.4.0",
        },
        "unmapped": {
            "source_dataset": "firewall_cef",
            "syslog_prefix": parsed["syslog_prefix"],
            "cef_version": parsed["cef_version"],
            "device_version": parsed["device_version"],
            "action": known_aliased.get("action"),
            "message": known_aliased.get("message"),
            "cef_extension_raw": ext,
        },
    }


def normalize_cef_lines_to_ocsf(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Mapea una lista de eventos {"raw_line": "..."} (salida de
    ingestion.connectors.read_text_lines) a OCSF Detection Finding.
    Líneas que no son CEF válido se omiten en vez de romper el batch
    completo (un log de producción puede mezclar líneas CEF con otras
    de formato distinto que MODEXRE aún no soporta)."""
    results = []
    for event in events:
        try:
            results.append(cef_event_to_ocsf(event["raw_line"]))
        except CEFParseError:
            continue
    return results
