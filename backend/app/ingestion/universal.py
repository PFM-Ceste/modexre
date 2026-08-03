"""
Ingesta Universal
====================

Punto de entrada ÚNICO para cualquier fichero que un usuario suba,
tanto en modo Laboratorio como en modo Formal: detecta automáticamente
de qué tipo es (CSV de investigación etiquetado, CSV de flujo sin
etiquetar, JSONL de Suricata, texto CEF de firewall, o PCAP) y lo
normaliza siempre al mismo modelo — eventos OCSF Network Activity o
Detection Finding, según corresponda — sin que el usuario tenga que
indicar manualmente el tipo de fuente.

Esto responde a un requisito de diseño explícito: "lo que suba lo que
suba se convierta a un solo modelo normalizado de tipos de ataque
para poder investigar en laboratorio o en modo formal". Antes de este
módulo, MODEXRE tenía dos caminos de ingesta separados (CSV
etiquetados del TFM1 para Laboratorio, evidencia sin etiquetar para
Formal); este módulo los unifica en un único punto de entrada, dejando
que sea el CONTENIDO del fichero — no una elección manual previa —
quien determine cómo se procesa.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from app.ingestion.connectors import read_flow_csv, read_jsonl, read_text_lines
from app.ingestion.pcap_reader import read_pcap_flows
from app.ocsf.mappers import event_to_ocsf, _KNOWN_FIELDS_BY_SOURCE
from app.ocsf.detection_finding import normalize_eve_events_to_ocsf
from app.ocsf.firewall_cef import normalize_cef_lines_to_ocsf
from app.ocsf.pcap_flow import normalize_pcap_flows_to_ocsf


# Fuentes CSV con dialecto conocido (nombres de columna alias) que
# sniff_csv_dialect puede reconocer. "generic_flow_csv" es el fallback
# cuando no hay solapamiento suficiente con ningún dialecto conocido.
_KNOWN_CSV_DIALECTS = ("cicids2017", "unsw_nb15")  # kitsune no tiene columnas de flujo reconocibles por nombre


def sniff_csv_dialect(columns: list[str]) -> str:
    """Determina qué dialecto de CSV de flujo es más probable a partir
    de sus nombres de columna, por solapamiento con los alias
    conocidos de cada fuente (ver app.ocsf.mappers._KNOWN_FIELDS_BY_SOURCE).

    Devuelve "generic_flow_csv" si ningún dialecto conocido solapa lo
    suficiente (evita adivinar un dialecto incorrecto con baja
    confianza, que produciría un mapeo de campos erróneo)."""
    cols = set(columns)
    best_source, best_score = "generic_flow_csv", 0
    for source in _KNOWN_CSV_DIALECTS:
        known_cols = set(_KNOWN_FIELDS_BY_SOURCE.get(source, {}).values())
        if not known_cols:
            continue
        score = len(known_cols & cols)
        if score > best_score:
            best_source, best_score = source, score

    # Umbral mínimo: al menos 2 columnas conocidas deben coincidir
    # para confiar en el dialecto detectado.
    if best_score < 2:
        return "generic_flow_csv"
    return best_source


def sniff_source_type(path: str | Path) -> str:
    """Detecta el tipo de fichero a partir de su extensión y, si hace
    falta, un vistazo rápido a su contenido. Devuelve uno de:
    'csv', 'jsonl', 'cef_text', 'pcap'.

    No decide todavía si el CSV está etiquetado o no, ni qué dialecto
    tiene — eso lo resuelve normalize_any() después de leerlo.
    """
    path = Path(path)
    suffix = path.suffix.lower()

    if suffix in (".pcap", ".pcapng", ".cap"):
        return "pcap"
    if suffix == ".csv":
        return "csv"
    if suffix in (".json", ".jsonl", ".ndjson"):
        return "jsonl"

    # Extensión ambigua (.log, .txt, sin extensión...): inspeccionar
    # las primeras líneas no vacías del fichero.
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            for _ in range(5):
                line = f.readline()
                if not line.strip():
                    continue
                stripped = line.strip()
                if "CEF:" in stripped:
                    return "cef_text"
                if stripped.startswith("{"):
                    try:
                        json.loads(stripped)
                        return "jsonl"
                    except json.JSONDecodeError:
                        pass
                if "," in stripped:
                    return "csv"
                break
    except (UnicodeDecodeError, OSError):
        pass

    # Comprobación de magic bytes por si la extensión no ayudó y el
    # contenido tampoco es texto (PCAP es binario).
    try:
        with open(path, "rb") as f:
            header = f.read(4)
        if header in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
            return "pcap"
    except OSError:
        pass

    raise ValueError(
        f"No se ha podido determinar el tipo de fichero de '{path.name}'. "
        f"Formatos soportados: CSV de flujo, JSON Lines (Suricata EVE), "
        f"texto CEF (firewall/syslog), PCAP."
    )


@dataclass
class UniversalIngestionResult:
    ocsf_events: list[dict[str, Any]]
    source_type_detected: str       # 'csv_labeled' | 'csv_unlabeled:<dialecto>' | 'suricata_eve' | 'firewall_cef' | 'pcap'
    is_labeled: bool
    file_hash: str
    events_hash: str
    row_count: int


def normalize_any(path: str | Path, source_hint: Optional[str] = None) -> UniversalIngestionResult:
    """Punto de entrada único: detecta el tipo de `path`, lo ingiere
    con el lector correspondiente, y lo normaliza a OCSF — siempre
    con el mismo resultado (lista de eventos OCSF), esté o no
    etiquetado el fichero de origen.

    `source_hint`, si se proporciona, fuerza el tipo detectado en vez
    de inferirlo (por si el usuario quiere forzar explícitamente un
    formato, por ejemplo cuando la auto-detección es ambigua).
    """
    path = Path(path)
    detected = source_hint or sniff_source_type(path)

    if detected == "pcap":
        result = read_pcap_flows(path)
        ocsf_events = normalize_pcap_flows_to_ocsf(result.events)
        return UniversalIngestionResult(
            ocsf_events=ocsf_events, source_type_detected="pcap", is_labeled=False,
            file_hash=result.file_hash, events_hash=result.events_hash, row_count=result.row_count,
        )

    if detected == "jsonl":
        result = read_jsonl("suricata_eve", path)
        ocsf_events = normalize_eve_events_to_ocsf(result.events)
        return UniversalIngestionResult(
            ocsf_events=ocsf_events, source_type_detected="suricata_eve", is_labeled=False,
            file_hash=result.file_hash, events_hash=result.events_hash, row_count=result.row_count,
        )

    if detected == "cef_text":
        result = read_text_lines("firewall_cef", path)
        ocsf_events = normalize_cef_lines_to_ocsf(result.events)
        return UniversalIngestionResult(
            ocsf_events=ocsf_events, source_type_detected="firewall_cef", is_labeled=False,
            file_hash=result.file_hash, events_hash=result.events_hash, row_count=result.row_count,
        )

    if detected == "csv":
        # Primero se lee sin exigir taxonomía, para poder inspeccionar
        # las columnas y decidir dialecto + si está etiquetado.
        result = read_flow_csv("generic_flow_csv", path)
        has_label = len(result.events) > 0 and "attack_cat" in result.events[0]
        dialect = sniff_csv_dialect(list(result.events[0].keys())) if result.events else "generic_flow_csv"

        ocsf_events = [
            event_to_ocsf(dialect, event, require_label=has_label)
            for event in result.events
        ]
        label_tag = "csv_labeled" if has_label else f"csv_unlabeled:{dialect}"
        return UniversalIngestionResult(
            ocsf_events=ocsf_events, source_type_detected=label_tag, is_labeled=has_label,
            file_hash=result.file_hash, events_hash=result.events_hash, row_count=result.row_count,
        )

    raise ValueError(f"Tipo de fuente '{detected}' no reconocido por el ingestor universal.")
