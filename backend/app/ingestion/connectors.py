"""
Capa de Ingesta
================

Cada conector lee una fuente de datos en bruto y devuelve:

  1. Una lista de eventos "crudos" (dicts en Python, con las columnas
     originales de la fuente, sin transformar).
  2. Metadatos de procedencia: ruta del fichero, hash SHA-256 del
     fichero completo, número de filas leídas, timestamp de ingesta.

Estos metadatos son los que alimentan el primer eslabón de la cadena
de custodia (operation="ingest") cuando se opera en modo FORMAL.

Los conectores NO normalizan a OCSF ni hacen feature engineering:
esa responsabilidad vive en app/ocsf y app/features respectivamente,
para mantener cada capa testeable de forma independiente.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from app.custody.chain import sha256_file, sha256_json


@dataclass
class IngestionResult:
    source_name: str          # p.ej. "cicids2017", "unsw_nb15", "kitsune"
    file_path: str
    file_hash: str             # SHA-256 del fichero original completo
    ingested_at: str
    row_count: int
    events: list[dict[str, Any]]
    events_hash: str           # SHA-256 del conjunto de eventos ya leídos en memoria


def _finalize(source_name: str, file_path: Path, events: list[dict[str, Any]]) -> IngestionResult:
    return IngestionResult(
        source_name=source_name,
        file_path=str(file_path),
        file_hash=sha256_file(file_path),
        ingested_at=datetime.now(timezone.utc).isoformat(),
        row_count=len(events),
        events=events,
        events_hash=sha256_json(events),
    )


def _to_snake_case(columns: list[str]) -> list[str]:
    """Misma normalización de nombres de columna que los notebooks
    FULL_* del TFM1: strip, espacios/guiones/slashes -> '_', minúsculas."""
    out = []
    for c in columns:
        c = str(c).strip().replace(" ", "_").replace("/", "_").replace("-", "_")
        out.append(c.lower())
    return out


def read_clean_csv(source_name: str, path: str | Path, nrows: int | None = None) -> IngestionResult:
    """Lee un CSV ya limpio por el pipeline del TFM1 (salida de los
    notebooks FULL_MachineLearningCVE / FULL_UNSW_NB15 / FULL_KITSUNE):
    columnas en snake_case, con `attack_cat` y `label` ya normalizados
    como primeras columnas.

    Valida la presencia de attack_cat/label en vez de asumirla: un
    CSV que no las tenga no ha pasado por la limpieza esperada, y
    dejar pasar eso silenciosamente rompería la capa OCSF más
    adelante con un error menos claro.
    """
    path = Path(path)
    df = pd.read_csv(path, nrows=nrows)
    df.columns = _to_snake_case(list(df.columns))

    missing = {"attack_cat", "label"} - set(df.columns)
    if missing:
        raise ValueError(
            f"El CSV '{path.name}' no contiene {sorted(missing)}. Se espera un "
            f"fichero ya normalizado por la capa de limpieza previa (attack_cat/"
            f"label como primeras columnas), no un CSV crudo sin procesar."
        )

    events = df.to_dict(orient="records")
    return _finalize(source_name, path, events)


def read_flow_csv(source_name: str, path: str | Path, nrows: int | None = None) -> IngestionResult:
    """Lee un CSV de flujo SIN exigir attack_cat/label.

    A diferencia de read_clean_csv (que exige la taxonomía del TFM1),
    esta función acepta tanto CSV ya etiquetados (los reenvía tal
    cual) como CSV de evidencia REAL sin etiquetar — p.ej. un export
    de CICFlowMeter propio de una empresa, con las mismas columnas de
    estadísticas de flujo pero sin que nadie haya clasificado el
    tráfico todavía. Es la puerta de entrada del ingestor universal
    (ver ingestion/universal.py) para CSV de origen desconocido.
    """
    path = Path(path)
    df = pd.read_csv(path, nrows=nrows)
    df.columns = _to_snake_case(list(df.columns))
    events = df.to_dict(orient="records")
    return _finalize(source_name, path, events)


def read_jsonl(source_name: str, path: str | Path, max_lines: int | None = None) -> IngestionResult:
    """Lee un fichero JSON Lines (un objeto JSON por línea), formato
    típico de logs de IDS/IPS como Suricata EVE JSON o Zeek en modo
    JSON. A diferencia de read_clean_csv, NO exige attack_cat/label:
    estas fuentes son verdaderamente en bruto y no traen etiqueta de
    ataque — esa etiqueta la produce el clasificador de MODEXRE más
    adelante, no la capa de ingesta.
    """
    import json

    path = Path(path)
    events: list[dict[str, Any]] = []
    # encoding="utf-8-sig" descarta un posible BOM (marca de orden de
    # bytes) al principio del fichero: algunos editores/terminales de
    # Windows lo añaden al guardar como "UTF-8", y eso hace que la
    # PRIMERA línea deje de empezar por '{', rompiendo el parseo JSON
    # de forma confusa (el error apunta a la primera línea aunque el
    # contenido sea válido).
    with open(path, "r", encoding="utf-8-sig") as f:
        for i, raw_line in enumerate(f):
            if max_lines is not None and i >= max_lines:
                break
            line = raw_line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as e:
                preview = line[:120] + ("..." if len(line) > 120 else "")
                raise ValueError(
                    f"Línea {i + 1} de '{path.name}' no es JSON válido: {e}\n"
                    f"Contenido de la línea: {preview!r}\n"
                    f"Comprueba que el fichero es JSON Lines (un objeto JSON por "
                    f"línea) y no, por ejemplo, un array JSON completo envuelto en "
                    f"[ ] con comas entre objetos."
                ) from e
    return _finalize(source_name, path, events)


def read_text_lines(source_name: str, path: str | Path, max_lines: int | None = None) -> IngestionResult:
    """Lee un fichero de texto plano línea a línea, preservando cada
    línea EXACTAMENTE tal cual (sin parsear), como 'events' de la
    forma {"raw_line": "..."}.

    Uso previsto: logs de firewall en formato syslog/CEF, que no son
    ni CSV tabular ni JSON estructurado. El parseo semántico (CEF ->
    OCSF) vive en app/ocsf, no aquí — esta capa solo da fe de qué
    contenía el fichero, byte a byte, que es lo que importa para la
    cadena de custodia.
    """
    path = Path(path)
    events: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if max_lines is not None and i >= max_lines:
                break
            line = line.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            events.append({"raw_line": line})
    return _finalize(source_name, path, events)


SOURCE_READERS = {
    "cicids2017": lambda path, nrows=None: read_clean_csv("cicids2017", path, nrows),
    "unsw_nb15": lambda path, nrows=None: read_clean_csv("unsw_nb15", path, nrows),
    "kitsune": lambda path, nrows=None: read_clean_csv("kitsune", path, nrows),
    "suricata_eve": lambda path, nrows=None: read_jsonl("suricata_eve", path, max_lines=nrows),
    "firewall_cef": lambda path, nrows=None: read_text_lines("firewall_cef", path, max_lines=nrows),
}


def read_source(source_name: str, path: str | Path, nrows: int | None = None) -> IngestionResult:
    """Punto de entrada único: despacha al lector correcto según
    source_name. Lanza ValueError si la fuente no está soportada,
    en vez de fallar silenciosamente con un lector incorrecto."""
    if source_name not in SOURCE_READERS:
        raise ValueError(
            f"Fuente '{source_name}' no soportada. Fuentes disponibles: "
            f"{list(SOURCE_READERS.keys())}"
        )
    return SOURCE_READERS[source_name](path, nrows=nrows)
