"""
Normalización a OCSF (Open Cybersecurity Schema Framework)
=============================================================

Traduce eventos ya limpios (salida de los notebooks FULL_* del TFM1:
`attack_cat` + `label` normalizados como dos primeras columnas,
nombres de columna en snake_case, sin IP/puerto tras la limpieza) a
la clase OCSF `Network Activity` (category_uid=4, class_uid=4001).

La taxonomía de `attack_cat` es la ya fijada y validada en el TFM1
(ver FULL_MachineLearningCVE_Descarga_CTGAN_Definitivo.ipynb,
FULL_UNSW_NB15_Descarga_Definitivo.ipynb,
FULL_KITSUNE_Descarga_Definitivo.ipynb): un conjunto cerrado
(ALLOWED_ATTACK_CATEGORIES) al que cualquier valor no reconocido cae
a "Generic". No se reimplementa aquí el normalizador completo de
attack_cat (eso vive en la capa de ingesta/limpieza previa, ya
resuelta en el TFM1); este módulo asume que attack_cat ya llega
normalizado a ese conjunto cerrado.

Campos sin equivalente directo en el esquema OCSF core (el grueso de
las características de flujo de cada dataset) se preservan íntegros
bajo `unmapped`, siguiendo la convención propia del estándar OCSF
para no perder información de la fuente original.

Referencia de esquema: https://schema.ocsf.io/1.4.0/classes/network_activity
"""

from __future__ import annotations

import math
from typing import Any


def _is_missing(value: Any) -> bool:
    """True si `value` representa un dato ausente: None, o NaN (float).

    Necesario porque un hueco vacío en un CSV leído con pandas se
    convierte en `float('nan')`, no en `None` -- y `nan is not None`
    es True, así que un simple chequeo `is not None` deja pasar el
    NaN como si fuera un valor real, para acabar convertido en 0.0 más
    adelante (ver ocsf_event_to_feature_dict en feature_engineering.py).
    Esto impedía distinguir "ausente" de "valor real cero" incluso
    cuando el dato de origen ya representaba correctamente la
    ausencia (p.ej. una columna duration/packets vacía en un CSV de
    entrenamiento que simula cobertura parcial tipo CEF)."""
    if value is None:
        return True
    if isinstance(value, float) and math.isnan(value):
        return True
    return False

NETWORK_ACTIVITY_CLASS_UID = 4001
NETWORK_ACTIVITY_CATEGORY_UID = 4

# activity_id: 6 = "Traffic" (genérico, válido para flujos ya agregados
# como los que producen CICFlowMeter/Argus, donde no distinguimos
# open/close/refuse a nivel de conexión individual).
DEFAULT_ACTIVITY_ID = 6

# Taxonomía cerrada de attack_cat, tal como se fija en los notebooks
# FULL_* del TFM1. Cualquier valor fuera de este conjunto es un error
# de ingesta anterior a esta capa (debería haber caído a "Generic"
# ya en la limpieza), así que aquí se valida en vez de asumir.
ALLOWED_ATTACK_CATEGORIES = {
    "Normal", "Fuzzers", "Exploits", "DoS", "Reconnaissance", "Generic",
    "Analysis", "Shellcode", "Backdoors", "DDoS", "PortScan", "MitM",
    "BruteForce",
    # Ampliación (ver notebooks de limpieza corregidos / hallazgo de
    # barrido horizontal en el pcap real case_2026_001): estas 6
    # categorías son nativas de CICIDS2017 (Bot, Web Attack – Xss,
    # Web Attack – Sql Injection, Heartbleed, Infiltration) y de
    # UNSW-NB15 (Worms), y antes se perdían dentro de "Generic" al no
    # estar en esta lista. Se recuperan como clases propias para no
    # descartar señal real que el modelo sí puede aprender a
    # distinguir.
    "Bot", "Worms", "Heartbleed", "Infiltration",
    "Web Attack – Xss", "Web Attack – Sql Injection",
}

# Campos de flujo conocidos por fuente, para extraerlos a los bloques
# OCSF `connection_info` / `traffic` cuando existen. El resto de
# columnas (la mayoría) se preserva sin más en `unmapped`.
_KNOWN_FIELDS_BY_SOURCE: dict[str, dict[str, str]] = {
    "cicids2017": {
        "protocol": "protocol",
        "duration": "flow_duration",
        "packets_out": "total_fwd_packets",
        "packets_in": "total_backward_packets",
        "bytes_out": "total_length_of_fwd_packets",
        "bytes_in": "total_length_of_bwd_packets",
    },
    "unsw_nb15": {
        "protocol": "proto",
        "duration": "dur",
        "packets_out": "spkts",
        "packets_in": "dpkts",
        "bytes_out": "sbytes",
        "bytes_in": "dbytes",
    },
    # Kitsune no conserva metadatos de flujo tras la limpieza (solo
    # estadísticas derivadas paquete a paquete), así que no hay campos
    # conocidos que extraer; todo queda en unmapped.
    "kitsune": {},
    # CSV de flujo de origen desconocido (p.ej. exportado por un
    # CICFlowMeter propio de una empresa, sin dialecto reconocido):
    # sin alias conocidos, todas las columnas numéricas se preservan
    # tal cual en unmapped.raw_flow_features.
    "generic_flow_csv": {},
}


class TaxonomyError(ValueError):
    """attack_cat no pertenece a la taxonomía cerrada esperada."""


def _validate_attack_cat(value: Any) -> str:
    attack_cat = str(value).strip()
    if attack_cat not in ALLOWED_ATTACK_CATEGORIES:
        raise TaxonomyError(
            f"attack_cat='{attack_cat}' no pertenece a la taxonomía cerrada "
            f"{sorted(ALLOWED_ATTACK_CATEGORIES)}. Esto indica un evento que no "
            f"pasó por la normalización de taxonomía previa (fuera del alcance "
            f"de este mapper)."
        )
    return attack_cat


def event_to_ocsf(source_name: str, event: dict[str, Any], require_label: bool = True) -> dict[str, Any]:
    """Mapea un evento de flujo (con o sin attack_cat/label) a OCSF
    Network Activity.

    Por defecto (`require_label=True`, comportamiento histórico e
    inalterado) exige que `event` contenga 'attack_cat'/'label', tal
    como las produce la capa de limpieza previa del TFM1, y lanza
    KeyError si faltan. Esto sigue siendo lo correcto para el modo
    Laboratorio con datasets de investigación ya etiquetados.

    Con `require_label=False`, admite evidencia REAL sin etiquetar
    (p.ej. un CSV de flujos exportado por el CICFlowMeter de una
    empresa, sin que nadie haya clasificado aún el tráfico): produce
    un evento OCSF sin 'attack_cat'/'label' en unmapped, con
    severity_id=1 (Informational) por defecto — la clasificación la
    dará después el modelo, no esta capa. Este es el modo que permite
    que MODEXRE trate cualquier evidencia, etiquetada o no, con el
    mismo pipeline de normalización.
    """
    has_label = "attack_cat" in event

    if not has_label:
        if require_label:
            raise KeyError(
                "El evento no contiene 'attack_cat'. Este mapper espera datos ya "
                "normalizados por la capa de limpieza previa (attack_cat/label "
                "como primeras columnas), no datos crudos sin procesar. Si se "
                "trata de evidencia real sin etiquetar, llama con "
                "require_label=False."
            )
        attack_cat = None
        is_attack = None  # desconocido: lo determinará el clasificador
    else:
        attack_cat = _validate_attack_cat(event["attack_cat"])
        is_attack = attack_cat != "Normal"

    known = _KNOWN_FIELDS_BY_SOURCE.get(source_name, {})
    connection_info: dict[str, Any] = {}
    if known.get("protocol") and event.get(known["protocol"]) is not None:
        connection_info["protocol_raw"] = event[known["protocol"]]
    if known.get("duration") and not _is_missing(event.get(known["duration"])):
        connection_info["duration"] = event[known["duration"]]

    traffic: dict[str, Any] = {}
    for ocsf_key in ("packets_out", "packets_in", "bytes_out", "bytes_in"):
        src_col = known.get(ocsf_key)
        if src_col and not _is_missing(event.get(src_col)):
            traffic[ocsf_key] = event[src_col]

    known_cols = set(known.values()) | {"attack_cat", "label"}

    unmapped: dict[str, Any] = {
        "source_dataset": source_name,
        "raw_flow_features": {
            k: v for k, v in event.items() if k not in known_cols
        },
    }
    if has_label:
        unmapped["attack_cat"] = attack_cat
        unmapped["label"] = event["label"]

    return {
        "class_uid": NETWORK_ACTIVITY_CLASS_UID,
        "category_uid": NETWORK_ACTIVITY_CATEGORY_UID,
        "activity_id": DEFAULT_ACTIVITY_ID,
        "severity_id": 1 if is_attack in (False, None) else 3,
        "connection_info": connection_info,
        "traffic": traffic,
        "metadata": {
            "product": {"name": source_name},
            "version": "1.4.0",
        },
        "unmapped": unmapped,
    }


def normalize_to_ocsf(source_name: str, event: dict[str, Any], require_label: bool = True) -> dict[str, Any]:
    """Punto de entrada único de normalización a OCSF."""
    if source_name not in _KNOWN_FIELDS_BY_SOURCE:
        raise ValueError(
            f"No hay mapper OCSF para la fuente '{source_name}'. "
            f"Fuentes soportadas: {list(_KNOWN_FIELDS_BY_SOURCE.keys())}"
        )
    return event_to_ocsf(source_name, event, require_label=require_label)
