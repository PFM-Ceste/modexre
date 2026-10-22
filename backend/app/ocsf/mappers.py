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


# Alias de columna para los extremos de la conexión y la marca
# temporal, por orden de preferencia (gana el primero que aparezca).
#
# Los CSV limpios del TFM1 no usan un nombre único para estos campos:
# la limpieza de Kitsune conserva `src`/`sport`/`dst`/`dport`/`time`,
# la de CICIDS2017 `source_ip`/`destination_ip`/`timestamp`, y UNSW-NB15
# trae `srcip`/`dsport`/`stime` en su esquema nativo. Resolverlos aquí
# por alias evita tener que declarar un dialecto por fuente, y permite
# además que un CSV de flujo exportado por un CICFlowMeter ajeno
# (generic_flow_csv) aporte sus IP sin configuración previa.
_SRC_IP_ALIASES = ("src_ip", "source_ip", "srcip", "saddr", "ip_src", "source_address", "src")
_DST_IP_ALIASES = ("dst_ip", "destination_ip", "dstip", "daddr", "ip_dst", "destination_address", "dst")
_SRC_PORT_ALIASES = ("src_port", "source_port", "srcport", "sport")
_DST_PORT_ALIASES = ("dst_port", "destination_port", "dstport", "dsport", "dport")
_TIMESTAMP_ALIASES = ("time", "timestamp", "stime", "flow_start", "first_seen", "ts")

# Valores centinela que las capas de limpieza usan para "no disponible"
# en columnas de IP/puerto (p.ej. un paquete sin puerto en Kitsune se
# exporta como -1). Tratarlos como un valor real inflaría
# `agg_distinct_dst_ports`, que contaría "-1" como un puerto distinto.
_SENTINEL_VALUES = {"", "-1", "nan", "none", "null", "0.0.0.0", "unknown", "n/a"}


def _clean_endpoint_value(value: Any) -> Any:
    """Devuelve `value` saneado, o None si representa un dato ausente
    (None, NaN o uno de los centinelas de _SENTINEL_VALUES).

    Conserva el tipo original en los valores no textuales: una marca
    temporal epoch (1540450900.0) tiene que seguir siendo numérica,
    porque flow_aggregation._parse_timestamp la interpreta como epoch
    solo si es int/float -- convertida a texto intentaría leerla como
    fecha ISO, fallaría, y la agregación volvería a quedarse a cero.
    """
    if _is_missing(value):
        return None
    if str(value).strip().lower() in _SENTINEL_VALUES:
        return None
    if isinstance(value, str):
        return value.strip()
    return value


def _first_present(event: dict[str, Any], aliases: tuple[str, ...]) -> Any:
    """Primer alias presente en `event` con un valor utilizable."""
    for name in aliases:
        if name in event:
            cleaned = _clean_endpoint_value(event[name])
            if cleaned is not None:
                return cleaned
    return None


def _as_port(value: Any) -> Any:
    """Normaliza un puerto a int cuando es posible, para que el conteo
    de puertos distintos no trate 80 y "80" como dos valores."""
    if value is None:
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return value


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

    ocsf_event: dict[str, Any] = {
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

    # Extremos de la conexión y marca temporal.
    #
    # Hasta aquí estos campos quedaban únicamente dentro de
    # `unmapped.raw_flow_features`, donde ninguna capa posterior los
    # buscaba: el informe pericial lee `src_endpoint.ip` (y mostraba
    # "n/d"), y -- más grave -- `features/flow_aggregation.py` agrupa
    # los eventos por `src_endpoint.ip` y los ordena por `time`, de
    # modo que sin ambos campos las cuatro features de agregación
    # (agg_distinct_dst_hosts/ports, agg_events_in_window,
    # agg_events_per_second) salían a cero en TODO CSV analizado en
    # modo Formal. Eso dejaba al clasificador decidiendo con 3 de las
    # 7 features de model_v3, y hacía invisible justamente el patrón
    # que esas features existen para detectar (barrido horizontal /
    # escaneo de puertos).
    #
    # Se emiten con los mismos nombres de campo que ya usan
    # pcap_flow.py, detection_finding.py y firewall_cef.py, para que
    # toda fuente llegue al clasificador con la misma forma.
    #
    # La adición es deliberadamente aditiva: `raw_flow_features` se
    # deja intacto, así que el vector de features de los modelos ya
    # certificados no cambia (las IP son texto y feature_engineering
    # descarta los valores no numéricos; `time` está excluido ahí por
    # el hallazgo de fuga temporal de Kitsune, y seguirlo estando es
    # justo lo que permite publicarlo aquí sin reintroducir esa fuga).
    src_ip = _first_present(event, _SRC_IP_ALIASES)
    src_port = _as_port(_first_present(event, _SRC_PORT_ALIASES))
    dst_ip = _first_present(event, _DST_IP_ALIASES)
    dst_port = _as_port(_first_present(event, _DST_PORT_ALIASES))

    src_endpoint = {k: v for k, v in (("ip", src_ip), ("port", src_port)) if v is not None}
    dst_endpoint = {k: v for k, v in (("ip", dst_ip), ("port", dst_port)) if v is not None}
    if src_endpoint:
        ocsf_event["src_endpoint"] = src_endpoint
    if dst_endpoint:
        ocsf_event["dst_endpoint"] = dst_endpoint

    event_time = _first_present(event, _TIMESTAMP_ALIASES)
    if event_time is not None:
        ocsf_event["time"] = event_time

    return ocsf_event


def normalize_to_ocsf(source_name: str, event: dict[str, Any], require_label: bool = True) -> dict[str, Any]:
    """Punto de entrada único de normalización a OCSF."""
    if source_name not in _KNOWN_FIELDS_BY_SOURCE:
        raise ValueError(
            f"No hay mapper OCSF para la fuente '{source_name}'. "
            f"Fuentes soportadas: {list(_KNOWN_FIELDS_BY_SOURCE.keys())}"
        )
    return event_to_ocsf(source_name, event, require_label=require_label)
