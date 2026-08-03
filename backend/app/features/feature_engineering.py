"""
Feature Engineering
=====================

Convierte eventos ya normalizados a OCSF `Network Activity`
(app/ocsf/mappers.py) en vectores de características numéricas aptos
para XGBoost.

Diseño: en vez de mantener una lista fija de columnas por dataset
(que ya vive, de forma dispersa, en cada CSV distinto), se extraen
TODAS las columnas numéricas presentes en `unmapped.raw_flow_features`
más los campos ya normalizados de `connection_info`/`traffic`. Esto
es intencionadamente igual para las tres fuentes del TFM1: el propio
evento OCSF ya abstrae la heterogeneidad de columnas entre datasets,
así que esta capa no necesita saber "estoy procesando CICIDS" o
"estoy procesando UNSW" — solo necesita números.

La etiqueta (label, attack_cat) se extrae por separado con
`extract_label`, nunca se incluye en el vector de features: incluirla
sería fuga de la variable objetivo (data leakage).
"""

from __future__ import annotations

from typing import Any

import numpy as np


# Nombres de campo conocidos como timestamps ABSOLUTOS (no duraciones ni
# tasas), excluidos deliberadamente del vector de features. Motivo
# empírico, no teórico: en el dataset Kitsune, entrenar incluyendo
# 'time' producía un F1 macro de 0.98 que caía a 0.66 al excluirlo — el
# modelo no aprendía patrones de tráfico, aprendía "en qué sesión de
# captura ocurrió el flujo", porque cada attack_cat se capturó en una
# ventana temporal separada. 'duration'/'dur' NO se excluyen: son
# diferencias de tiempo (features legítimas de flujo), no marcas de
# tiempo absolutas.
_TIMESTAMP_LEAKAGE_FIELDS = {"time", "timestamp", "stime", "ltime", "first_seen"}


def _is_numeric(value: Any) -> bool:
    if isinstance(value, bool):
        return False  # bool es subtipo de int en Python; lo tratamos aparte
    return isinstance(value, (int, float)) and not isinstance(value, complex)


def ocsf_event_to_feature_dict(ocsf_event: dict[str, Any]) -> dict[str, float]:
    """Extrae un diccionario {nombre_feature: valor_numérico} de un
    evento OCSF Network Activity. Valores no numéricos se descartan
    (no se inventan codificaciones aquí); NaN/inf se sustituyen por 0.0
    para que XGBoost no falle por valores no finitos.
    """
    unmapped = ocsf_event.get("unmapped", {})
    raw = unmapped.get("raw_flow_features", {})

    candidates: dict[str, Any] = dict(raw)
    candidates.update(ocsf_event.get("connection_info", {}))
    candidates.update(ocsf_event.get("traffic", {}))

    features: dict[str, float] = {}
    for key, value in candidates.items():
        if key in ("attack_cat", "label"):
            continue
        if key in _TIMESTAMP_LEAKAGE_FIELDS:
            continue
        if _is_numeric(value):
            v = float(value)
            if not np.isfinite(v):
                v = 0.0
            features[key] = v

    return features


def extract_label(ocsf_event: dict[str, Any]) -> int:
    """Extrae la etiqueta binaria (0=Normal, 1=ataque) de un evento
    OCSF ya etiquetado. Lanza KeyError si el evento no tiene label
    (p.ej. si es un Detection Finding sin etiquetar: ese caso pasa
    por inference, no por aquí)."""
    unmapped = ocsf_event.get("unmapped", {})
    if "label" not in unmapped:
        raise KeyError(
            "El evento OCSF no tiene 'label' en unmapped. extract_label solo "
            "aplica a eventos ya etiquetados (Network Activity del TFM1), no a "
            "hallazgos sin etiquetar (Detection Finding)."
        )
    return int(unmapped["label"])


def build_feature_matrix(
    ocsf_events: list[dict[str, Any]],
    feature_names: list[str] | None = None,
) -> tuple[np.ndarray, list[str]]:
    """Construye una matriz numérica (n_eventos x n_features) a partir
    de una lista de eventos OCSF.

    Si `feature_names` se proporciona (caso de inferencia, donde el
    conjunto de columnas debe coincidir EXACTAMENTE con el usado en
    entrenamiento), se fuerza ese orden y las columnas ausentes en un
    evento concreto se rellenan con 0.0. Si no se proporciona (caso de
    entrenamiento), se infiere como la unión ordenada de todas las
    features vistas.
    """
    per_event_features = [ocsf_event_to_feature_dict(e) for e in ocsf_events]

    if feature_names is None:
        all_keys: set[str] = set()
        for f in per_event_features:
            all_keys.update(f.keys())
        feature_names = sorted(all_keys)

    matrix = np.zeros((len(ocsf_events), len(feature_names)), dtype=float)
    for i, feats in enumerate(per_event_features):
        for j, name in enumerate(feature_names):
            matrix[i, j] = feats.get(name, 0.0)

    return matrix, feature_names
