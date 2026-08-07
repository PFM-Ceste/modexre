"""
Tests de app/features/feature_engineering.py::build_feature_matrix
======================================================================

Decisión final (0.0), tras probar y descartar dos alternativas con
np.nan -- ver el historial completo documentado en el docstring de
build_feature_matrix. Resumen:

  1. 0.0 (esta versión): mejor resultado real validado (model_v3,
     7/20 eventos de un barrido de red real como Reconnaissance).
  2. np.nan sin reentrenar: 0/20, descartado.
  3. np.nan CON reentrenamiento (model_v4): 0/20, peor todavía --
     "NaN en duration" se aprendió como prior espurio hacia la clase
     mayoritaria (Normal), confirmado con SHAP.

Estos tests fijan el comportamiento actual (relleno con 0.0) como
contrato explícito, para que un cambio futuro sea una decisión
deliberada y documentada, no un descuido.
"""

import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.features.feature_engineering import build_feature_matrix, ocsf_event_to_feature_dict


def _event_with_features(**raw_flow_features):
    return {"unmapped": {"raw_flow_features": raw_flow_features}}


def test_missing_feature_columns_are_filled_with_zero():
    """Comportamiento vigente, deliberado tras evaluar alternativas:
    una columna ausente en un evento concreto (p.ej. duration/packets
    en evidencia CEF) se rellena con 0.0, no con NaN."""
    event = _event_with_features(
        agg_distinct_dst_hosts=20, agg_distinct_dst_ports=4, agg_events_in_window=20,
    )
    feature_names = ["duration", "packets_in", "packets_out",
                      "agg_distinct_dst_hosts", "agg_distinct_dst_ports", "agg_events_in_window"]
    matrix, names = build_feature_matrix([event], feature_names=feature_names)

    assert names == feature_names
    assert matrix[0, names.index("duration")] == 0.0
    assert matrix[0, names.index("packets_in")] == 0.0
    assert matrix[0, names.index("packets_out")] == 0.0
    assert matrix[0, names.index("agg_distinct_dst_hosts")] == 20.0
    assert not np.isnan(matrix).any()


def test_genuinely_zero_value_is_preserved_as_zero():
    """Un valor real de 0 (p.ej. 0 bytes salientes) se comporta igual
    que una columna ausente con el esquema actual -- ambos dan 0.0.
    Esta ambigüedad es precisamente la limitación documentada; este
    test fija el comportamiento actual, no lo valida como ideal."""
    event = _event_with_features(duration=0.0, packets_in=5, packets_out=0.0)
    feature_names = ["duration", "packets_in", "packets_out"]
    matrix, names = build_feature_matrix([event], feature_names=feature_names)

    assert matrix[0, names.index("duration")] == 0.0
    assert matrix[0, names.index("packets_out")] == 0.0


def test_training_mode_without_feature_names_infers_columns():
    """En modo entrenamiento (feature_names=None), las columnas se
    infieren de la unión de todos los eventos vistos."""
    events = [
        _event_with_features(duration=1.5, packets_in=3),
        _event_with_features(duration=2.0, packets_in=7),
    ]
    matrix, names = build_feature_matrix(events)
    assert not np.isnan(matrix).any()
    assert set(names) == {"duration", "packets_in"}


def test_ocsf_event_to_feature_dict_cleans_nan_inf_in_present_values():
    """Si un valor SÍ está presente pero es NaN/inf (p.ej. una
    división por cero calculada aguas arriba), se sustituye por 0.0
    -- distinto del caso de una columna directamente ausente, que
    build_feature_matrix gestiona por separado."""
    event = {"unmapped": {"raw_flow_features": {"duration": float("inf")}}}
    feats = ocsf_event_to_feature_dict(event)
    assert feats["duration"] == 0.0
