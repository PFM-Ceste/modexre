"""Regresión: los extremos de la conexión en CSV (decisión de diseño 5)
=========================================================================

`app/ocsf/mappers.py` no emitía `src_endpoint`/`dst_endpoint`/`time`, a
diferencia de los mappers de PCAP, Suricata y CEF. Como ese mapper es
el que normaliza TODO CSV, las IP del fichero quedaban enterradas en
`unmapped.raw_flow_features`, donde ninguna capa posterior las buscaba.

La consecuencia visible era que el informe pericial mostraba "IPs de
origen: n/d". La consecuencia grave era silenciosa:
`features/flow_aggregation.py` agrupa por `src_endpoint.ip` y ordena
por `time`, así que sin esos campos las cuatro features de agregación
salían a cero en todo CSV analizado en modo Formal -- el clasificador
decidía con 3 de las 7 features de model_v3, y el patrón de barrido
horizontal que esas features existen para detectar era invisible.

Estos tests fijan el comportamiento corregido para que no pueda
reintroducirse sin que falle la batería.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.features.flow_aggregation import enrich_with_aggregation
from app.ocsf.mappers import event_to_ocsf


# --- Alias de columna por dialecto de limpieza -----------------------

def test_dialecto_kitsune_src_sport_dst_dport():
    """Limpieza de Kitsune: src / sport / dst / dport / time."""
    event = {
        "attack_cat": "DDoS", "label": 1, "time": 1540450900.0,
        "src": "192.168.2.113", "sport": 43034,
        "dst": "122.226.84.253", "dport": 443,
    }
    ocsf = event_to_ocsf("kitsune", event)
    assert ocsf["src_endpoint"] == {"ip": "192.168.2.113", "port": 43034}
    assert ocsf["dst_endpoint"] == {"ip": "122.226.84.253", "port": 443}


def test_dialecto_cicids_source_ip_destination_ip():
    """Limpieza de CICIDS2017: source_ip / destination_ip / timestamp."""
    event = {
        "attack_cat": "PortScan", "label": 1,
        "source_ip": "10.0.0.66", "source_port": 50611,
        "destination_ip": "192.168.1.10", "destination_port": 22,
        "timestamp": "2026-10-21T09:00:00",
    }
    ocsf = event_to_ocsf("cicids2017", event)
    assert ocsf["src_endpoint"]["ip"] == "10.0.0.66"
    assert ocsf["dst_endpoint"]["ip"] == "192.168.1.10"
    assert ocsf["time"] == "2026-10-21T09:00:00"


def test_dialecto_unsw_srcip_dsport():
    """Esquema nativo de UNSW-NB15: srcip / dstip / dsport / stime."""
    event = {
        "attack_cat": "Reconnaissance", "label": 1,
        "srcip": "175.45.176.0", "sport": 13284,
        "dstip": "149.171.126.16", "dsport": 80, "stime": 1421927414,
    }
    ocsf = event_to_ocsf("unsw_nb15", event)
    assert ocsf["src_endpoint"]["ip"] == "175.45.176.0"
    assert ocsf["dst_endpoint"] == {"ip": "149.171.126.16", "port": 80}
    assert ocsf["time"] == 1421927414


# --- Tipos y valores centinela ---------------------------------------

def test_epoch_conserva_tipo_numerico():
    """Una marca epoch debe seguir siendo numérica: convertida a texto,
    flow_aggregation la leería como fecha ISO, fallaría, y el evento
    quedaría fuera de la agregación causal sin aviso."""
    ocsf = event_to_ocsf("kitsune", {"attack_cat": "Normal", "label": 0,
                                      "time": 1540450900.192, "src": "10.0.0.1"})
    assert isinstance(ocsf["time"], float)


def test_puerto_menos_uno_se_trata_como_ausente():
    """Kitsune exporta -1 cuando el paquete no lleva puerto. Contarlo
    como un puerto real inflaría agg_distinct_dst_ports."""
    ocsf = event_to_ocsf("kitsune", {
        "attack_cat": "DDoS", "label": 1, "time": 1540450900.0,
        "src": "192.168.2.113", "sport": -1, "dst": "8.8.8.8", "dport": -1,
    })
    assert ocsf["src_endpoint"] == {"ip": "192.168.2.113"}
    assert ocsf["dst_endpoint"] == {"ip": "8.8.8.8"}


def test_puerto_textual_se_normaliza_a_entero():
    """80 y "80" no deben contar como dos puertos distintos."""
    ocsf = event_to_ocsf("kitsune", {"attack_cat": "Normal", "label": 0,
                                      "src": "10.0.0.1", "dst": "10.0.0.2", "dport": "80"})
    assert ocsf["dst_endpoint"]["port"] == 80


def test_csv_sin_columnas_de_ip_no_emite_extremos():
    """Un CSV sin IP (Kitsune crudo, solo estadísticas derivadas) debe
    seguir normalizándose sin inventar extremos vacíos."""
    ocsf = event_to_ocsf("cicids2017", {"attack_cat": "Normal", "label": 0,
                                         "flow_duration": 1000, "protocol": 6})
    assert "src_endpoint" not in ocsf
    assert "dst_endpoint" not in ocsf


def test_raw_flow_features_se_conserva_intacto():
    """La corrección es aditiva: el vector de features de los modelos ya
    certificados no puede cambiar por emitir los extremos."""
    event = {"attack_cat": "Normal", "label": 0, "src": "10.0.0.1",
             "dst": "10.0.0.2", "dport": 443, "alguna_metrica": 3.5}
    ocsf = event_to_ocsf("kitsune", event)
    assert ocsf["unmapped"]["raw_flow_features"]["alguna_metrica"] == 3.5
    assert ocsf["unmapped"]["raw_flow_features"]["src"] == "10.0.0.1"


# --- Regresión de extremo a extremo ----------------------------------

def test_barrido_horizontal_desde_csv_produce_agregacion_no_nula():
    """El guardián real del hallazgo: un barrido horizontal descrito en
    un CSV debe generar señal de agregación. Antes de la corrección,
    las cuatro features salían a cero y el barrido era indetectable."""
    base = 1540450900.0
    eventos = [
        event_to_ocsf("kitsune", {
            "attack_cat": "Reconnaissance", "label": 1,
            "time": base + i * 0.5, "src": "192.168.2.113",
            "dst": f"10.0.0.{10 + i}", "dport": 80,
        })
        for i in range(20)
    ]
    enriquecidos = enrich_with_aggregation(eventos, window_seconds=60.0)
    ultimo = enriquecidos[-1]["unmapped"]["raw_flow_features"]

    assert ultimo["agg_distinct_dst_hosts"] == 20, "no se ven los 20 destinos del barrido"
    assert ultimo["agg_events_in_window"] == 20
    assert ultimo["agg_events_per_second"] > 0
    # Causalidad: el primer evento solo puede verse a sí mismo.
    assert enriquecidos[0]["unmapped"]["raw_flow_features"]["agg_distinct_dst_hosts"] == 1


def test_trafico_normal_no_se_confunde_con_barrido():
    """Contraste del test anterior: muchos eventos al MISMO destino no
    deben producir señal de barrido, solo de volumen."""
    base = 1540450900.0
    eventos = [
        event_to_ocsf("kitsune", {
            "attack_cat": "Normal", "label": 0, "time": base + i * 0.5,
            "src": "192.168.2.50", "dst": "192.168.2.1", "dport": 443,
        })
        for i in range(20)
    ]
    enriquecidos = enrich_with_aggregation(eventos, window_seconds=60.0)
    ultimo = enriquecidos[-1]["unmapped"]["raw_flow_features"]

    assert ultimo["agg_distinct_dst_hosts"] == 1
    assert ultimo["agg_distinct_dst_ports"] == 1
    assert ultimo["agg_events_in_window"] == 20


# --- Formatos de marca temporal --------------------------------------

def test_timestamp_cicids_con_barras_se_interpreta():
    """CICIDS2017 exporta `timestamp` como "7/7/2017 3:30" (mes primero,
    sin segundos ni ceros de relleno). fromisoformat() lo rechaza, así
    que antes el evento quedaba fuera de la agregación causal sin aviso
    y el dataset llegaba al clasificador con las cuatro features a cero
    aunque conservara las IP."""
    from app.features.flow_aggregation import _parse_timestamp
    from datetime import datetime, timezone

    ts = _parse_timestamp("7/7/2017 3:30")
    assert ts is not None, "no se interpreta el formato de CICIDS2017"
    assert datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M") == "2017-07-07 03:30"


def test_timestamp_admite_los_formatos_de_las_tres_fuentes():
    """Un mismo vector de agregación debe poder construirse desde los
    tres dialectos de limpieza, que traen la fecha de formas distintas."""
    from app.features.flow_aggregation import _parse_timestamp

    assert _parse_timestamp("7/7/2017 3:30") is not None        # CICIDS2017
    assert _parse_timestamp(1540450900.192) is not None          # Kitsune (epoch)
    assert _parse_timestamp("1421927414") is not None            # UNSW-NB15 (stime)
    assert _parse_timestamp("2026-10-21T09:00:00") is not None   # PCAP / Suricata (ISO)
    assert _parse_timestamp("2017-07-07 03:30:00") is not None   # ISO con espacio


def test_timestamp_ininteligible_sigue_devolviendo_none():
    """No se debe inventar una ventana temporal para un valor que no es
    una fecha: el evento se clasifica igual, solo que sin agregación."""
    from app.features.flow_aggregation import _parse_timestamp

    assert _parse_timestamp("no es una fecha") is None
    assert _parse_timestamp("") is None
    assert _parse_timestamp(None) is None
    assert _parse_timestamp(True) is None  # un bool es int, pero no es una fecha


def test_barrido_con_fechas_cicids_produce_agregacion():
    """Regresión de extremo a extremo con el formato de CICIDS2017."""
    from app.features.flow_aggregation import enrich_with_aggregation

    eventos = [
        event_to_ocsf("cicids2017", {
            "attack_cat": "PortScan", "label": 1,
            "source_ip": "10.0.0.66", "destination_ip": "192.168.1.5",
            "destination_port": 1000 + i,
            "timestamp": f"7/7/2017 3:{30 + i:02d}",
        })
        for i in range(20)
    ]
    enriquecidos = enrich_with_aggregation(eventos, window_seconds=3600.0)
    ultimo = enriquecidos[-1]["unmapped"]["raw_flow_features"]
    assert ultimo["agg_distinct_dst_ports"] == 20
    assert ultimo["agg_events_in_window"] == 20
