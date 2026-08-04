"""
Agregación por Origen y Ventana Temporal
============================================

Cierra el Hallazgo 3 (ver README): la clasificación evento a evento
no puede detectar un patrón de escaneo, porque un escaneo se define
por el comportamiento de un origen A LO LARGO de varios eventos
(muchos puertos/hosts distintos tocados en poco tiempo), no por las
características de un único flujo aislado.

Esta capa se ejecuta DESPUÉS de la normalización OCSF y ANTES de la
extracción de features: para cada evento, calcula estadísticas
agregadas sobre los eventos del MISMO origen (`src_endpoint.ip`)
dentro de una ventana temporal causal (solo eventos anteriores o
simultáneos al evento actual — nunca del futuro, que sería
metodológicamente inválido para un sistema pensado para operar en
tiempo real) y las añade al propio evento OCSF, de donde
features/feature_engineering.py las recoge automáticamente como
cualquier otra característica numérica.

Variables añadidas (bajo unmapped.raw_flow_features, prefijo
'agg_' para no colisionar con nombres de features ya existentes):

  - agg_distinct_dst_ports: nº de puertos destino distintos tocados
    por este origen en la ventana.
  - agg_distinct_dst_hosts: nº de hosts destino distintos tocados.
  - agg_events_in_window: nº total de eventos de este origen en la
    ventana (volumen de actividad).
  - agg_events_per_second: lo mismo que agg_events_in_window, pero
    normalizado por el tiempo REALMENTE observado hasta ese evento
    (no por window_seconds fijo). Ver nota de diseño más abajo.

Nota de diseño — normalización del volumen de actividad
---------------------------------------------------------
`agg_events_in_window` es un conteo absoluto, no relativo a cuánto
tiempo se ha observado realmente ese origen. Esto produce una
distorsión conocida en capturas más cortas que window_seconds: un
origen activo durante TODA una captura corta (p.ej. 16s) acumula un
`agg_events_in_window` similar al de un origen activo durante una
ventana completa de ataque, aunque su comportamiento sea benigno —
simplemente porque la ventana de observación disponible es más corta
que la ventana de diseño. Un modelo entrenado sobre capturas largas
(como los datasets de referencia) puede así sobre-disparar en
capturas cortas de evidencia real.

`agg_events_per_second` corrige esto dividiendo por el tiempo
realmente transcurrido y observado para ese origen hasta el evento
actual (acotado por window_seconds), no por la ventana nominal. Es
una magnitud comparable entre capturas de duración muy distinta.

IMPORTANTE — compatibilidad con modelos ya certificados: este campo
se AÑADE, no sustituye a `agg_events_in_window`. `model_v1` fue
certificado sin `agg_events_per_second` en su `feature_names`, por lo
que introducir este campo no altera su comportamiento ni invalida su
hash de integridad (feature_engineering.py solo toma las columnas que
el manifest del modelo declara). Para que un modelo lo use de verdad
hace falta recertificar una nueva versión que lo incluya en el
entrenamiento.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

DEFAULT_WINDOW_SECONDS = 60.0

# Suelo mínimo de tiempo observado, para evitar divisiones por un
# intervalo casi nulo (p.ej. el primer evento de una ráfaga, donde el
# tiempo observado es 0): un solo evento no debe producir una tasa
# artificialmente altísima solo por dividir entre un denominador muy
# pequeño.
_MIN_OBSERVED_SECONDS = 1.0


def _parse_timestamp(raw: Any) -> Optional[float]:
    """Convierte el timestamp de un evento OCSF (ISO 8601, en 'time'
    o 'unmapped.first_seen') a epoch en segundos. Devuelve None si no
    hay timestamp interpretable (el evento se excluye de la
    agregación causal, no se le asigna una ventana arbitraria)."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError):
        return None


def _event_timestamp(event: dict[str, Any]) -> Optional[float]:
    raw = event.get("time") or event.get("unmapped", {}).get("first_seen")
    return _parse_timestamp(raw)


def _event_src_ip(event: dict[str, Any]) -> Optional[str]:
    return event.get("src_endpoint", {}).get("ip")


def _event_dst_ip(event: dict[str, Any]) -> Optional[str]:
    return event.get("dst_endpoint", {}).get("ip")


def _event_dst_port(event: dict[str, Any]) -> Optional[Any]:
    return event.get("dst_endpoint", {}).get("port")


def enrich_with_aggregation(
    ocsf_events: list[dict[str, Any]],
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
) -> list[dict[str, Any]]:
    """Enriquece una lista de eventos OCSF con estadísticas agregadas
    por origen y ventana temporal causal.

    No modifica los eventos originales in-place (devuelve copias),
    para que la operación sea auditable de forma independiente en la
    cadena de custodia (input_hash del paso siguiente se calcula
    sobre el resultado de esta función, no sobre el original).

    Eventos sin src_ip o sin timestamp interpretable se enriquecen
    con contadores a 0 (no se excluyen del resultado: siguen
    clasificándose, solo sin señal de agregación).
    """
    # Índice: por src_ip, lista de (timestamp, dst_ip, dst_port) de
    # TODOS los eventos con timestamp válido, para poder consultar la
    # ventana causal de cada evento en O(n) por evento.
    by_src: dict[str, list[tuple[float, Optional[str], Any]]] = {}
    for event in ocsf_events:
        src_ip = _event_src_ip(event)
        ts = _event_timestamp(event)
        if src_ip is None or ts is None:
            continue
        by_src.setdefault(src_ip, []).append((ts, _event_dst_ip(event), _event_dst_port(event)))

    for records in by_src.values():
        records.sort(key=lambda r: r[0])

    enriched: list[dict[str, Any]] = []
    for event in ocsf_events:
        src_ip = _event_src_ip(event)
        ts = _event_timestamp(event)

        agg_ports, agg_hosts, agg_count, agg_rate = 0, 0, 0, 0.0
        if src_ip is not None and ts is not None:
            window_start = ts - window_seconds
            in_window = [r for r in by_src[src_ip] if window_start <= r[0] <= ts]
            agg_count = len(in_window)
            agg_ports = len({r[2] for r in in_window if r[2] is not None})
            agg_hosts = len({r[1] for r in in_window if r[1] is not None})

            # Tiempo realmente observado para este origen hasta el
            # evento actual (nunca mayor que window_seconds): la
            # diferencia entre el timestamp actual y el más antiguo
            # dentro de la ventana. Con un solo evento en la ventana,
            # ese intervalo es 0 -> se aplica el suelo mínimo.
            oldest_in_window = in_window[0][0]
            observed_span = max(ts - oldest_in_window, 0.0)
            observed_span = max(observed_span, _MIN_OBSERVED_SECONDS)
            agg_rate = agg_count / observed_span

        new_event = dict(event)
        new_unmapped = dict(event.get("unmapped", {}))
        new_raw_features = dict(new_unmapped.get("raw_flow_features", {}))
        new_raw_features.update({
            "agg_distinct_dst_ports": agg_ports,
            "agg_distinct_dst_hosts": agg_hosts,
            "agg_events_in_window": agg_count,
            "agg_events_per_second": round(agg_rate, 6),
        })
        new_unmapped["raw_flow_features"] = new_raw_features
        new_unmapped["aggregation_window_seconds"] = window_seconds
        new_event["unmapped"] = new_unmapped

        enriched.append(new_event)

    return enriched
