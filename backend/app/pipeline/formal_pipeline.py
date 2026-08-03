"""
Orquestador del Modo FORMAL
==============================

Ata entre sí los componentes ya construidos (ingestion, ocsf,
features, models.classifier) y la cadena de custodia
(custody.chain.CustodyChain), de forma que CADA paso del análisis
pericial queda registrado como un eslabón verificable:

    ingest → ocsf_normalize → feature_extract → classify

Generalizado sobre las tres fuentes de tipo Detection Finding
soportadas (Suricata EVE, firewall CEF, PCAP): la lógica de
orquestación y registro en la cadena de custodia es idéntica, solo
cambia qué lector de ingesta y qué normalizador OCSF se invocan.

Este módulo es el único punto del proyecto donde CustodyChain se usa
en combinación con el resto de capas. El modo Laboratorio (ver
models/training.py) nunca debe importar CustodyChain: los
experimentos con sintéticos no deben poder generar, ni por error, un
expediente pericial.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from app.custody.chain import CustodyChain, sha256_json
from app.features.feature_engineering import build_feature_matrix
from app.features.flow_aggregation import enrich_with_aggregation, DEFAULT_WINDOW_SECONDS
from app.ingestion.connectors import read_source
from app.ingestion.pcap_reader import read_pcap_flows
from app.models.classifier import FrozenClassifier
from app.ocsf.detection_finding import normalize_eve_events_to_ocsf
from app.ocsf.firewall_cef import normalize_cef_lines_to_ocsf
from app.ocsf.pcap_flow import normalize_pcap_flows_to_ocsf


@dataclass
class FindingResult:
    """Resultado pericial de un único evento analizado: el evento OCSF
    original, la clasificación del modelo propio de MODEXRE y la
    explicación SHAP asociada."""
    ocsf_event: dict[str, Any]
    prediction: dict[str, Any]
    explanation: dict[str, Any]


@dataclass
class FormalCaseReport:
    case_id: str
    source_name: str
    file_path: str
    findings: list[FindingResult] = field(default_factory=list)
    custody_verification: Optional[dict[str, Any]] = None


@dataclass
class _SourceHandler:
    """Describe cómo ingerir y normalizar una fuente concreta, para
    que FormalCaseRunner.run() no tenga que conocer los detalles de
    cada una."""
    ingest_source_name: str
    ingest_component: str
    normalize: Callable[[list[dict[str, Any]]], list[dict[str, Any]]]
    normalize_component: str
    ingest_fn: Callable[[str | Path], Any]


def _pcap_ingest_adapter(path: str | Path):
    """Adapta PcapIngestionResult a la misma interfaz mínima
    (file_hash, events, events_hash, row_count) que usan las demás
    fuentes, para no ramificar la lógica de run()."""
    return read_pcap_flows(path)


_SOURCE_HANDLERS: dict[str, _SourceHandler] = {
    "suricata_eve": _SourceHandler(
        ingest_source_name="suricata_eve",
        ingest_component="ingestion.connectors.read_jsonl:v1",
        normalize=normalize_eve_events_to_ocsf,
        normalize_component="ocsf.detection_finding.normalize_eve_events_to_ocsf:v1",
        ingest_fn=lambda path: read_source("suricata_eve", path),
    ),
    "firewall_cef": _SourceHandler(
        ingest_source_name="firewall_cef",
        ingest_component="ingestion.connectors.read_text_lines:v1",
        normalize=normalize_cef_lines_to_ocsf,
        normalize_component="ocsf.firewall_cef.normalize_cef_lines_to_ocsf:v1",
        ingest_fn=lambda path: read_source("firewall_cef", path),
    ),
    "pcap": _SourceHandler(
        ingest_source_name="pcap",
        ingest_component="ingestion.pcap_reader.read_pcap_flows:v1",
        normalize=normalize_pcap_flows_to_ocsf,
        normalize_component="ocsf.pcap_flow.normalize_pcap_flows_to_ocsf:v1",
        ingest_fn=_pcap_ingest_adapter,
    ),
}


class FormalCaseRunner:
    """Ejecuta el pipeline pericial completo para un caso, registrando
    cada paso en la cadena de custodia.

    Uso:
        chain = CustodyChain("case_2026_001.db")
        runner = FormalCaseRunner(chain, classifier)
        report = runner.run(case_id="case_2026_001", source_type="suricata_eve", path="eve.json")
    """

    def __init__(
        self,
        chain: CustodyChain,
        classifier: FrozenClassifier,
        aggregation_window_seconds: float = DEFAULT_WINDOW_SECONDS,
    ):
        self.chain = chain
        self.classifier = classifier
        self.aggregation_window_seconds = aggregation_window_seconds

    def run(
        self,
        case_id: str,
        source_type: str,
        path: str | Path,
        on_step: Optional[Callable[[str, dict[str, Any]], None]] = None,
    ) -> FormalCaseReport:
        """Ejecuta el pipeline pericial completo.

        `on_step`, si se proporciona, se invoca justo DESPUÉS de
        completarse cada paso, con (nombre_del_paso, info) — pensado
        para que una interfaz (Streamlit u otra) pueda pintar una
        pantalla de progreso en vivo sin necesidad de que este módulo
        sepa nada de UI. `info` siempre incluye al menos 'label'
        (texto legible) y 'detail' (una línea con la cifra relevante
        de ese paso, la misma que ya se guarda en la nota del eslabón
        de custodia).
        """
        def _notify(step: str, label: str, detail: str) -> None:
            if on_step is not None:
                on_step(step, {"label": label, "detail": detail})

        path = Path(path)

        if source_type == "auto":
            from app.ingestion.universal import normalize_any

            universal_result = normalize_any(path)
            self.chain.add_record(
                case_id=case_id,
                operation="ingest",
                component="ingestion.universal.normalize_any:v1",
                input_hash=universal_result.file_hash,
                output_hash=universal_result.events_hash,
                notes=(
                    f"Ingesta de {universal_result.row_count} eventos desde {path.name} "
                    f"(auto-detectado: {universal_result.source_type_detected})."
                ),
            )
            _notify("ingest", "Ingesta de evidencia (auto-detección)",
                    f"{universal_result.row_count} eventos, tipo detectado: {universal_result.source_type_detected}")

            ocsf_events = universal_result.ocsf_events
            ocsf_hash = sha256_json(ocsf_events)
            self.chain.add_record(
                case_id=case_id,
                operation="ocsf_normalize",
                component="ingestion.universal.normalize_any:v1",
                input_hash=universal_result.events_hash,
                output_hash=ocsf_hash,
                notes=(
                    f"{len(ocsf_events)} eventos normalizados a OCSF "
                    f"({'con' if universal_result.is_labeled else 'sin'} etiqueta de origen)."
                ),
            )
            _notify("ocsf_normalize", "Normalización OCSF",
                    f"{len(ocsf_events)} eventos ({universal_result.source_type_detected})")

        else:
            if source_type not in _SOURCE_HANDLERS:
                raise ValueError(
                    f"source_type '{source_type}' no soportado. Disponibles: "
                    f"{list(_SOURCE_HANDLERS.keys())} + 'auto' (auto-detección)."
                )
            handler = _SOURCE_HANDLERS[source_type]

            # --- Paso 1: ingesta ---
            ingestion_result = handler.ingest_fn(path)
            self.chain.add_record(
                case_id=case_id,
                operation="ingest",
                component=handler.ingest_component,
                input_hash=ingestion_result.file_hash,
                output_hash=ingestion_result.events_hash,
                notes=f"Ingesta de {ingestion_result.row_count} eventos desde {path.name} ({source_type}).",
            )
            _notify("ingest", "Ingesta de evidencia",
                    f"{ingestion_result.row_count} eventos leídos de {path.name}")

            # --- Paso 2: normalización OCSF ---
            ocsf_events = handler.normalize(ingestion_result.events)
            ocsf_hash = sha256_json(ocsf_events)
            self.chain.add_record(
                case_id=case_id,
                operation="ocsf_normalize",
                component=handler.normalize_component,
                input_hash=ingestion_result.events_hash,
                output_hash=ocsf_hash,
                notes=(
                    f"{len(ocsf_events)} eventos normalizados a OCSF (de "
                    f"{ingestion_result.row_count} eventos ingeridos)."
                ),
            )
            _notify("ocsf_normalize", "Normalización OCSF",
                    f"{len(ocsf_events)} eventos normalizados de {ingestion_result.row_count} totales")

        if not ocsf_events:
            report = FormalCaseReport(
                case_id=case_id, source_name=source_type, file_path=str(path), findings=[]
            )
            report.custody_verification = self.chain.verify(case_id)
            _notify("done", "Sin eventos válidos", "0 hallazgos")
            return report

        # --- Paso 3: agregación por origen y ventana temporal ---
        # Cierra la limitación de que la clasificación evento a evento
        # no puede ver patrones de escaneo (ver README, Hallazgo 3):
        # añade variables como "cuántos puertos distintos ha tocado
        # este origen en los últimos N segundos" a cada evento.
        aggregated_events = enrich_with_aggregation(ocsf_events, window_seconds=self.aggregation_window_seconds)
        aggregated_hash = sha256_json(aggregated_events)
        self.chain.add_record(
            case_id=case_id,
            operation="aggregate",
            component="features.flow_aggregation.enrich_with_aggregation:v1",
            input_hash=ocsf_hash,
            output_hash=aggregated_hash,
            notes=(
                f"Agregación causal por origen, ventana de {self.aggregation_window_seconds}s "
                f"(distintos puertos/hosts destino, volumen de eventos)."
            ),
        )
        _notify("aggregate", "Agregación por origen",
                f"ventana de {self.aggregation_window_seconds:.0f}s, {len(aggregated_events)} eventos")

        # --- Paso 4: feature extraction ---
        feature_matrix, feature_names = build_feature_matrix(
            aggregated_events, feature_names=self.classifier.feature_names
        )
        features_hash = sha256_json(feature_matrix.tolist())
        self.chain.add_record(
            case_id=case_id,
            operation="feature_extract",
            component="features.feature_engineering.build_feature_matrix:v1",
            input_hash=aggregated_hash,
            output_hash=features_hash,
            notes=f"Vector de {len(feature_names)} características por evento, alineado con model_version={self.classifier.version}.",
        )
        _notify("feature_extract", "Extracción de características",
                f"{len(feature_names)} variables por evento")

        # --- Paso 5: clasificación + explicación (modelo congelado) ---
        predictions = self.classifier.predict_batch(feature_matrix)
        explanations = self.classifier.explain_batch(feature_matrix)
        findings: list[FindingResult] = [
            FindingResult(ocsf_event, prediction, explanation)
            for ocsf_event, prediction, explanation in zip(aggregated_events, predictions, explanations)
        ]

        classify_output_hash = sha256_json(
            [{"prediction": f.prediction, "explanation": f.explanation} for f in findings]
        )
        self.chain.add_record(
            case_id=case_id,
            operation="classify",
            component=f"models.classifier.FrozenClassifier:{self.classifier.version}",
            input_hash=features_hash,
            output_hash=classify_output_hash,
            notes=f"{len(findings)} eventos clasificados con explicación SHAP local.",
        )
        _notify("classify", "Clasificación + SHAP",
                f"{len(findings)} eventos clasificados con modelo {self.classifier.version}")

        report = FormalCaseReport(
            case_id=case_id, source_name=source_type, file_path=str(path), findings=findings,
        )
        report.custody_verification = self.chain.verify(case_id)
        verified = "íntegra" if report.custody_verification["valid"] else "CON INCIDENCIAS"
        _notify("verify", "Verificación de custodia",
                f"cadena {verified}, {report.custody_verification['total_records']} eslabones")
        return report

    def run_suricata_eve(self, case_id: str, path: str | Path) -> FormalCaseReport:
        """Alias retrocompatible: equivalente a run(..., source_type='suricata_eve')."""
        return self.run(case_id, "suricata_eve", path)
