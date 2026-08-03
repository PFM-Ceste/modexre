import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.pipeline.formal_pipeline import FormalCaseReport, FindingResult
from app.report.report_generator import (
    group_findings_by_category,
    build_category_summary,
    filter_report_by_categories,
    aggregate_shap_by_category,
)


def _finding(category: str, src_ip: str, dst_ip: str, prob: float = 0.9):
    return FindingResult(
        ocsf_event={
            "src_endpoint": {"ip": src_ip, "port": 12345},
            "dst_endpoint": {"ip": dst_ip, "port": 22},
            "finding_info": {"title": f"Alerta {category}"},
        },
        prediction={"label": 1 if category != "Normal" else 0, "attack_cat": category,
                    "probability": prob, "model_version": "v1"},
        explanation={"top_features": [{"feature": "duration", "shap_value": 1.0}]},
    )


def _sample_report() -> FormalCaseReport:
    findings = [
        _finding("PortScan", "10.0.0.5", "203.0.113.7", 0.95),
        _finding("PortScan", "10.0.0.5", "203.0.113.8", 0.90),
        _finding("Normal", "10.0.0.9", "8.8.8.8", 0.99),
        _finding("DoS", "10.0.0.20", "203.0.113.7", 0.80),
        _finding("DoS", "10.0.0.20", "203.0.113.7", 0.85),
    ]
    return FormalCaseReport(
        case_id="case_test", source_name="suricata_eve", file_path="eve.json",
        findings=findings, custody_verification={"valid": True, "total_records": 5, "issues": []},
    )


# ---------- group_findings_by_category ----------

def test_group_findings_by_category():
    report = _sample_report()
    grouped = group_findings_by_category(report)

    assert set(grouped.keys()) == {"PortScan", "Normal", "DoS"}
    assert len(grouped["PortScan"]) == 2
    assert len(grouped["Normal"]) == 1
    assert len(grouped["DoS"]) == 2


def test_group_findings_preserves_first_appearance_order():
    report = _sample_report()
    grouped = group_findings_by_category(report)
    # Orden de aparición en la evidencia: PortScan, Normal, DoS
    assert list(grouped.keys()) == ["PortScan", "Normal", "DoS"]


# ---------- build_category_summary ----------

def test_build_category_summary_includes_ips_and_stats():
    report = _sample_report()
    summary = build_category_summary(report)

    by_cat = {s["categoria"]: s for s in summary}
    assert by_cat["PortScan"]["n_eventos"] == 2
    assert by_cat["PortScan"]["src_ips"] == ["10.0.0.5"]
    assert by_cat["PortScan"]["dst_ips"] == ["203.0.113.7", "203.0.113.8"]
    assert abs(by_cat["PortScan"]["probabilidad_media"] - 0.925) < 1e-9

    assert by_cat["DoS"]["src_ips"] == ["10.0.0.20"]


# ---------- filter_report_by_categories ----------

def test_filter_report_by_single_category():
    report = _sample_report()
    filtered = filter_report_by_categories(report, ["PortScan"])

    assert len(filtered.findings) == 2
    assert all(f.prediction["attack_cat"] == "PortScan" for f in filtered.findings)
    # Metadatos del caso se preservan
    assert filtered.case_id == report.case_id
    assert filtered.custody_verification == report.custody_verification


def test_filter_report_by_multiple_categories():
    report = _sample_report()
    filtered = filter_report_by_categories(report, ["PortScan", "DoS"])
    assert len(filtered.findings) == 4
    assert all(f.prediction["attack_cat"] in ("PortScan", "DoS") for f in filtered.findings)


def test_filter_report_empty_list_means_all():
    report = _sample_report()
    filtered = filter_report_by_categories(report, [])
    assert len(filtered.findings) == len(report.findings)


def test_filter_report_does_not_mutate_original():
    report = _sample_report()
    original_count = len(report.findings)
    filter_report_by_categories(report, ["PortScan"])
    assert len(report.findings) == original_count


def test_filter_report_unknown_category_yields_empty():
    report = _sample_report()
    filtered = filter_report_by_categories(report, ["CategoriaInexistente"])
    assert filtered.findings == []


# ---------- aggregate_shap_by_category ----------

def test_aggregate_shap_sums_absolute_values_across_findings():
    findings = [
        FindingResult(
            ocsf_event={}, prediction={"label": 1, "attack_cat": "PortScan", "probability": 0.9},
            explanation={"top_features": [
                {"feature": "agg_distinct_dst_ports", "shap_value": 3.0},
                {"feature": "duration", "shap_value": -1.0},
            ]},
        ),
        FindingResult(
            ocsf_event={}, prediction={"label": 1, "attack_cat": "PortScan", "probability": 0.8},
            explanation={"top_features": [
                {"feature": "agg_distinct_dst_ports", "shap_value": -5.0},
                {"feature": "duration", "shap_value": 0.5},
            ]},
        ),
    ]
    result = aggregate_shap_by_category(findings)
    by_feature = {r["feature"]: r["contribucion_agregada"] for r in result}

    # |3.0| + |-5.0| = 8.0 (nunca se cancelan positivos y negativos)
    assert by_feature["agg_distinct_dst_ports"] == 8.0
    assert by_feature["duration"] == 1.5
    # El resultado siempre es >= 0 (nunca negativo, es la corrección
    # del bug detectado: sumar sin abs() podía dar valores negativos
    # si los signos coincidían).
    assert all(v >= 0 for v in by_feature.values())


def test_aggregate_shap_respects_top_n():
    findings = [FindingResult(
        ocsf_event={}, prediction={"label": 1},
        explanation={"top_features": [
            {"feature": f"f{i}", "shap_value": float(10 - i)} for i in range(8)
        ]},
    )]
    result = aggregate_shap_by_category(findings, top_n=3)
    assert len(result) == 3
    assert result[0]["feature"] == "f0"  # mayor contribución primero
