import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ingestion.connectors import read_source, read_clean_csv


# Muestra fiel al formato de salida real de FULL_MachineLearningCVE_*.ipynb:
# attack_cat/label normalizados como primeras columnas, resto en snake_case.
CICIDS_CLEAN_SAMPLE = """attack_cat,label,Destination Port,Protocol,Flow Duration,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets
Normal,0,80,6,1000,10,8,500,400
DDoS,1,443,6,2500,20,15,1200,900
PortScan,1,22,6,500,5,3,200,100
"""


@pytest.fixture
def cicids_csv(tmp_path):
    p = tmp_path / "MachineLearningCVE_full_clean_sample.csv"
    p.write_text(CICIDS_CLEAN_SAMPLE)
    return p


def test_read_clean_csv_normalizes_column_names(cicids_csv):
    result = read_clean_csv("cicids2017", cicids_csv)
    assert "destination_port" in result.events[0]
    assert "attack_cat" in result.events[0]
    assert result.row_count == 3


def test_read_clean_csv_computes_file_hash(cicids_csv):
    result = read_clean_csv("cicids2017", cicids_csv)
    assert len(result.file_hash) == 64  # SHA-256 en hex
    assert result.source_name == "cicids2017"


def test_read_source_dispatches_correctly(cicids_csv):
    result = read_source("cicids2017", cicids_csv)
    assert result.row_count == 3


def test_read_source_rejects_unknown_source(cicids_csv):
    with pytest.raises(ValueError):
        read_source("fuente_inexistente", cicids_csv)


def test_read_clean_csv_rejects_file_without_taxonomy(tmp_path):
    """Un CSV que no ha pasado por la limpieza del TFM1 (sin
    attack_cat/label) debe fallar de forma explícita, no seguir
    silenciosamente con datos a medio normalizar."""
    p = tmp_path / "raw_not_cleaned.csv"
    p.write_text("Destination Port,Protocol,Label\n80,6,BENIGN\n")
    with pytest.raises(ValueError):
        read_clean_csv("cicids2017", p)


def test_events_hash_changes_if_file_changes(cicids_csv, tmp_path):
    result_a = read_clean_csv("cicids2017", cicids_csv)

    modified = tmp_path / "cicids_modified.csv"
    modified.write_text(CICIDS_CLEAN_SAMPLE.replace("Normal,0", "DDoS,1"))
    result_b = read_clean_csv("cicids2017", modified)

    assert result_a.events_hash != result_b.events_hash
    assert result_a.file_hash != result_b.file_hash
