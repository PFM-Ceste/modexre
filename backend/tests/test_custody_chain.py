"""
Tests del módulo de cadena de custodia.

Ejecutar con:  pytest backend/tests/test_custody_chain.py -v
"""

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.custody.chain import CustodyChain, sha256_json, sha256_bytes, sha256_file, GENESIS_HASH


@pytest.fixture
def chain(tmp_path):
    db_path = tmp_path / "test_case.db"
    return CustodyChain(db_path)


def test_first_record_links_to_genesis(chain):
    rec = chain.add_record(
        case_id="case_001",
        operation="ingest",
        component="ingestion.pcap_reader:v1",
        input_hash=sha256_json({"file": "captura.pcap"}),
        output_hash=sha256_json({"events": 1200}),
    )
    assert rec.prev_hash == GENESIS_HASH
    assert rec.index == 0


def test_chain_links_sequentially(chain):
    r1 = chain.add_record("case_001", "ingest", "ingestion.pcap_reader:v1", "h_in_1", "h_out_1")
    r2 = chain.add_record("case_001", "ocsf_normalize", "ocsf.mapper:v1", "h_in_2", "h_out_2")
    r3 = chain.add_record("case_001", "classify", "models.xgboost:v1.2", "h_in_3", "h_out_3")

    assert r1.index == 0 and r2.index == 1 and r3.index == 2
    assert r2.prev_hash == r1.record_hash
    assert r3.prev_hash == r2.record_hash


def test_verify_detects_valid_chain(chain):
    chain.add_record("case_001", "ingest", "ingestion.pcap_reader:v1", "h1", "h2")
    chain.add_record("case_001", "classify", "models.xgboost:v1.2", "h3", "h4")

    result = chain.verify("case_001")
    assert result["valid"] is True
    assert result["total_records"] == 2
    assert result["issues"] == []


def test_verify_detects_tampered_record(chain):
    """Simula que alguien modifica manualmente un campo en la base de
    datos (ej. cambia el output_hash de una clasificación) e intenta
    pasar desapercibido. La verificación debe detectarlo."""
    chain.add_record("case_001", "ingest", "ingestion.pcap_reader:v1", "h1", "h2")
    chain.add_record("case_001", "classify", "models.xgboost:v1.2", "h3", "h4")

    with sqlite3.connect(chain.db_path) as conn:
        conn.execute(
            "UPDATE custody_chain SET output_hash = ? WHERE case_id = ? AND idx = 1",
            ("h4_MANIPULADO", "case_001"),
        )
        conn.commit()

    result = chain.verify("case_001")
    assert result["valid"] is False
    assert any("Eslabón #1" in issue for issue in result["issues"])


def test_verify_detects_broken_link_on_deletion(chain):
    """Simula el borrado de un eslabón intermedio."""
    chain.add_record("case_001", "ingest", "ingestion.pcap_reader:v1", "h1", "h2")
    chain.add_record("case_001", "ocsf_normalize", "ocsf.mapper:v1", "h3", "h4")
    chain.add_record("case_001", "classify", "models.xgboost:v1.2", "h5", "h6")

    with sqlite3.connect(chain.db_path) as conn:
        conn.execute("DELETE FROM custody_chain WHERE case_id = ? AND idx = 1", ("case_001",))
        conn.commit()

    result = chain.verify("case_001")
    assert result["valid"] is False


def test_different_cases_are_isolated(chain):
    chain.add_record("case_001", "ingest", "ingestion.pcap_reader:v1", "h1", "h2")
    chain.add_record("case_002", "ingest", "ingestion.pcap_reader:v1", "h3", "h4")
    chain.add_record("case_001", "classify", "models.xgboost:v1.2", "h5", "h6")

    chain_1 = chain.get_chain("case_001")
    chain_2 = chain.get_chain("case_002")

    assert len(chain_1) == 2
    assert len(chain_2) == 1
    assert chain_1[0].prev_hash == GENESIS_HASH
    assert chain_2[0].prev_hash == GENESIS_HASH
    assert chain_1[1].prev_hash == chain_1[0].record_hash


def test_hash_helpers_are_deterministic(tmp_path):
    assert sha256_json({"a": 1, "b": 2}) == sha256_json({"b": 2, "a": 1})

    f = tmp_path / "sample.bin"
    f.write_bytes(b"contenido de prueba forense")
    assert sha256_file(f) == sha256_bytes(b"contenido de prueba forense")
