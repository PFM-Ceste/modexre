"""
Módulo de Cadena de Custodia — Hash-Chain (Nivel 2)
=====================================================

Cada evento forense (ingesta, normalización OCSF, extracción de
características, inferencia del modelo, generación de informe) se
registra como un eslabón (CustodyRecord) que incluye:

  - hash del propio contenido (input/output de la operación)
  - hash del eslabón anterior (encadenamiento)
  - metadatos: timestamp, operación, componente/versión responsable

Si un eslabón se altera o se borra, el hash del eslabón siguiente deja
de coincidir con el prev_hash recalculado, lo que hace la
manipulación detectable matemáticamente, sin necesidad de firma
digital (eso sería el Nivel 3, fuera de alcance de este TFM pero
mencionado como línea futura).

IMPORTANTE: este módulo solo se usa en modo FORMAL. El modo
LABORATORIO no debe instanciar CustodyChain, así se garantiza que
los experimentos con datos sintéticos nunca contaminan el expediente
pericial.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


GENESIS_HASH = "0" * 64  # hash de referencia para el primer eslabón de cada caso


def sha256_bytes(data: bytes) -> str:
    """Hash SHA-256 de unos bytes, en hexadecimal."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    """Hash SHA-256 de un fichero completo, leído por bloques (evita
    cargar ficheros grandes de captura en memoria)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_json(obj: Any) -> str:
    """Hash SHA-256 de una estructura serializable a JSON.

    sort_keys=True para que el hash sea determinista independientemente
    del orden de inserción de las claves del diccionario de entrada.
    """
    encoded = json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    return sha256_bytes(encoded)


@dataclass
class CustodyRecord:
    index: int
    timestamp: str
    case_id: str
    operation: str          # p.ej. "ingest", "ocsf_normalize", "feature_extract", "classify", "report_generate"
    component: str          # p.ej. "ingestion.pcap_reader:v1", "models.xgboost:v1.2"
    input_hash: str
    output_hash: str
    prev_hash: str
    record_hash: str = ""   # se calcula tras construir el resto de campos
    notes: Optional[str] = None

    def compute_record_hash(self) -> str:
        payload = {
            "index": self.index,
            "timestamp": self.timestamp,
            "case_id": self.case_id,
            "operation": self.operation,
            "component": self.component,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "prev_hash": self.prev_hash,
            "notes": self.notes,
        }
        return sha256_json(payload)


class CustodyChain:
    """Gestiona la cadena de custodia de uno o varios casos periciales
    persistida en SQLite.

    Uso típico:
        chain = CustodyChain("case_2026_001.db")
        chain.add_record(
            case_id="case_2026_001",
            operation="ingest",
            component="ingestion.pcap_reader:v1",
            input_hash=sha256_file("captura.pcap"),
            output_hash=sha256_json(eventos_crudos),
            notes="Captura recibida de la empresa X."
        )
    """

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS custody_chain (
                    idx INTEGER NOT NULL,
                    ts TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    component TEXT NOT NULL,
                    input_hash TEXT NOT NULL,
                    output_hash TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL,
                    notes TEXT,
                    PRIMARY KEY (case_id, idx)
                )
                """
            )
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _last_record(self, case_id: str) -> tuple[int, str]:
        """Devuelve (siguiente_idx, prev_hash) para ESTE caso.

        La cadena es independiente por caso (case_id): cada expediente
        pericial arranca en idx=0 / GENESIS_HASH, para que la cadena
        de un caso nunca dependa de datos de otro caso.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT idx, record_hash FROM custody_chain WHERE case_id = ? ORDER BY idx DESC LIMIT 1",
                (case_id,),
            ).fetchone()
        if row is None:
            return 0, GENESIS_HASH
        return row[0] + 1, row[1]

    def add_record(
        self,
        case_id: str,
        operation: str,
        component: str,
        input_hash: str,
        output_hash: str,
        notes: Optional[str] = None,
    ) -> CustodyRecord:
        """Añade un nuevo eslabón a la cadena de `case_id` y lo persiste."""
        next_idx, prev_hash = self._last_record(case_id)

        record = CustodyRecord(
            index=next_idx,
            timestamp=datetime.now(timezone.utc).isoformat(),
            case_id=case_id,
            operation=operation,
            component=component,
            input_hash=input_hash,
            output_hash=output_hash,
            prev_hash=prev_hash,
            notes=notes,
        )
        record.record_hash = record.compute_record_hash()

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO custody_chain
                    (idx, ts, case_id, operation, component, input_hash, output_hash, prev_hash, record_hash, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.index,
                    record.timestamp,
                    record.case_id,
                    record.operation,
                    record.component,
                    record.input_hash,
                    record.output_hash,
                    record.prev_hash,
                    record.record_hash,
                    record.notes,
                ),
            )
            conn.commit()

        return record

    def get_chain(self, case_id: str) -> list[CustodyRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT idx, ts, case_id, operation, component,
                       input_hash, output_hash, prev_hash, record_hash, notes
                FROM custody_chain
                WHERE case_id = ?
                ORDER BY idx ASC
                """,
                (case_id,),
            ).fetchall()

        return [
            CustodyRecord(
                index=r[0], timestamp=r[1], case_id=r[2], operation=r[3],
                component=r[4], input_hash=r[5], output_hash=r[6],
                prev_hash=r[7], record_hash=r[8], notes=r[9],
            )
            for r in rows
        ]

    def verify(self, case_id: str) -> dict:
        """Verifica la integridad de la cadena de `case_id`.

        Recalcula cada record_hash y comprueba que:
          1. El hash recalculado coincide con el almacenado (nadie
             modificó los campos de ese eslabón).
          2. El prev_hash de cada eslabón coincide con el record_hash
             del eslabón anterior (nadie insertó/eliminó eslabones).

        Devuelve un informe apto para incluir en el anexo técnico del
        informe pericial.
        """
        records = self.get_chain(case_id)
        issues: list[str] = []
        expected_prev = GENESIS_HASH

        for rec in records:
            recalculated = rec.compute_record_hash()
            if recalculated != rec.record_hash:
                issues.append(
                    f"Eslabón #{rec.index}: hash almacenado no coincide con el "
                    f"recalculado. Posible alteración del registro."
                )
            if rec.prev_hash != expected_prev:
                issues.append(
                    f"Eslabón #{rec.index}: prev_hash no coincide con el hash "
                    f"del eslabón anterior. Posible inserción/eliminación en la cadena."
                )
            expected_prev = rec.record_hash

        return {
            "case_id": case_id,
            "valid": len(issues) == 0,
            "total_records": len(records),
            "issues": issues,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    def to_report_dict(self, case_id: str) -> list[dict]:
        """Serializa la cadena de `case_id` para incrustar en el informe pericial."""
        return [asdict(r) for r in self.get_chain(case_id)]
