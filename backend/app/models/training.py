"""
Generación de Datos Sintéticos — Modo LABORATORIO
====================================================

Generaliza la lógica ya validada en el TFM1
(SINTETICO_MachineLearningCVE / SINTETICO_UNSW_NB15 /
SINTETICO_KITSUNE_Descarga_CTGAN_Definitivo.ipynb) a un módulo
Python reutilizable y testeable, en vez de mantener tres notebooks
casi idénticos.

Nota de nomenclatura: los notebooks originales llevan "CTGAN" en el
nombre de fichero, pero el sintetizador realmente empleado es
`GaussianCopulaSynthesizer` de SDV (Synthetic Data Vault), no CTGAN.
Se mantiene esa elección aquí por continuidad metodológica con el
TFM1, corrigiendo únicamente la nomenclatura.

Pipeline (idéntico al de los notebooks, generalizado por source_name):

  1. Escaneo por chunks del CSV real para contar clases de attack_cat
     sin cargar el fichero completo en memoria.
  2. Construcción de una muestra de entrenamiento ESTRATIFICADA:
     mínimo garantizado por clase de ataque + tope de Normal.
  3. Ajuste (fit) del sintetizador sobre esa muestra estratificada.
  4. Generación por cuotas y por clase, escrita incrementalmente a
     CSV para no agotar memoria con datasets grandes.

IMPORTANTE: este módulo es de uso EXCLUSIVO del modo LABORATORIO. El
modo FORMAL nunca debe invocar generate_synthetic_dataset ni
importar GaussianCopulaSynthesizer: el expediente pericial solo
trabaja con evidencia real (ver app/models/inference.py).
"""

from __future__ import annotations

import gc
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd


def normalize_cols(columns: list[str]) -> list[str]:
    """Misma normalización de nombres de columna que el resto del
    pipeline de limpieza del TFM1 (ver app/ingestion/connectors.py)."""
    return [
        str(c).strip().replace(" ", "_").replace("/", "_").replace("-", "_").lower()
        for c in columns
    ]


@dataclass
class SyntheticGenerationConfig:
    """Hiperparámetros de generación, con los mismos valores por
    defecto que los notebooks del TFM1 (ajustables por dataset)."""
    random_state: int = 42
    chunk_size: int = 250_000

    train_total_n: int = 250_000
    train_normal_max: int = 140_000
    train_attack_min_each: int = 35_000

    normal_n: int = 200_000
    attack_n_each: int = 30_000

    default_distribution: str = "gamma"
    enforce_min_max_values: bool = False


@dataclass
class SyntheticGenerationSummary:
    source_name: str
    attack_categories_found: list[str]
    train_sample_shape: tuple[int, int]
    train_sample_class_counts: dict[str, int]
    synthetic_rows_total: int
    synthetic_class_counts: dict[str, int] = field(default_factory=dict)
    output_path: str = ""
    metadata_path: Optional[str] = None


def _enforce_label_from_attack_cat(df: pd.DataFrame) -> pd.DataFrame:
    """label se deriva SIEMPRE de attack_cat, nunca al revés (misma
    regla de coherencia que en la capa de limpieza)."""
    if "attack_cat" not in df.columns:
        raise ValueError("Falta 'attack_cat' en el dataframe: no se puede derivar 'label'.")
    df = df.copy()
    df["attack_cat"] = df["attack_cat"].astype(str).str.strip()
    df["label"] = (df["attack_cat"].str.lower() != "normal").astype(int)
    return df


def count_attack_categories(real_csv: str | Path, chunk_size: int) -> Counter:
    """Pasada 1: cuenta las categorías de attack_cat sin cargar el
    CSV completo en memoria."""
    real_csv = Path(real_csv)
    counts: Counter = Counter()
    reader = pd.read_csv(real_csv, low_memory=False, chunksize=chunk_size)
    for chunk in reader:
        chunk.columns = normalize_cols(list(chunk.columns))
        if "attack_cat" not in chunk.columns:
            raise ValueError(f"'{real_csv.name}' no contiene 'attack_cat'.")
        counts.update(chunk["attack_cat"].astype(str).str.strip().tolist())
        del chunk
        gc.collect()
    return counts


def build_stratified_training_sample(
    real_csv: str | Path,
    attack_categories: list[str],
    config: SyntheticGenerationConfig,
) -> pd.DataFrame:
    """Pasada 2: construye una muestra de entrenamiento estratificada
    (mínimo garantizado por clase de ataque + tope de Normal), leyendo
    el CSV real por chunks."""
    real_csv = Path(real_csv)
    rng = np.random.RandomState(config.random_state)
    seen_per_cat: Counter = Counter()
    train_parts: list[pd.DataFrame] = []

    reader = pd.read_csv(real_csv, low_memory=False, chunksize=config.chunk_size)
    for chunk in reader:
        chunk.columns = normalize_cols(list(chunk.columns))
        chunk = _enforce_label_from_attack_cat(chunk)

        for cat in attack_categories:
            need = config.train_attack_min_each - seen_per_cat[cat]
            if need <= 0:
                continue
            sub = chunk[chunk["attack_cat"] == cat]
            if len(sub) == 0:
                continue
            take = min(need, len(sub))
            sample = sub.sample(n=take, random_state=int(rng.randint(0, 1_000_000_000)))
            train_parts.append(sample)
            seen_per_cat[cat] += len(sample)

        need_normal = config.train_normal_max - seen_per_cat["Normal"]
        if need_normal > 0:
            sub_normal = chunk[chunk["attack_cat"].str.lower() == "normal"]
            if len(sub_normal) > 0:
                take_normal = min(need_normal, len(sub_normal))
                sample_normal = sub_normal.sample(
                    n=take_normal, random_state=int(rng.randint(0, 1_000_000_000))
                )
                train_parts.append(sample_normal)
                seen_per_cat["Normal"] += len(sample_normal)

        del chunk
        gc.collect()

        if sum(seen_per_cat.values()) >= config.train_total_n:
            break

    if not train_parts:
        raise RuntimeError(
            "No se pudo construir muestra de entrenamiento: revisa que el CSV "
            "contenga las categorías de ataque esperadas."
        )

    df_train = pd.concat(train_parts, ignore_index=True)
    df_train = df_train.sample(frac=1.0, random_state=config.random_state).reset_index(drop=True)
    if len(df_train) > config.train_total_n:
        df_train = df_train.sample(
            n=config.train_total_n, random_state=config.random_state
        ).reset_index(drop=True)

    return df_train


def fit_synthesizer(df_train: pd.DataFrame, config: SyntheticGenerationConfig):
    """Ajusta un GaussianCopulaSynthesizer (SDV) sobre la muestra
    estratificada. Import diferido de sdv: es una dependencia pesada
    exclusiva del modo Laboratorio, no debe cargarse en modo Formal."""
    from sdv.metadata import Metadata
    from sdv.single_table import GaussianCopulaSynthesizer

    df_sdv = df_train.copy()
    for c in df_sdv.columns:
        if str(df_sdv[c].dtype) == "category":
            df_sdv[c] = df_sdv[c].astype("object")
    df_sdv["attack_cat"] = df_sdv["attack_cat"].astype(str)
    df_sdv["label"] = df_sdv["label"].astype(str)

    metadata = Metadata.detect_from_dataframe(df_sdv)
    synth = GaussianCopulaSynthesizer(
        metadata,
        default_distribution=config.default_distribution,
        enforce_min_max_values=config.enforce_min_max_values,
    )
    synth.fit(df_sdv)
    return synth, metadata


def generate_synthetic_dataset(
    source_name: str,
    real_csv: str | Path,
    output_csv: str | Path,
    config: Optional[SyntheticGenerationConfig] = None,
    metadata_json: Optional[str | Path] = None,
) -> SyntheticGenerationSummary:
    """Orquesta el pipeline completo de generación sintética para una
    fuente dada (cicids2017 / unsw_nb15 / kitsune), reproduciendo la
    lógica de los notebooks SINTETICO_*.ipynb del TFM1.

    Uso EXCLUSIVO del modo Laboratorio.
    """
    config = config or SyntheticGenerationConfig()
    real_csv = Path(real_csv)
    output_csv = Path(output_csv)

    counts = count_attack_categories(real_csv, config.chunk_size)
    attack_categories = sorted(c for c in counts if str(c).strip().lower() != "normal")
    if not attack_categories:
        raise RuntimeError(f"No se detectaron categorías de ataque en '{real_csv.name}'.")

    df_train = build_stratified_training_sample(real_csv, attack_categories, config)
    synth, metadata = fit_synthesizer(df_train, config)

    if metadata_json:
        metadata.save_to_json(str(metadata_json))

    if output_csv.exists():
        output_csv.unlink()

    def _append(df_part: pd.DataFrame) -> None:
        header = not output_csv.exists()
        df_part.to_csv(output_csv, index=False, mode="a", header=header)

    syn_normal = synth.sample(num_rows=config.normal_n)
    syn_normal.columns = normalize_cols(list(syn_normal.columns))
    syn_normal = _enforce_label_from_attack_cat(syn_normal)
    syn_normal["attack_cat"] = "Normal"
    syn_normal["label"] = 0
    _append(syn_normal)
    del syn_normal
    gc.collect()

    for cat in attack_categories:
        syn_attack = synth.sample(num_rows=config.attack_n_each)
        syn_attack.columns = normalize_cols(list(syn_attack.columns))
        syn_attack = _enforce_label_from_attack_cat(syn_attack)
        syn_attack["attack_cat"] = str(cat)
        syn_attack["label"] = 1
        _append(syn_attack)
        del syn_attack
        gc.collect()

    syn_class_counts: Counter = Counter()
    syn_reader = pd.read_csv(output_csv, chunksize=200_000, low_memory=False)
    total_rows = 0
    for chunk in syn_reader:
        syn_class_counts.update(chunk["attack_cat"].astype(str).str.strip().tolist())
        total_rows += len(chunk)

    return SyntheticGenerationSummary(
        source_name=source_name,
        attack_categories_found=attack_categories,
        train_sample_shape=df_train.shape,
        train_sample_class_counts=dict(df_train["attack_cat"].value_counts()),
        synthetic_rows_total=total_rows,
        synthetic_class_counts=dict(syn_class_counts),
        output_path=str(output_csv),
        metadata_path=str(metadata_json) if metadata_json else None,
    )
