"""
Clasificador XGBoost + Explicabilidad SHAP
=============================================

Clasificador MULTI-CLASE (no binario): predice la categoría de
ataque completa (`attack_cat`, incluyendo "Normal"), no solo
"ataque sí/no". Esto es deliberado: el analista debe poder ver QUÉ
tipos de ataque hay realmente en la evidencia analizada, y decidir
después en cuál centrarse (uno, varios, o todos) — no al revés. Fijar
de antemano una única categoría objetivo invertía el orden correcto
de un análisis pericial.

Dos responsabilidades deliberadamente separadas, en línea con la
distinción Laboratorio/Formal del resto del proyecto:

  - `train_xgboost_classifier` / `save_model_artifact`: modo
    LABORATORIO. Aquí se entrena, se reentrena, se ajustan
    hiperparámetros libremente.

  - `FrozenClassifier`: modo FORMAL. Carga un artefacto de modelo ya
    entrenado y versionado (con su propio hash) y SOLO hace
    inferencia — nunca reentrena. Esto es lo que garantiza que el
    modelo usado en un expediente pericial es exactamente el mismo
    que se validó en Laboratorio, sin deriva entre ambos momentos.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb


@dataclass
class TrainingMetrics:
    accuracy: float
    f1_macro: float
    f1_weighted: float
    precision_macro: float
    recall_macro: float
    n_train: int
    n_test: int


def train_xgboost_classifier(
    X: np.ndarray,
    y: np.ndarray,
    test_size: float = 0.2,
    random_state: int = 42,
) -> tuple[xgb.XGBClassifier, TrainingMetrics]:
    """Entrena un XGBoost (binario o multi-clase, autodetectado según
    el número de clases distintas en `y`), evaluado con F1 macro como
    métrica principal (mismo criterio que el TFM1: penaliza ignorar
    las clases minoritarias, crítico en ciberseguridad).

    `y` puede ser un array de enteros (0..n_clases-1) o de strings
    (p.ej. attack_cat); si es de strings, quien llama debe haberlo
    codificado ya con un LabelEncoder (ver train_multiclass_from_labels
    más abajo, que hace esto automáticamente).
    """
    n_classes = len(np.unique(y))
    is_multiclass = n_classes > 2

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    model = xgb.XGBClassifier(
        random_state=random_state,
        eval_metric="mlogloss" if is_multiclass else "logloss",
        n_estimators=200,
        max_depth=6,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    metrics = TrainingMetrics(
        accuracy=float(accuracy_score(y_test, y_pred)),
        f1_macro=float(f1_score(y_test, y_pred, average="macro")),
        f1_weighted=float(f1_score(y_test, y_pred, average="weighted")),
        precision_macro=float(precision_score(y_test, y_pred, average="macro", zero_division=0)),
        recall_macro=float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
        n_train=len(X_train),
        n_test=len(X_test),
    )
    return model, metrics


def train_multiclass_from_labels(
    X: np.ndarray,
    attack_cat_labels: list[str],
    test_size: float = 0.2,
    random_state: int = 42,
) -> tuple[xgb.XGBClassifier, TrainingMetrics, LabelEncoder]:
    """Conveniencia: entrena directamente a partir de las etiquetas de
    texto de attack_cat (p.ej. "Normal", "PortScan", "DDoS"...),
    codificándolas internamente. Devuelve también el LabelEncoder para
    que save_model_artifact pueda guardar el mapeo índice->nombre en
    el manifest (necesario para decodificar predicciones en modo
    Formal sin depender de recordar el orden de entrenamiento)."""
    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(attack_cat_labels)
    model, metrics = train_xgboost_classifier(X, y_encoded, test_size, random_state)
    return model, metrics, encoder


def save_model_artifact(
    model: xgb.XGBClassifier,
    feature_names: list[str],
    metrics: TrainingMetrics,
    version: str,
    output_dir: str | Path,
    class_names: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Serializa el modelo + metadatos versionados a disco (modo
    Laboratorio → artefacto "certificado" listo para modo Formal).

    `class_names`: lista ordenada por índice (class_names[i] es el
    nombre de la clase codificada como `i`), típicamente
    `encoder.classes_.tolist()` de train_multiclass_from_labels. Si
    se omite (caso binario simple 0/1), FrozenClassifier.predict
    devuelve solo el label numérico, sin nombre de clase.

    Devuelve el manifest, que incluye el hash SHA-256 del propio
    fichero de modelo: es lo que permite, en modo Formal, demostrar
    que el modelo usado en un caso concreto no cambió respecto al que
    se validó aquí.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Formato nativo de XGBoost (UBJSON), NO pickle: pickle serializa
    # también la versión interna de la librería, así que un modelo
    # entrenado con una versión de xgboost puede fallar al cargarse
    # con otra ligeramente distinta ("input stream corrupted"), algo
    # que ocurre con facilidad entre el entorno de desarrollo y la
    # máquina del usuario final. save_model/load_model es el formato
    # que la propia documentación de XGBoost recomienda para
    # portabilidad entre versiones y plataformas.
    model_path = output_dir / f"model_{version}.ubj"
    model.save_model(str(model_path))

    model_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()

    manifest = {
        "version": version,
        "model_file": model_path.name,
        "model_hash": model_hash,
        "feature_names": feature_names,
        "class_names": class_names,
        "metrics": asdict(metrics),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "XGBoost",
        "xgboost_version": xgb.__version__,
    }
    manifest_path = output_dir / f"model_{version}.manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))

    return manifest


class ModelIntegrityError(ValueError):
    """El fichero de modelo no coincide con el hash declarado en el manifest."""


class FrozenClassifier:
    """Wrapper de solo-inferencia sobre un modelo ya entrenado y
    versionado. Uso exclusivo de modo FORMAL.

    Verifica el hash del fichero de modelo contra el manifest en el
    momento de carga: si alguien sustituyó el .pkl sin actualizar el
    manifest (accidental o deliberadamente), la carga falla en vez de
    usar silenciosamente un modelo distinto al certificado.
    """

    def __init__(self, model_dir: str | Path, version: str):
        model_dir = Path(model_dir)
        manifest_path = model_dir / f"model_{version}.manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"No existe manifest para la versión '{version}' en {model_dir}")

        self.manifest = json.loads(manifest_path.read_text())
        model_path = model_dir / self.manifest["model_file"]

        actual_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
        if actual_hash != self.manifest["model_hash"]:
            raise ModelIntegrityError(
                f"El hash del fichero de modelo '{model_path.name}' no coincide "
                f"con el declarado en el manifest. El modelo pudo haber sido "
                f"sustituido tras su certificación en Laboratorio."
            )

        self._model: xgb.XGBClassifier = xgb.XGBClassifier()
        self._model.load_model(str(model_path))

        self.feature_names: list[str] = self.manifest["feature_names"]
        self.class_names: Optional[list[str]] = self.manifest.get("class_names")
        self.version = version
        self._explainer = None  # se crea perezosamente, es costoso

    def predict_batch(self, feature_matrix: np.ndarray) -> list[dict[str, Any]]:
        """Versión en lote de predict(): una sola llamada a
        predict()/predict_proba() sobre toda la matriz, en vez de una
        llamada por fila. Con muchos eventos (cientos o miles), esto
        es órdenes de magnitud más rápido que llamar a predict() en
        un bucle Python."""
        labels = self._model.predict(feature_matrix)
        proba_matrix = self._model.predict_proba(feature_matrix)

        results = []
        for i in range(len(feature_matrix)):
            label = int(labels[i])
            proba_dist = proba_matrix[i]
            result: dict[str, Any] = {
                "label": label, "probability": float(proba_dist[label]), "model_version": self.version,
            }
            if self.class_names:
                result["attack_cat"] = self.class_names[label]
                result["class_probabilities"] = {
                    self.class_names[j]: float(p) for j, p in enumerate(proba_dist)
                }
            results.append(result)
        return results

    def explain_batch(self, feature_matrix: np.ndarray, top_n: int = 10) -> list[dict[str, Any]]:
        """Versión en lote de explain(): SHAP calcula las
        contribuciones de TODA la matriz en una sola llamada
        vectorizada, en vez de una llamada (con su overhead de Python)
        por evento. Con 90.000 eventos, la diferencia entre esto y un
        bucle de explain() es la diferencia entre minutos y horas."""
        import shap

        if self._explainer is None:
            self._explainer = shap.TreeExplainer(self._model)

        predicted_labels = self._model.predict(feature_matrix)
        shap_values = self._explainer.shap_values(feature_matrix)
        values = np.array(shap_values)

        n_features = len(self.feature_names)
        is_multiclass = values.ndim == 3  # forma: (n_muestras, n_features, n_clases)

        results = []
        for i in range(len(feature_matrix)):
            if is_multiclass:
                row_values = values[i, :, int(predicted_labels[i])]
            else:
                row_values = values[i]
            row_values = np.asarray(row_values).reshape(-1)

            ranked = sorted(
                zip(self.feature_names, row_values),
                key=lambda kv: abs(kv[1]),
                reverse=True,
            )[:top_n]
            results.append({
                "model_version": self.version,
                "top_features": [{"feature": name, "shap_value": float(val)} for name, val in ranked],
            })
        return results

    def predict(self, feature_vector: np.ndarray) -> dict[str, Any]:
        """feature_vector debe tener las columnas en el MISMO orden
        que self.feature_names (ver features/feature_engineering.py,
        build_feature_matrix con feature_names=self.feature_names).

        Devuelve tanto el índice numérico de clase como su nombre
        (attack_cat) si el modelo es multi-clase con class_names
        registrados, y además la distribución de probabilidad
        completa sobre todas las clases — así el informe pericial
        puede mostrar el desglose completo, no solo la clase más
        probable, dejando la decisión de qué priorizar al analista."""
        x = feature_vector.reshape(1, -1)
        label = int(self._model.predict(x)[0])
        proba_dist = self._model.predict_proba(x)[0]
        proba = float(proba_dist[label])

        result: dict[str, Any] = {
            "label": label, "probability": proba, "model_version": self.version,
        }
        if self.class_names:
            result["attack_cat"] = self.class_names[label]
            result["class_probabilities"] = {
                self.class_names[i]: float(p) for i, p in enumerate(proba_dist)
            }
        return result

    def explain(self, feature_vector: np.ndarray, top_n: int = 10) -> dict[str, Any]:
        """Explicación local SHAP para un caso individual (TreeExplainer,
        eficiente y determinista para XGBoost), para la clase predicha
        (en el caso multi-clase, SHAP da un vector de contribuciones
        POR CLASE; se reporta el de la clase que el modelo eligió)."""
        import shap

        if self._explainer is None:
            self._explainer = shap.TreeExplainer(self._model)

        x = feature_vector.reshape(1, -1)
        predicted_label = int(self._model.predict(x)[0])
        shap_values = self._explainer.shap_values(x)

        values = np.array(shap_values)
        if values.ndim == 3:
            # Multi-clase: forma confirmada (n_muestras, n_features, n_clases).
            values = values[0, :, predicted_label]
        values = values.reshape(-1)

        ranked = sorted(
            zip(self.feature_names, values),
            key=lambda kv: abs(kv[1]),
            reverse=True,
        )[:top_n]

        return {
            "model_version": self.version,
            "top_features": [{"feature": name, "shap_value": float(val)} for name, val in ranked],
        }
