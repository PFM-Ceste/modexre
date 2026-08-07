"""
MODEXRE — Interfaz
=====================

Amarra los dos modos ya construidos sobre el mismo backend:

  - LABORATORIO: sube un CSV limpio (formato TFM1: attack_cat/label
    normalizados), genera datos sintéticos, entrena XGBoost, evalúa
    F1 macro/weighted, y certifica el modelo (lo congela con hash de
    integridad) para su uso en modo Formal.

  - FORMAL: sube evidencia real (Suricata EVE JSON / firewall CEF /
    PCAP), elige un modelo ya certificado, y genera un expediente
    pericial completo con cadena de custodia verificada y explicación
    SHAP por evento.

Ejecutar con:  streamlit run frontend/app.py
(desde el directorio backend/ en el PYTHONPATH, o con
 PYTHONPATH=backend streamlit run frontend/app.py)
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.custody.chain import CustodyChain
from app.features.feature_engineering import build_feature_matrix, extract_label
from app.models.classifier import (
    FrozenClassifier,
    save_model_artifact,
    train_multiclass_from_labels,
    train_xgboost_classifier,
)
from app.models.training import SyntheticGenerationConfig, generate_synthetic_dataset
from app.ocsf.mappers import event_to_ocsf
from app.pipeline.formal_pipeline import FormalCaseRunner
from app.report.report_generator import (
    generate_report_docx,
    generate_report_docx_judicial,
    build_category_summary,
    filter_report_by_categories,
    aggregate_shap_by_category,
    ATTACK_LABEL_MAP,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(tempfile.gettempdir()) / "modexre_data"
# Los modelos certificados viven en el propio proyecto (models_certified/),
# no en una carpeta temporal: así los modelos que ya vienen entrenados
# (v1_scan_aggregated_*, etc.) aparecen automáticamente en la interfaz,
# y los que entrenes tú desde la pestaña Laboratorio se guardan en el
# mismo sitio, disponibles entre reinicios de la aplicación.
MODEL_DIR = PROJECT_ROOT / "models_certified"
CASE_DIR = DATA_DIR / "cases"
for d in (DATA_DIR, MODEL_DIR, CASE_DIR):
    d.mkdir(parents=True, exist_ok=True)


st.set_page_config(page_title="MODEXRE", layout="wide", page_icon="🛡️")

# Estilo propio: cabecera con banner degradado, tarjetas con sombra
# sutil, y botones/pestañas con esquinas redondeadas — sin depender de
# ningún fichero externo (todo vía CSS embebido), para que funcione
# igual en cualquier máquina donde se ejecute la app.
st.markdown("""
<style>
    .modexre-banner {
        background: linear-gradient(135deg, #1A3A5C 0%, #2E5A8A 60%, #3E7CB8 100%);
        padding: 1.6rem 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 14px rgba(26, 58, 92, 0.25);
    }
    .modexre-banner h1 {
        color: white !important;
        margin: 0;
        font-size: 2.1rem;
        letter-spacing: 0.5px;
    }
    .modexre-banner p {
        color: #D6E4F0;
        margin: 0.3rem 0 0 0;
        font-size: 0.95rem;
    }
    div[data-testid="stExpander"] {
        border-radius: 10px;
        border: 1px solid #DDE5EE;
        box-shadow: 0 1px 4px rgba(0,0,0,0.04);
    }
    .stButton > button, .stDownloadButton > button {
        border-radius: 8px;
        font-weight: 600;
    }
    div[data-testid="stMetric"] {
        background-color: #EEF2F7;
        border-radius: 10px;
        padding: 0.8rem 1rem;
        border: 1px solid #DDE5EE;
    }
</style>
<div class="modexre-banner">
    <h1>🛡️ MODEXRE</h1>
    <p>Detección forense de intrusiones con IA explicable y cadena de custodia</p>
</div>
""", unsafe_allow_html=True)

tab_lab, tab_formal = st.tabs(["🧪 Laboratorio", "⚖️ Formal"])


# =====================================================================
# MODO LABORATORIO
# =====================================================================
with tab_lab:
    st.header("Modo Laboratorio")
    st.markdown(
        "Entrena y certifica el modelo aquí, con datos reales y/o sintéticos. "
        "Nada de lo que ocurre en esta pestaña genera cadena de custodia."
    )

    st.info(
        "📚 **¿Qué subir aquí?** Un dataset de investigación YA ETIQUETADO "
        "(CICIDS2017, UNSW-NB15, Kitsune, o similar), con columnas `attack_cat` "
        "y `label`. Sirve para **entrenar** el modelo, no para analizar un caso.\n\n"
        "❌ Si tienes evidencia real de un caso concreto (una alerta de "
        "Suricata, un log de firewall, un PCAP, o un CSV SIN etiquetar) "
        "— eso va en la pestaña **⚖️ Formal**, no aquí."
    )

    uploaded_csv = st.file_uploader(
        "CSV limpio (formato TFM1: attack_cat/label como primeras columnas)",
        type=["csv"],
        key="lab_csv",
    )

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("1. Generación sintética (opcional)")
        generate_synth = st.checkbox("Generar datos sintéticos con SDV antes de entrenar")
        normal_n = st.number_input("Normal (sintético)", value=2000, step=500)
        attack_n_each = st.number_input("Por clase de ataque (sintético)", value=500, step=100)

    with col_b:
        st.subheader("2. Entrenamiento")

        # CORRECCIÓN: antes era un st.text_input libre con
        # value="v1" fijo -- fácil escribir por error el nombre de
        # una versión ya certificada (o simplemente no cambiar el
        # valor por defecto) y sobrescribir un modelo ya validado sin
        # darse cuenta. Ahora se detectan las versiones existentes,
        # se sugiere automáticamente la siguiente disponible (v1, v2,
        # v3... el primer hueco libre), y se avisa explícitamente si
        # el nombre elegido coincide con uno ya certificado.
        _existing_versions = sorted(
            m.stem.replace(".manifest", "").replace("model_", "")
            for m in MODEL_DIR.glob("*.manifest.json")
        )

        def _next_free_version(existing: list[str]) -> str:
            n = 1
            while f"v{n}" in existing:
                n += 1
            return f"v{n}"

        _suggested = _next_free_version(_existing_versions)
        _options = _existing_versions + [f"{_suggested} (nueva)"]

        if _existing_versions:
            st.caption(f"Versiones ya certificadas: {', '.join(_existing_versions)}")

        _version_choice = st.selectbox(
            "Versión del modelo a certificar",
            options=_options,
            index=len(_options) - 1,  # por defecto, la nueva sugerida
        )

        if _version_choice.endswith(" (nueva)"):
            model_version = _version_choice.replace(" (nueva)", "")
        else:
            model_version = _version_choice
            st.warning(
                f"⚠️ '{model_version}' ya existe y está certificado. Si entrenas y "
                f"certificas ahora, **se sobrescribirá** el modelo actual (el "
                f"anterior dejará de estar disponible en modo Formal, aunque su "
                f"hash quede en el historial si ya se usó en algún caso). Si no "
                f"quieres sobrescribirlo, elige '{_suggested} (nueva)' en su lugar."
            )

        train_button = st.button("Entrenar y certificar modelo", type="primary")

    if train_button:
        if uploaded_csv is None:
            st.error("Sube primero un CSV limpio.")
        else:
            with st.spinner("Procesando..."):
                tmp_csv = DATA_DIR / uploaded_csv.name
                tmp_csv.write_bytes(uploaded_csv.getvalue())

                training_csv = tmp_csv
                if generate_synth:
                    syn_csv = DATA_DIR / f"synthetic_{uploaded_csv.name}"
                    config = SyntheticGenerationConfig(normal_n=int(normal_n), attack_n_each=int(attack_n_each))
                    summary = generate_synthetic_dataset("uploaded", tmp_csv, syn_csv, config)
                    st.info(f"Sintético generado: {summary.synthetic_rows_total} filas, "
                            f"clases: {summary.attack_categories_found}")
                    training_csv = syn_csv

                import pandas as pd
                df = pd.read_csv(training_csv)
                df.columns = [str(c).strip().lower() for c in df.columns]
                if "attack_cat" not in df.columns or "label" not in df.columns:
                    st.error("El CSV no contiene attack_cat/label. No se puede entrenar.")
                else:
                    events = [
                        event_to_ocsf("cicids2017", row)
                        for row in df.to_dict(orient="records")
                    ]
                    X, feature_names = build_feature_matrix(events)

                    # CORRECCIÓN: antes se entrenaba en modo binario
                    # (extract_label -> 0/1) descartando por completo
                    # attack_cat, aunque el CSV subido trajera decenas
                    # de miles de filas con la categoría completa
                    # (PortScan, Reconnaissance, BruteForce...). Esto
                    # producía modelos "certificados" que en Formal
                    # solo podían distinguir Normal/Ataque genérico,
                    # nunca la categoría específica -- confirmado en
                    # el caso real case_2026_001, donde model_v2 (pese
                    # a haberse entrenado con datos que sí distinguían
                    # Reconnaissance de PortScan por su patrón real de
                    # agregación) nunca llegó a aprender esa distinción,
                    # porque el propio flujo de certificación se la
                    # ocultaba antes de entrenar.
                    attack_cat_labels = [
                        e.get("unmapped", {}).get("attack_cat") for e in events
                    ]
                    model, metrics, encoder = train_multiclass_from_labels(X, attack_cat_labels)
                    manifest = save_model_artifact(
                        model, feature_names, metrics, model_version, MODEL_DIR,
                        class_names=encoder.classes_.tolist(),
                    )

                    st.success(f"Modelo '{model_version}' certificado y congelado.")
                    st.json(manifest["metrics"])
                    st.caption(f"Clases aprendidas: {', '.join(encoder.classes_.tolist())}")
                    st.caption(f"Hash del modelo: `{manifest['model_hash'][:16]}...`")

    st.divider()
    st.subheader("Modelos certificados disponibles")
    manifests = sorted(MODEL_DIR.glob("*.manifest.json"))
    if not manifests:
        st.write("Ningún modelo certificado todavía.")
    else:
        for m in manifests:
            import json
            data = json.loads(m.read_text())
            st.write(f"**{data['version']}** — F1 macro: {data['metrics']['f1_macro']:.3f} "
                      f"— {data['trained_at']}")


# =====================================================================
# MODO FORMAL
# =====================================================================
with tab_formal:
    st.header("Modo Formal")
    st.markdown(
        "Analiza evidencia real. Cada paso queda registrado en una cadena de "
        "custodia verificable. El modelo usado aquí nunca se reentrena."
    )

    st.info(
        "⚖️ **¿Qué subir aquí?** La evidencia de UN CASO concreto que quieres "
        "analizar: una alerta/log de Suricata (`.json`), un log de firewall "
        "(`.log`/`.txt` con formato CEF), una captura de red (`.pcap`), o un "
        "CSV de flujo — con o sin etiquetar. No hace falta que le digas el "
        "tipo, MODEXRE lo detecta solo.\n\n"
        "❌ No subas aquí un dataset de investigación completo (decenas de "
        "miles de filas) solo para \"probar\" — eso es lo que sirve para "
        "**entrenar** en la pestaña **🧪 Laboratorio**, y aquí tardaría mucho "
        "más de lo necesario sin aportar nada distinto."
    )

    available_versions = [
        m.stem.replace(".manifest", "").replace("model_", "")
        for m in sorted(MODEL_DIR.glob("*.manifest.json"))
    ]
    if not available_versions:
        st.warning("No hay ningún modelo certificado. Ve primero a la pestaña Laboratorio.")
    else:
        case_id = st.text_input("Identificador del caso", value="case_2026_001")
        col_cliente, col_perito = st.columns(2)
        with col_cliente:
            cliente = st.text_input("Cliente / destinatario del informe", value="")
        with col_perito:
            perito = st.text_input("Perito / responsable del análisis", value="")

        tipo_informe = st.radio(
            "Tipo de informe a generar",
            options=["tecnico", "juridico"],
            format_func=lambda t: {
                "tecnico": "📋 Técnico completo (detalle evento a evento, para auditor/perito contrario)",
                "juridico": "⚖️ Jurídico (agrupado por tipo de ataque, para presentar ante un Juzgado)",
            }[t],
            horizontal=False,
        )
        if tipo_informe == "juridico":
            col_j1, col_j2 = st.columns(2)
            with col_j1:
                juzgado = st.text_input("Juzgado", value="JUZGADO DE INSTRUCCIÓN N.º [A COMPLETAR]")
                perito_titulacion = st.text_input(
                    "Titulación del perito",
                    value="Analista forense en ciberseguridad — Especialista en Inteligencia Artificial",
                )
            with col_j2:
                procedimiento = st.text_input("Procedimiento", value="DILIGENCIAS PREVIAS N.º [A COMPLETAR] / [AÑO]")
                perito_colegiado = st.text_input("N.º de colegiado (si aplica)", value="")

        auto_detect = st.checkbox(
            "Detectar automáticamente el tipo de fichero (recomendado)", value=True
        )
        if auto_detect:
            source_type = "auto"
            st.caption(
                "Sube cualquier evidencia: CSV de flujo (con o sin etiquetar), "
                "Suricata EVE JSON, log de firewall CEF, o PCAP. MODEXRE detecta "
                "el tipo y lo normaliza automáticamente."
            )
        else:
            source_type = st.selectbox(
                "Tipo de fuente (forzado manualmente)",
                options=["suricata_eve", "firewall_cef", "pcap"],
                format_func=lambda s: {
                    "suricata_eve": "Suricata EVE JSON (IDS/IPS)",
                    "firewall_cef": "Firewall (syslog/CEF)",
                    "pcap": "Captura PCAP",
                }[s],
            )
        if len(available_versions) == 1:
            model_version_sel = available_versions[0]
            st.caption(f"Modelo: **{model_version_sel}** (único disponible).")
        else:
            model_version_sel = st.selectbox(
                "Modelo certificado a usar",
                options=sorted(available_versions, key=lambda v: "scan_aggregated" not in v and v != "v1"),
            )

        evidence_file = st.file_uploader(
            "Fichero de evidencia",
            type=["json", "log", "txt", "pcap", "pcapng", "csv"],
            key="formal_evidence",
        )

        run_button = st.button("Ejecutar análisis pericial", type="primary")

        if run_button:
            if evidence_file is None:
                st.error("Sube primero un fichero de evidencia.")
            else:
                evidence_path = CASE_DIR / f"{case_id}_{evidence_file.name}"
                evidence_path.write_bytes(evidence_file.getvalue())

                classifier = FrozenClassifier(MODEL_DIR, version=model_version_sel)
                chain = CustodyChain(CASE_DIR / f"{case_id}.db")
                runner = FormalCaseRunner(chain, classifier)

                STEP_ICONS = {
                    "ingest": "📥", "ocsf_normalize": "🔄", "aggregate": "🧩",
                    "feature_extract": "🧮", "classify": "🧠", "verify": "🔐",
                    "done": "✅",
                }
                with st.status("Ejecutando pipeline pericial...", expanded=True) as status_box:
                    def on_step(step_name, info):
                        icon = STEP_ICONS.get(step_name, "•")
                        status_box.write(f"{icon} **{info['label']}** — {info['detail']}")

                    report = runner.run(
                        case_id=case_id, source_type=source_type,
                        path=evidence_path, on_step=on_step,
                    )
                    status_box.update(label="Pipeline completado", state="complete", expanded=False)

                # Se guarda en session_state para que elegir categorías más
                # abajo (que provoca un rerun de todo el script, como
                # cualquier interacción en Streamlit) no obligue a repetir
                # el análisis completo cada vez.
                st.session_state["case_report"] = report
                st.session_state["case_chain_records"] = chain.get_chain(case_id)
                st.session_state["case_id_analizado"] = case_id

        # ---- Resultados: se muestran si hay un análisis guardado para
        # este caso, tanto si se acaba de ejecutar como si ya estaba ----
        if st.session_state.get("case_id_analizado") == case_id and "case_report" in st.session_state:
            report = st.session_state["case_report"]
            chain_records = st.session_state["case_chain_records"]

            verification = report.custody_verification or {}
            if verification.get("valid"):
                st.success(f"Cadena de custodia íntegra ({verification.get('total_records')} eslabones).")
            else:
                st.error("⚠️ La cadena de custodia presenta incidencias. Ver detalle abajo.")

            st.divider()
            st.subheader("Resumen por tipo de ataque")
            category_summary = build_category_summary(report)
            if not category_summary:
                st.info("No se ha podido clasificar ningún evento (evidencia vacía o sin eventos válidos).")
            else:
                for row in category_summary:
                    icon = "🟢" if row["categoria"] == "Normal" else "🔴"
                    with st.container(border=True):
                        st.markdown(f"{icon} **{row['categoria']}** — {row['n_eventos']} evento(s), "
                                    f"probabilidad media {row['probabilidad_media']:.2f}")
                        col_src, col_dst = st.columns(2)
                        with col_src:
                            st.caption("IPs de origen: " + (", ".join(row["src_ips"]) or "n/d"))
                        with col_dst:
                            st.caption("IPs de destino: " + (", ".join(row["dst_ips"]) or "n/d"))

                all_categories = [row["categoria"] for row in category_summary]
                default_selection = [c for c in all_categories if c != "Normal"] or all_categories
                categorias_elegidas = st.multiselect(
                    "Categorías a incluir en el informe",
                    options=all_categories,
                    default=default_selection,
                    help="Por defecto se excluye 'Normal' del informe (no suele interesar en un "
                         "expediente pericial), pero puedes incluirla si la necesitas.",
                )

                st.divider()
                st.subheader("Análisis agregado por categoría seleccionada")
                for cat in categorias_elegidas:
                    cat_findings = [f for f in report.findings if
                                     (f.prediction.get("attack_cat") or ATTACK_LABEL_MAP.get(f.prediction["label"])) == cat]
                    if not cat_findings:
                        continue
                    probs = [f.prediction["probability"] for f in cat_findings]
                    icon = "🟢" if cat == "Normal" else "🔴"
                    with st.expander(f"{icon} **{cat}** — {len(cat_findings)} evento(s), "
                                      f"probabilidad media {sum(probs)/len(probs):.2f}", expanded=True):
                        st.write("**Variables más influyentes (SHAP agregado de todos los eventos de esta categoría):**")
                        for feat in aggregate_shap_by_category(cat_findings):
                            st.write(f"- `{feat['feature']}`: {feat['contribucion_agregada']:.3f}")

                st.divider()
                if st.button("📝 Generar informe con las categorías seleccionadas", type="primary"):
                    filtered_report = filter_report_by_categories(report, categorias_elegidas)

                    if tipo_informe == "juridico":
                        docx_bytes = generate_report_docx_judicial(
                            filtered_report, chain_records,
                            juzgado=juzgado, procedimiento=procedimiento,
                            perito_nombre=perito or "[NOMBRE DEL PERITO]",
                            perito_titulacion=perito_titulacion,
                            perito_colegiado=perito_colegiado or "[N.º de colegiado, si aplica]",
                            cliente=cliente or "No especificado",
                        )
                        file_label, file_suffix = "jurídico", "juridico"
                    else:
                        docx_bytes = generate_report_docx(
                            filtered_report, chain_records,
                            cliente=cliente or "No especificado",
                            perito=perito or "Sistema MODEXRE (análisis automatizado)",
                        )
                        file_label, file_suffix = "técnico", "tecnico"

                    st.download_button(
                        f"📄 Descargar informe {file_label} (Word)",
                        data=docx_bytes,
                        file_name=f"informe_{file_suffix}_{case_id}.docx",
                        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    )
