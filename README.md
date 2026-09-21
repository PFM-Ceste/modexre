# MODEXRE

**MOdular Digital EXamination & Reporting Environment**

Sistema de detección forense de intrusiones de red con inteligencia
artificial explicable (XAI) y cadena de custodia digital verificable.

Desarrollado como continuación del Trabajo de Fin de Máster
*"Generación de datos sintéticos y entrenamiento aplicando IA
Explicable para la detección, análisis forense y evidencia legal de
incidentes de ciberseguridad"* (TFM1), que validó en laboratorio un
clasificador XGBoost con explicabilidad SHAP sobre datos reales y
sintéticos. MODEXRE traslada ese modelo a un flujo pericial operativo.

---

## Idea central

MODEXRE tiene **dos modos de operación**, deliberadamente separados
tanto en código como en garantías:

| | Modo Laboratorio | Modo Formal |
|---|---|---|
| Datos | Reales + sintéticos (CTGAN/SDV) | Solo evidencia real |
| Propósito | Entrenar y validar el modelo | Analizar un caso concreto |
| Cadena de custodia | No aplica | Obligatoria, verificable |
| Modelo | Se entrena y ajusta libremente | Congelado, solo inferencia |

El modo Laboratorio produce un modelo **certificado** (versionado, con
hash de integridad). El modo Formal solo puede *usar* ese modelo,
nunca reentrenarlo — así se puede demostrar que el sistema que
clasificó la evidencia de un caso es exactamente el mismo que se
validó en Laboratorio, sin deriva entre ambos momentos.

## Arquitectura

```
backend/app/
├── custody/chain.py        Cadena de custodia (hash-chain, sin firma — Nivel 2)
├── ingestion/
│   ├── connectors.py         CSV limpios (TFM1), JSONL, texto plano línea a línea
│   └── pcap_reader.py        Agregación de paquetes PCAP a flujos (5-tupla)
├── ocsf/
│   ├── mappers.py             Network Activity — datos YA ETIQUETADOS (entrenamiento)
│   ├── detection_finding.py   Detection Finding — alertas Suricata (sin etiquetar)
│   ├── firewall_cef.py        Detection Finding — logs de firewall CEF/syslog
│   └── pcap_flow.py           Network Activity — flujos de PCAP (sin etiquetar)
├── features/
│   ├── feature_engineering.py Evento OCSF → vector numérico
│   └── flow_aggregation.py    Agregación causal entre flujos (ventana temporal)
├── models/
│   ├── training.py            Generación sintética (SDV GaussianCopula) — Laboratorio
│   └── classifier.py          XGBoost + SHAP: entrena, congela, infiere, explica
├── pipeline/formal_pipeline.py   Orquestador: ingesta → OCSF → agregación → features → clasificación → custodia
└── report/
    ├── report_generator.py    Informe pericial: Markdown y .docx
    └── scripts/generate_report_docx.js   Generador .docx (docx-js)

frontend/app.py             Interfaz Streamlit (pestañas Laboratorio / Formal)
```

El backend expone además una **API REST con FastAPI**
(`backend/app/main.py`), usada por la interfaz Streamlit y disponible
también para integraciones externas.

### Dos clases OCSF, a propósito

- **`Network Activity`** (`mappers.py`, `pcap_flow.py`): tráfico ya
  agregado en flujos. Los eventos de `mappers.py` vienen con
  `attack_cat`/`label` ya fijados por el TFM1 — sirven para
  **entrenar**. Los de `pcap_flow.py` no tienen etiqueta — sirven
  para **clasificar**.
- **`Detection Finding`** (`detection_finding.py`, `firewall_cef.py`):
  el "hallazgo" de OTRO sistema (Suricata, un firewall) sobre ese
  tráfico. Nunca se copia su categoría como si fuera la etiqueta de
  MODEXRE — la clasificación final la produce siempre el modelo propio.

### Taxonomía de ataques

Cerrada, heredada del TFM1 (`app/ocsf/mappers.py::ALLOWED_ATTACK_CATEGORIES`):

```
Normal, Fuzzers, Exploits, DoS, Reconnaissance, Generic, Analysis,
Shellcode, Backdoors, DDoS, PortScan, MitM, BruteForce
```

Cualquier evento con `attack_cat` fuera de este conjunto se rechaza
explícitamente (`TaxonomyError`) en vez de inventarse una categoría nueva.

## Fuentes de ingesta soportadas

| Fuente | Formato | ¿Etiquetada? | Uso típico |
|---|---|---|---|
| `cicids2017` / `unsw_nb15` / `kitsune` | CSV limpio (TFM1) | Sí | Entrenamiento |
| `suricata_eve` | JSONL (EVE JSON) | No | Análisis pericial |
| `firewall_cef` | Texto plano (CEF/syslog) | No | Análisis pericial |
| `pcap` | Binario PCAP | No | Análisis pericial |

El parser CEF cubre el núcleo del estándar (campos comunes a la
mayoría de fabricantes: `src`, `dst`, `spt`, `dpt`, `proto`, `act`,
`cat`, `msg`), no dialectos propietarios completos por marca — límite
de alcance consciente. La agregación de PCAP a flujo es una
implementación propia simple (5-tupla + corte por inactividad), no
pretende igualar a CICFlowMeter en su totalidad.

## Cadena de custodia

Hash-chain por caso (`case_id`), sin firma digital (Nivel 2). Cada
operación del pipeline formal (`ingest`, `ocsf_normalize`,
`aggregate`, `feature_extract`, `classify`) genera un eslabón con:

- hash del input y del output de esa operación,
- hash del eslabón anterior (encadenamiento),
- timestamp, componente/versión responsable.

`CustodyChain.verify(case_id)` recalcula toda la cadena y detecta
tanto la alteración de un eslabón como el borrado de uno intermedio.

## Modelo certificado por defecto

El modelo recomendado para uso pericial es
**`models_certified/model_v3`**, multi-clase, con agregación causal entre
flujos y con las tres correcciones de la decisión de diseño 4 aplicadas.
La versión recomendada se declara en `models_certified/RESUMEN.json`, que
es la fuente de verdad que lee la interfaz para preseleccionarla:

| Modelo | Clases | F1 macro | n_train | Features |
|---|---|---|---|---|
| **v3** (recomendado) | 18 categorías (UNSW-NB15 + CICIDS2017) | 0.6214 | 242.361 | las 6 de v1 más `agg_events_per_second` |
| v1 (referencia) | Normal, PortScan, DoS, BruteForce | 0.9538 | 3.448 | `agg_distinct_dst_hosts`, `agg_distinct_dst_ports`, `agg_events_in_window`, `duration`, `packets_in`, `packets_out` |

Los dos F1 macro **no son comparables**: v1 mide una tarea de 4 categorías
y v3 una de 18. El descenso no indica un modelo peor, sino una tarea más
exigente. v1 es además anterior a la corrección de la decisión de diseño 4,
por lo que se conserva solo como referencia comparativa en modo Laboratorio.

El modelo no se elige según la fuente de la evidencia: el ingestor
universal (`ingestion/universal.py`) normaliza toda fuente al mismo
formato antes de llegar al clasificador, así que un único modelo
certificado sirve para cualquier fuente soportada.

Modelos certificados adicionales (comparativa por dataset, uso en
modo Laboratorio) y el detalle de los tres hallazgos del desarrollo
(fuga de información en Kitsune, gap de cobertura de características,
necesidad de agregación temporal) se documentan en la memoria del
proyecto.

## Cómo ejecutarlo

```bash
git clone https://github.com/PFM-Ceste/modexre.git
cd modexre
pip install -r requirements.txt
```

**API backend (FastAPI):**

```bash
uvicorn backend.app.main:app --reload
```

**Interfaz Streamlit:**

```bash
streamlit run frontend/app.py
```

**En Windows, arranque rápido con doble clic:**

En vez de escribir el comando anterior a mano cada vez, el repositorio
incluye `Arrancar_MODEXRE.bat` en la raíz del proyecto: haz doble
clic sobre él y arranca la interfaz Streamlit automáticamente desde
la carpeta donde hayas clonado el proyecto (no importa cuál sea).

Para tener un acceso directo en el escritorio con icono propio,
ejecuta una sola vez `Crear_Acceso_Directo.ps1` (clic derecho →
"Ejecutar con PowerShell"; si Windows bloquea el script, abre
PowerShell como administrador y ejecuta primero
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`).

- **Pestaña Laboratorio**: sube un CSV limpio (formato TFM1),
  opcionalmente genera datos sintéticos, entrena y certifica un modelo.
- **Pestaña Formal**: sube evidencia real (Suricata EVE JSON, log de
  firewall CEF, o PCAP), elige un modelo certificado, y genera el
  expediente pericial con cadena de custodia verificada.

## Tests

```bash
cd backend && python -m pytest tests/ -v
```

139 tests en 20 módulos, cubriendo cada capa de forma aislada y varios
recorridos end-to-end reales (entrenar → congelar → inferir → explicar; ingesta
→ OCSF → agregación → features → clasificación → custodia → informe).

## Generar el informe pericial en Word

```python
from app.report.report_generator import generate_report_docx
generate_report_docx(report, chain.get_chain(case_id), "informe.docx")
```

Usa **python-docx**, ya incluido en `requirements.txt`. No hace falta
Node.js ni ninguna dependencia adicional.

El repositorio conserva además una vía alternativa basada en la librería
npm `docx` (`backend/app/report/scripts/generate_report_docx.js`), que la
aplicación **no** utiliza. Solo si se invoca explícitamente
`generate_report_docx_via_node()` hace falta Node.js:

```bash
npm install docx   # solo para la vía alternativa
```

## Limitaciones conocidas (alcance consciente, no bugs)

- El modelo por defecto (`model_v3`) se entrenó sobre 242.361 eventos
  (60.591 de prueba). El entrenamiento sobre el dataset real completo
  del TFM1, con sus métricas finales documentadas, queda pendiente.
- El parser CEF no cubre dialectos propietarios completos de cada
  fabricante de firewall.
- La agregación de flujo desde PCAP es una implementación propia
  simplificada, no un sustituto completo de CICFlowMeter.
- La cadena de custodia es Nivel 2 (hash-chain sin firma digital); el
  Nivel 3 (con firma digital y no repudio) se deja como línea futura.

## Contexto académico

Proyecto Final de Máster — Máster en Redes Informáticas y Seguridad
(MRC), CESTE Escuela Internacional de Negocios, partner de University
of Wales Trinity Saint David (UWTSD). Curso 2025-2026.

## Licencia

Pendiente de definir por el autor.
