# MODEXRE

Sistema de detección forense de intrusiones de red con IA explicable
y cadena de custodia digital. Desarrollado como continuación del TFM1
("Generación de datos sintéticos y entrenamiento aplicando IA
Explicable para la detección, análisis forense y evidencia legal de
incidentes de ciberseguridad").

## Idea central

MODEXRE tiene **dos modos de operación**, deliberadamente separados
tanto en código como en garantías:

| | Modo Laboratorio | Modo Formal |
|---|---|---|
| Datos | Reales + sintéticos (CTGAN/SDV) | Solo evidencia real |
| Propósito | Entrenar y validar el modelo | Analizar un caso concreto |
| Cadena de custodia | No aplica | Obligatoria, verificable |
| Modelo | Se entrena y ajusta libremente | Congelado, solo inferencia |

El modo Laboratorio produce un modelo **certificado** (versionado,
con hash de integridad). El modo Formal solo puede *usar* ese modelo,
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
├── features/feature_engineering.py   Evento OCSF → vector numérico
├── models/
│   ├── training.py            Generación sintética (SDV GaussianCopula) — Laboratorio
│   └── classifier.py          XGBoost + SHAP: entrena, congela, infiere, explica
├── pipeline/formal_pipeline.py   Orquestador: ata ingesta→OCSF→features→clasificación
│                                  a la cadena de custodia, para las 3 fuentes sin etiquetar
└── report/
    ├── report_generator.py    Informe pericial: Markdown y .docx
    └── scripts/generate_report_docx.js   Generador .docx (docx-js)

frontend/app.py             Interfaz Streamlit (pestañas Laboratorio / Formal)
```

### Dos clases OCSF, a propósito

- **`Network Activity`** (`mappers.py`, `pcap_flow.py`): tráfico ya
  agregado en flujos. Los eventos de `mappers.py` vienen con
  `attack_cat`/`label` ya fijados por el TFM1 — sirven para
  **entrenar**. Los de `pcap_flow.py` no tienen etiqueta — sirven
  para **clasificar**.
- **`Detection Finding`** (`detection_finding.py`, `firewall_cef.py`):
  el "hallazgo" de OTRO sistema (Suricata, un firewall) sobre ese
  tráfico. Nunca se copia su categoría como si fuera la etiqueta de
  MODEXRE — la clasificación final la produce siempre el modelo
  propio.

### Taxonomía de ataques

Cerrada, heredada del TFM1 (ver
`app/ocsf/mappers.py::ALLOWED_ATTACK_CATEGORIES`):

```
Normal, Fuzzers, Exploits, DoS, Reconnaissance, Generic, Analysis,
Shellcode, Backdoors, DDoS, PortScan, MitM, BruteForce
```

Cualquier evento con `attack_cat` fuera de este conjunto se rechaza
explícitamente (`TaxonomyError`) en vez de inventarse una categoría
nueva.

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

Hash-chain por caso (`case_id`), sin firma digital (Nivel 2 — ver
justificación de nivel en el diseño original). Cada operación del
pipeline formal (`ingest`, `ocsf_normalize`, `feature_extract`,
`classify`) genera un eslabón con:

- hash del input y del output de esa operación,
- hash del eslabón anterior (encadenamiento),
- timestamp, componente/versión responsable.

`CustodyChain.verify(case_id)` recalcula toda la cadena y detecta
tanto la alteración de un eslabón como el borrado de uno intermedio.

## Resultados reales de entrenamiento

**Simplificación final (decisión de producto):** tras varias
iteraciones (ver historial más abajo), MODEXRE se distribuye con
**un único modelo certificado** (`models_certified/model_v1`), no una
colección de modelos a elegir. La razón: el modelo no se elige según
de dónde viene la evidencia (Suricata, firewall, PCAP, CSV) — todas
las fuentes se normalizan al mismo formato antes de llegar al
clasificador (ver `ingestion/universal.py`), así que un único modelo
sirve para cualquier fuente. Tener varios modelos a elegir solo
generaba confusión sobre cuál usar, sin aportar ninguna ventaja
práctica.

**Modelo `v1`** — multi-clase, con agregación entre flujos:

| Clases | F1 macro | Features |
|---|---|---|
| Normal, PortScan, DoS, BruteForce | 0.9538 | `agg_distinct_dst_hosts`, `agg_distinct_dst_ports`, `agg_events_in_window`, `duration`, `packets_in`, `packets_out` |

Entrenado sobre CICIDS2017 (dataset de referencia del TFM1) con
escenarios de sesión sintéticos para la señal de agregación (el CSV
limpio de CICIDS no conserva IPs, así que la continuidad de sesión
por origen no puede reconstruirse desde datos reales — ver Hallazgo 2
más abajo).

Si en el futuro se quiere retomar la comparativa entre datasets
(CICIDS/UNSW/Kitsune) con fines académicos para la memoria, el modo
Laboratorio permite reentrenar y certificar modelos adicionales en
cualquier momento — el histórico de esa comparativa (con las cifras
por dataset) se conserva a continuación como referencia de las
decisiones tomadas durante el desarrollo.

### Historial de desarrollo (referencia, no vigente)

**Conjunto final de modelos certificados** (`models_certified/`, ver
`RESUMEN.json` para el detalle programático). Superan varias
generaciones intermedias de modelos durante el desarrollo de esta
sesión (binarios simples → multi-clase → con agregación); se
documentan aquí solo los vigentes:

| Modelo | F1 macro | Propósito |
|---|---|---|
| `v1_real_cicids2017` | 0.9992 | Referencia académica (78 features CICFlowMeter, validación sobre el propio dataset) |
| `v1_multiclass_cicids2017_reduced` | 0.9656 | Triage: qué tipos de ataque hay (5 features de evidencia real) |
| `v1_multiclass_unsw_nb15_reduced` | 0.7470 | Triage |
| `v1_multiclass_kitsune_reduced` | 0.3941 | Triage (rendimiento limitado, ver Hallazgo 1/2) |
| **`v1_scan_aggregated_cicids2017`** | **0.9538** | **Recomendado**: multi-clase (Normal/PortScan/DoS/BruteForce) con agregación, escenarios sintéticos |
| **`v1_scan_aggregated_unsw_nb15`** | **0.9491** | **Recomendado**: multi-clase (Normal/PortScan/DoS/BruteForce) con agregación, escenarios sintéticos |
| **`v1_scan_aggregated_kitsune`** | **0.9320** | **Recomendado** (con agregación, DATOS REALES — mejora de 0.394 a 0.932 frente a la versión sin agregación) |

Modelos certificados con muestras estratificadas reales (90k-135k filas
por dataset) de los CSV limpios del TFM1, en `models_certified/`:

| Dataset | F1 macro | F1 weighted | Features |
|---|---|---|---|
| CICIDS2017 | 0.9992 | 0.9996 | 78 |
| UNSW-NB15 | 0.9964 | 0.9986 | 37 |
| Kitsune | 0.6623 | 0.8600 | 2 |

### Hallazgo 1 — Fuga de información detectada y corregida (Kitsune)

La primera versión entrenada con Kitsune daba F1 macro = 0.984, pese a
tener solo columnas de puerto/IP/timestamp. El análisis SHAP reveló
que la variable dominante era `time` (timestamp absoluto): el dataset
Kitsune concatena capturas separadas por tipo de ataque, así que el
modelo aprendía "en qué sesión de captura ocurrió el flujo", no un
patrón de tráfico real. Al excluir `time`, el F1 macro cayó a 0.662
— la cifra honesta. Se corrigió `feature_engineering.py` para excluir
permanentemente campos de timestamp absoluto (`time`, `timestamp`,
`stime`, `ltime`) del vector de features, con test de regresión
(`test_absolute_timestamp_fields_excluded_from_features`). Se
verificó que UNSW-NB15 no tenía el mismo problema (sus columnas
`stime`/`ltime` no afectaban al resultado).

### Hallazgo 2 — Gap de cobertura de features entre fuentes

El modelo entrenado sobre CICIDS2017 espera 78 características
(las que calcula CICFlowMeter a partir de PCAP crudo: longitudes de
cabecera, ventanas TCP, inter-arrival times detallados...). Ninguna
de las fuentes de evidencia REAL soportadas (Suricata EVE, firewall
CEF, PCAP agregado por MODEXRE) puede producir ese vector completo:
en la práctica, una alerta de Suricata solo rellena 4 de esas 78
features (`packets_in/out`, `bytes_in/out`); el resto queda a 0.0.
Esto es una limitación arquitectónica real, no un error de
implementación: el modelo de referencia (CICIDS) tiene baja cobertura
efectiva sobre evidencia derivada de fuentes distintas a un dataset
de investigación con CICFlowMeter.

**Implementado.** `models_certified/model_v1_real_cicids2017_reduced`:
mismo dataset (CICIDS2017), entrenado solo con `duration`,
`packets_in`, `packets_out`, `bytes_in`, `bytes_out` — las 5 features
que Suricata/firewall/PCAP sí pueden rellenar. F1 macro = 0.9655
(frente a 0.9992 del modelo completo, caída esperable y aceptable
dado que usa 5 features en vez de 78). Con la misma alerta de prueba
(escaneo SSH), el modelo de 78 features la clasificaba como normal
(cobertura real ~5%, features en cero empujan la predicción por
defecto); el modelo reducido la clasifica correctamente como
maliciosa (probabilidad 0.74, con `bytes_in`/`duration` como
variables más influyentes según SHAP). **Este es el modelo
recomendado para el modo Formal con evidencia real**; el modelo
completo de 78 features se mantiene como modelo de referencia para
validación académica sobre el propio dataset CICIDS, en línea con la
metodología del TFM1.

## Caso de estudio: Reconnaissance / Port Scanning

TFM2 se centra en esta categoría de ataque (presente con buen volumen
en los tres datasets: `PortScan` en CICIDS2017, UNSW-NB15 y Kitsune).
Se entrenaron detectores especializados (positivo = PortScan, negativo
= todo lo demás, incluyendo Normal y otros tipos de ataque), con
features reducidas por dataset, en `models_certified/`:

| Dataset | Features | F1 macro | Precision | Recall |
|---|---|---|---|---|
| CICIDS2017 | duration, packets_in/out, bytes_in/out | 0.9996 | 0.9997 | 0.9995 |
| UNSW-NB15 | duration, packets_in/out, bytes_in/out | 0.9224 | 0.9626 | 0.8902 |
| Kitsune | dport, sport | 0.9997 | 0.9999 | 0.9995 |

Kitsune, que rendía mal en clasificación multi-clase genérica (F1
macro 0.66, ver hallazgo anterior), rinde excelente aquí — tiene
sentido: la diversidad de puertos destino (`dport`) es una señal casi
perfecta específicamente para escaneo, aunque insuficiente para
distinguir entre las demás 6 categorías de ataque.

### Hallazgo 3 — La detección de escaneo necesita agregación entre flujos (RESUELTO)

Al probar el detector especializado sobre el caso de prueba real
(alerta Suricata "ET SCAN SSH BruteForce", un único flujo agregado de
500 paquetes/45KB), el modelo lo clasificó como NO-PortScan con alta
confianza (0.9999) — en clara discrepancia con el detector genérico
(que sí lo marcaba como malicioso, 0.74). Análisis: el modelo
especializado tenía razón dado lo que veía. Un escaneo real se
manifiesta como MUCHOS flujos distintos, cada uno con pocos paquetes
(una conexión corta por puerto probado) — no como un único flujo de
500 paquetes, que se parece más a fuerza bruta o transferencia de
datos. El pipeline clasificaba evento a evento, sin agregación
temporal entre flujos del mismo origen.

**Solución implementada**: `features/flow_aggregation.py`, un nuevo
paso del pipeline formal (`ingest → ocsf_normalize → aggregate →
feature_extract → classify`, con su propio eslabón de cadena de
custodia). Para cada evento, calcula de forma CAUSAL (solo eventos
pasados o simultáneos del mismo `src_ip`, nunca del futuro — necesario
para que el diseño sea válido en un sistema operando en tiempo real)
tres variables: `agg_distinct_dst_ports`, `agg_distinct_dst_hosts`,
`agg_events_in_window`, dentro de una ventana temporal configurable
(60s por defecto). Validado con un caso real de 8 alertas del mismo
origen a 8 puertos distintos: el último evento de la secuencia ve
correctamente los 8 puertos, el primero solo se ve a sí mismo, y un
caso de contraste (5 eventos al mismo puerto, tráfico normal repetido)
produce `agg_distinct_dst_ports=1` frente a `=5` del patrón de
escaneo — la señal distingue ambos casos con claridad
(`test_flow_aggregation_pipeline.py`).


## Clasificación multi-clase (no un único ataque fijado)

Decisión de diseño corregida a mitad de desarrollo: inicialmente se
entrenaron detectores binarios especializados en una sola categoría
(PortScan). Se corrigió porque invertía el orden correcto de un
análisis pericial: el sistema debe primero mostrar QUÉ tipos de
ataque hay en la evidencia, y el analista decide DESPUÉS en cuál
centrarse — no al revés.

El clasificador (`train_multiclass_from_labels` en
`models/classifier.py`) predice ahora la categoría completa
(`attack_cat`, incluyendo "Normal"), no un binario. `FrozenClassifier.
predict()` devuelve tanto la clase más probable como la distribución
de probabilidad sobre TODAS las categorías presentes en el
entrenamiento (`class_probabilities`), que se refleja íntegra en el
informe pericial — así el juez/analista ve el desglose completo, no
solo el veredicto del modelo.

Modelos multi-clase certificados (`models_certified/`, features
reducidas, mismas 6 categorías presentes en la muestra de CICIDS,
9 en UNSW, 7 en Kitsune):

| Dataset | F1 macro | Nº clases |
|---|---|---|
| CICIDS2017 | 0.9656 | 6 |
| UNSW-NB15 | 0.7470 | 9 |
| Kitsune | 0.3941 | 7 |

El coste de distinguir entre más categorías con menos features es
visible y esperado: Kitsune (solo `dport`/`sport` disponibles) cae de
forma pronunciada frente a su detector binario especializado (0.9997
para "es PortScan sí/no" vs. 0.39 para "cuál de 7 categorías es") —
dos features simplemente no bastan para separar 7 clases, aunque sí
basten para una decisión binaria bien definida. Esto es un trade-off
real a discutir en la memoria: multi-clase da más información útil al
analista, pero exige más riqueza de features de la que la evidencia
externa (Suricata/firewall/PCAP) puede aportar en según qué fuente.

**Corrección de diseño (requisito explícito):** el software debe
determinar el tipo de ataque en cada caso, diferenciando entre varias
tipologías y no solo "ataque sí/no" — esto aplica a CUALQUIER
evidencia subida, se suba lo que se suba. Los modelos
`v1_scan_aggregated_*` se reentrenaron para ser multi-clase (no
binarios) manteniendo la agregación entre flujos:

| Dataset | F1 macro | Clases | Datos de entrenamiento |
|---|---|---|---|
| CICIDS2017 | 0.9538 | Normal, PortScan, DoS, BruteForce | Sintético de escenario |
| UNSW-NB15 | 0.9491 | Normal, PortScan, DoS, BruteForce | Sintético de escenario |
| Kitsune | 0.9320 | Normal, PortScan, DoS, DDoS, Fuzzers, Generic, MitM (7) | **Datos reales** |

Estos son los modelos recomendados por defecto en la interfaz para
cualquier análisis en modo Formal, independientemente de la fuente de
evidencia (CSV, Suricata, firewall, PCAP) — el ingestor universal
(`ingestion/universal.py`) normaliza todo a la misma taxonomía cerrada
antes de llegar al clasificador, así que el resultado siempre es
comparable entre fuentes.

## Cómo ejecutarlo

```bash
pip install -r requirements.txt
streamlit run frontend/app.py
```

En la pestaña **Laboratorio**: sube un CSV limpio (formato TFM1),
opcionalmente genera sintético, entrena y certifica un modelo.

En la pestaña **Formal**: sube evidencia real (Suricata EVE JSON,
log de firewall CEF, o PCAP), elige un modelo certificado, y genera
el expediente pericial con cadena de custodia verificada.

## Tests

```bash
cd backend && python -m pytest tests/ -v
```

72 tests, cubriendo cada capa de forma aislada y varios recorridos
end-to-end reales (entrenar → congelar → inferir → explicar; ingesta
→ OCSF → features → clasificación → custodia → informe).

## Generar el informe pericial en Word

```python
from app.report.report_generator import generate_report_docx
generate_report_docx(report, chain.get_chain(case_id), "informe.docx")
```

Requiere Node.js y la librería npm `docx` instalada (usada solo para
este paso; el resto del backend es Python puro).

## Limitaciones conocidas (alcance consciente, no bugs)

- El modelo de clasificación se ha validado hasta ahora con datos de
  prueba pequeños en los tests. El entrenamiento con el dataset real
  completo del TFM1 (`*_full_clean.csv`) queda pendiente de ejecutar
  y documentar con sus métricas finales en la memoria.
- El parser CEF no cubre dialectos propietarios completos de cada
  fabricante de firewall.
- La agregación de flujo desde PCAP es una implementación propia
  simplificada, no un sustituto completo de CICFlowMeter.
- La cadena de custodia es Nivel 2 (hash-chain sin firma digital); el
  Nivel 3 (con firma) se deja como línea futura, igual que se planteó
  en el TFM1.
