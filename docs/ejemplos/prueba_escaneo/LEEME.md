# Caso de prueba: escaneo de puertos

`eve_ejemplo_escaneo.json`: 8 alertas simuladas de Suricata, mismo
origen (198.51.100.23), 8 puertos destino distintos en segundos —
patrón clásico de escaneo.

## Cómo probarlo en tu interfaz local

1. `streamlit run frontend/app.py`
2. Pestaña **Formal**:
   - Tipo de fuente: `Suricata EVE JSON (IDS/IPS)`
   - Modelo certificado: `v1_scan_aggregated_cicids2017` (el único
     entrenado con la señal de agregación entre flujos; los demás
     modelos `v1_multiclass_*`/`v1_real_*` NO la usan)
   - Sube `eve_ejemplo_escaneo.json`
3. Resultado esperado: los 8 eventos clasificados como `PortScan`,
   con `agg_distinct_dst_ports` creciendo de 1 a 7 según SHAP.

`informe_pericial_ejemplo_escaneo.docx`: el informe pericial completo
ya generado a partir de este mismo caso, para que veas el formato
final sin tener que ejecutar nada.

## Nota importante sobre este modelo concreto

`v1_scan_aggregated_cicids2017` está entrenado con datos SINTÉTICOS
de escenario (sesiones simuladas de escaneo vs. tráfico normal), no
con el CSV real de CICIDS2017 — porque ese CSV, tras la limpieza del
TFM1, no conserva las IPs de origen y por tanto no permite reconstruir
qué flujos pertenecen al mismo origen a lo largo del tiempo (requisito
imprescindible para que la agregación tenga algo que agregar). Es una
limitación de los datos de origen, no del diseño de MODEXRE. Ver
README.md, sección "Clasificación multi-clase" y "Hallazgo 3".
