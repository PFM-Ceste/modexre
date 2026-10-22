# Ficheros de muestra para probar MODEXRE

Todos representan el mismo patrón —un origen que sondea sistemáticamente
la red, más tráfico normal de fondo— cada uno en el formato real de su
fuente, para poder probar rápido cualquiera de las cuatro vías de
ingesta.

| Fichero | Fuente | Notas |
|---|---|---|
| `suricata_eve_ejemplo.json` | Suricata EVE JSON | 8 alertas de escaneo |
| `suricata_eve_hostsweep.json` | Suricata EVE JSON | Barrido horizontal: 20 hosts, 4 puertos |
| `firewall_ejemplo.log` | Firewall CEF/syslog | 5 alertas de escaneo + 1 de tráfico normal |
| `firewall_hostsweep.log` | Firewall CEF/syslog | El mismo barrido, visto por un firewall |
| `captura_portscan.pcap` | PCAP | 22 paquetes: escaneo a 12 puertos + tráfico HTTPS normal. Construido con Scapy: sintético, pero con estructura de paquete válida a nivel de protocolo |
| `cicids2017_muestra_pequena.csv` | CSV etiquetado | 3.568 filas de CICIDS2017, 10 categorías |
| `unsw_nb15_muestra_pequena.csv` | CSV etiquetado | 4.674 filas de UNSW-NB15, 10 categorías |
| `kitsune_muestra_pequena.csv` | CSV etiquetado | 497 filas de Kitsune, 7 categorías |

Todas conservan la dirección IP de origen y destino, el puerto y la
marca temporal, que son los campos de los que depende la agregación
causal por origen (`agg_distinct_dst_hosts`, `agg_distinct_dst_ports`,
`agg_events_in_window`, `agg_events_per_second`) y la identificación
del equipo responsable en el informe pericial.

## Cómo probarlos

Pestaña **⚖️ Formal** → dejar activado "Detectar automáticamente el tipo
de fichero" → subir cualquiera de estos ficheros → modelo **`v3`** (el
recomendado, preseleccionado) → *Ejecutar análisis pericial*.

## Resultado esperado sobre las muestras etiquetadas

Como estas tres muestras conservan su columna `attack_cat`, puede
contrastarse la salida del modelo con la clasificación de origen. Medido
con `model_v3`:

| Muestra | Acierto de categoría exacta | Ataques detectados como no-Normal |
|---|---|---|
| CICIDS2017 | 83,5% | 98,7% |
| UNSW-NB15 | 38,5% | 90,3% |

En CICIDS2017 la categoría mayoritaria predicha coincide con la real en
8 de las 10 clases: `BruteForce` y `DDoS` al 100%, `PortScan` 98%,
`Bot` 97%, `Normal` 99%.

La diferencia con UNSW-NB15 no es casual y conviene entenderla antes de
interpretar esa cifra: sus categorías se solapan mucho entre sí
(`Analysis`, `Backdoors` y `DoS` acaban en su mayoría bajo `Generic`;
`Shellcode` y `Worms` bajo `Exploits`), de modo que el error se
concentra en confusiones entre familias de ataque próximas, no en
dejar pasar tráfico malicioso como legítimo: 9 de cada 10 ataques
siguen marcándose como tales.

## Una advertencia sobre el tamaño de la muestra

Las características de agregación miden densidad temporal por origen:
cuántos destinos y puertos distintos toca una misma IP dentro de una
ventana. Un muestreo aleatorio reparte las filas de un barrido entre
miles de huecos y **destruye** esa densidad: de un escaneo real de mil
puertos quedan unas decenas de eventos sueltos, que ya no se parecen a
un barrido.

Por eso estas muestras no se extrajeron al azar, sino conservando
secuencias consecutivas del mismo origen en orden temporal. El cuaderno
que las genera es `notebooks/Extraer_Muestras_Con_IP.ipynb`, que parte
de los CSV limpios completos.

Si se regeneran con un muestreo aleatorio, o con muy pocas filas por
clase, la agregación pierde sentido y los resultados de la tabla
anterior no se reproducen.
