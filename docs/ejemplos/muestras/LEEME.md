# Ficheros de muestra para probar MODEXRE

Todos representan el mismo patrón (escaneo de puertos desde un origen,
más algo de tráfico normal de fondo), cada uno en el formato real de
su fuente, para que puedas probar rápido cualquiera de las cuatro
formas de ingesta.

| Fichero | Fuente | Notas |
|---|---|---|
| `suricata_eve_ejemplo.json` | Suricata EVE JSON | 8 alertas reales de escaneo |
| `firewall_ejemplo.log` | Firewall CEF/syslog | 5 alertas de escaneo + 1 tráfico normal |
| `captura_portscan.pcap` | PCAP | 22 paquetes: escaneo a 12 puertos + tráfico HTTPS normal. **Construido con Scapy de forma sintética pero con estructura de paquete real** (no es una captura de tráfico real de producción, es válido a nivel de protocolo) |
| `cicids2017_muestra_pequena.csv` | CSV (con etiqueta) | ~500 filas estratificadas del dataset real CICIDS2017 |
| `unsw_nb15_muestra_pequena.csv` | CSV (con etiqueta) | ~500 filas estratificadas del dataset real UNSW-NB15 |
| `kitsune_muestra_pequena.csv` | CSV (con etiqueta) | ~500 filas estratificadas del dataset real Kitsune |

## Cómo probarlos

Pestaña **Formal** → deja "Detectar automáticamente" activado → sube
cualquiera de estos ficheros → modelo `v1` → "Ejecutar análisis pericial".

Los tres CSV son ideales para pruebas RÁPIDAS (segundos, no minutos)
frente a las muestras completas de 90.000+ filas que usamos antes.
