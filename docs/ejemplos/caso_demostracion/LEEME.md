# Caso de demostración CASO-2026-014

Un recorrido completo del modo Formal sobre una única pieza de evidencia:
de la captura de red a los dos informes firmados, con su cadena de
custodia. Sirve para ver el sistema funcionando de principio a fin sin
tener que construirse un caso propio.

## El escenario

Un equipo de la red interna (`10.14.3.87`) comienza a sondear
sistemáticamente el resto del segmento: 78 hosts distintos, cuatro
puertos en cada uno. Alrededor de ese barrido hay tráfico corriente de
oficina —navegación web y correo desde cuatro puestos legítimos—, de modo
que el análisis tiene que **distinguir**, no limitarse a marcarlo todo.

## Ficheros

| Fichero | Qué es |
|---|---|
| `CASO-2026-014_captura.pcap` | La evidencia: 406 KB de tráfico capturado |
| `CASO-2026-014_informe_tecnico.docx` | Informe técnico con las clasificaciones y las explicaciones SHAP |
| `CASO-2026-014_informe_juridico.docx` | Informe pericial, redactado para un lector no técnico |
| `generar_caso_demo.py` | El script que construyó la captura, para poder rehacerla |

## Cómo reproducirlo

Pestaña **⚖️ Formal** → dejar activado "Detectar automáticamente el tipo
de fichero" → subir `CASO-2026-014_captura.pcap` → modelo **`v3`** →
*Ejecutar análisis pericial*.

Los dos informes que genera deben coincidir en contenido con los que
acompañan a este fichero. Las marcas de tiempo y los identificadores de
la cadena de custodia sí cambiarán, porque se calculan en el momento del
análisis: lo que no cambia son las clasificaciones ni los hashes de la
evidencia de entrada.

## Sobre la captura

Es **sintética**, construida con Scapy, y no contiene tráfico real ni
datos de ninguna persona. Las direcciones son de rango privado salvo el
servidor web (`93.184.216.34`, el de `example.com`, reservado para
documentación).

Aun siendo sintética, los paquetes son válidos a nivel de protocolo: cada
sonda es un SYN que no llega a establecer sesión —o se queda sin
respuesta, o el destino contesta con RST—, mientras que el tráfico
legítimo son sesiones TCP completas con su handshake, sus datos en ambos
sentidos y su cierre. Esa diferencia es justamente la que el modelo tiene
que detectar.

Se eligió PCAP y no un CSV ya procesado porque es lo que un perito recibe
de verdad, y porque es la fuente sobre la que MODEXRE rinde mejor en la
validación cruzada.

## Limitación que conviene conocer

El puerto de destino no se publica en el pipeline de PCAP (ver el
comentario en `backend/app/ocsf/pcap_flow.py`), de modo que
`agg_distinct_dst_ports` vale cero en esta fuente. La identificación del
barrido se sostiene sobre el número de hosts distintos y la densidad
temporal, no sobre la variedad de puertos.
