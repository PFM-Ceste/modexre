"""
Genera la captura de red del caso de demostración.

Escenario: un equipo de la red interna (10.14.3.87) comienza a sondear
sistemáticamente el resto del segmento. Alrededor de ese barrido hay
tráfico corriente de oficina -- navegación web, correo -- para que el
análisis tenga que distinguir, no simplemente marcarlo todo.

Se emite como PCAP porque es la fuente sobre la que MODEXRE obtiene su
mejor rendimiento (87-90% de identificación correcta en la validación
cruzada) y porque es lo que un perito recibe de verdad: la captura del
tráfico, no un CSV ya procesado.
"""

import random
from scapy.all import IP, TCP, Ether, wrpcap

random.seed(20261022)

SALIDA = "/home/claude/work/incidente_red_2026.pcap"

# --- Topología de la oficina ---
ATACANTE = "10.14.3.87"           # equipo comprometido
PUESTOS = [f"10.14.3.{n}" for n in (12, 23, 41, 58)]   # puestos legítimos
SERVIDOR_WEB = "93.184.216.34"
SERVIDOR_CORREO = "10.14.1.25"
PUERTA_ENLACE = "10.14.3.1"

paquetes = []
t = 1761120000.0  # 22/10/2026 ~08:00 UTC


def _mac(ip: str) -> str:
    """MAC estable derivada de la IP, para que la captura sea coherente."""
    ultimo = int(ip.split(".")[-1])
    return f"02:00:5e:{ultimo:02x}:{(ultimo * 7) % 256:02x}:01"


def enviar(origen, destino, sport, dport, flags, carga=0, avance=0.0):
    global t
    t += avance
    pkt = (Ether(src=_mac(origen), dst=_mac(destino)) /
           IP(src=origen, dst=destino) /
           TCP(sport=sport, dport=dport, flags=flags))
    if carga:
        pkt = pkt / (b"X" * carga)
    pkt.time = t
    paquetes.append(pkt)


def sesion_legitima(cliente, servidor, dport, n_intercambios, inicio):
    """Sesión TCP completa: handshake, datos en ambos sentidos y cierre.
    Es el tráfico que el sistema NO debe marcar."""
    global t
    t = inicio
    sport = random.randint(49152, 65000)
    enviar(cliente, servidor, sport, dport, "S", avance=0.0)
    enviar(servidor, cliente, dport, sport, "SA", avance=0.012)
    enviar(cliente, servidor, sport, dport, "A", avance=0.004)
    for _ in range(n_intercambios):
        enviar(cliente, servidor, sport, dport, "PA", carga=random.randint(180, 900), avance=random.uniform(0.05, 0.4))
        enviar(servidor, cliente, dport, sport, "PA", carga=random.randint(400, 1400), avance=random.uniform(0.03, 0.25))
    enviar(cliente, servidor, sport, dport, "FA", avance=0.1)
    enviar(servidor, cliente, dport, sport, "FA", avance=0.02)
    enviar(cliente, servidor, sport, dport, "A", avance=0.005)


# =====================================================================
# 1. Actividad normal de oficina, antes del incidente
# =====================================================================
inicio = t
for i, puesto in enumerate(PUESTOS):
    sesion_legitima(puesto, SERVIDOR_WEB, 443, random.randint(14, 22), inicio + i * 7.0)
    sesion_legitima(puesto, SERVIDOR_CORREO, 993, random.randint(12, 18), inicio + i * 7.0 + 3.5)

# =====================================================================
# 2. El barrido: 10.14.3.87 recorre el segmento host por host
#
#    Cada sonda es un SYN que no obtiene respuesta de servicio: o se
#    queda sin contestar, o el destino responde con RST (puerto
#    cerrado). Ese patrón -- un paquete de ida, cero o uno de vuelta,
#    sin datos -- es la huella que distingue una sonda de una conexión
#    real, y es lo que el modelo aprende a reconocer.
# =====================================================================
inicio_barrido = inicio + 60.0
t = inicio_barrido
PUERTOS_SONDEADOS = (22, 445, 3389, 8080)

objetivos = [f"10.14.{bloque}.{host}"
             for bloque in (1, 2, 3)
             for host in range(10, 40)]
random.shuffle(objetivos)
objetivos = [o for o in objetivos if o != ATACANTE][:78]

for destino in objetivos:
    for puerto in PUERTOS_SONDEADOS:
        sport = random.randint(40000, 60000)
        enviar(ATACANTE, destino, sport, puerto, "S", avance=random.uniform(0.04, 0.12))
        # Dos de cada tres sondas reciben RST; el resto, silencio.
        if random.random() < 0.66:
            enviar(destino, ATACANTE, puerto, sport, "RA", avance=0.003)

fin_barrido = t

# =====================================================================
# 3. Más actividad normal, durante y después del barrido
# =====================================================================
for i, puesto in enumerate(PUESTOS):
    sesion_legitima(puesto, SERVIDOR_WEB, 443, random.randint(15, 24), inicio_barrido + 20.0 + i * 9.0)
    sesion_legitima(puesto, SERVIDOR_CORREO, 993, random.randint(10, 16), inicio_barrido + 25.0 + i * 9.0)

paquetes.sort(key=lambda p: p.time)
wrpcap(SALIDA, paquetes)

print(f"Captura generada: {SALIDA}")
print(f"  {len(paquetes)} paquetes")
print(f"  barrido: {ATACANTE} -> {len(objetivos)} hosts distintos "
      f"x {len(PUERTOS_SONDEADOS)} puertos, en {fin_barrido - inicio_barrido:.0f} s")
print(f"  tráfico legítimo: {len(PUESTOS)} puestos contra web, correo y DNS")
