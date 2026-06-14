"""Analizador de logs de autenticación con detecciones estilo SIEM.

Parsea un `auth.log` de Linux y, en lugar de solo contar fallos por IP, aplica
varias reglas de detección como lo haría un motor de correlación básico:

- R001 Fuerza bruta: muchos fallos desde una misma IP dentro de una ventana de
  tiempo deslizante (no solo un total acumulado).
- R002 Password spraying: una IP que prueba MUCHOS usuarios distintos con pocos
  intentos cada uno (el patrón inverso a la fuerza bruta, suele evadir umbrales).
- R003 Enumeración de usuarios: fallos contra usuarios inexistentes ("invalid user").
- R004 Posible compromiso: un login EXITOSO desde una IP que venía fallando.
- Watchlist: cualquier actividad desde IPs marcadas se eleva de severidad.

Cada hallazgo se emite como una "alerta" estructurada (regla, severidad, IP,
evidencia, ventana temporal), apta para salida JSON y para encadenar con otras
herramientas.

Solo librería estándar. Para uso educativo y en entornos autorizados.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta

# Líneas de fallo:
#   "May 11 10:12:01 host sshd[123]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
PATRON_FALLO = re.compile(
    r"^(?P<mes>\w{3})\s+(?P<dia>\d+)\s+(?P<hora>\d{2}:\d{2}:\d{2}).*"
    r"Failed password for (?P<invalido>invalid user )?(?P<usuario>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
# Líneas de éxito:
#   "May 11 10:15:42 host sshd[130]: Accepted password for cata from 1.2.3.4 port 22 ssh2"
PATRON_EXITO = re.compile(
    r"^(?P<mes>\w{3})\s+(?P<dia>\d+)\s+(?P<hora>\d{2}:\d{2}:\d{2}).*"
    r"Accepted password for (?P<usuario>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

_MESES = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

SEVERIDAD = {"R001": "alta", "R002": "alta", "R003": "media", "R004": "crítica"}


class Evento:
    """Un intento de autenticación normalizado a partir de una línea de log."""

    __slots__ = ("ts", "ip", "usuario", "exito", "usuario_invalido")

    def __init__(self, ts: datetime, ip: str, usuario: str, exito: bool, usuario_invalido: bool):
        self.ts = ts
        self.ip = ip
        self.usuario = usuario
        self.exito = exito
        self.usuario_invalido = usuario_invalido


def _timestamp(mes: str, dia: str, hora: str, anio: int = 1900) -> datetime:
    """Construye un datetime desde los campos de syslog (que no traen año)."""
    h, m, s = (int(x) for x in hora.split(":"))
    return datetime(anio, _MESES.get(mes, 1), int(dia), h, m, s)


def parsear(lineas: list[str]) -> list[Evento]:
    """Convierte líneas de log en una lista de Eventos ordenada por tiempo."""
    eventos: list[Evento] = []
    for linea in lineas:
        m = PATRON_FALLO.search(linea)
        if m:
            eventos.append(Evento(
                _timestamp(m["mes"], m["dia"], m["hora"]),
                m["ip"], m["usuario"], exito=False,
                usuario_invalido=bool(m["invalido"])))
            continue
        m = PATRON_EXITO.search(linea)
        if m:
            eventos.append(Evento(
                _timestamp(m["mes"], m["dia"], m["hora"]),
                m["ip"], m["usuario"], exito=True, usuario_invalido=False))
    return sorted(eventos, key=lambda e: e.ts)


def _alerta(regla: str, ip: str, descripcion: str, **evidencia) -> dict:
    return {
        "regla": regla,
        "severidad": SEVERIDAD.get(regla, "media"),
        "ip": ip,
        "descripcion": descripcion,
        "evidencia": evidencia,
    }


def detectar_fuerza_bruta(
    eventos: list[Evento], umbral: int = 5, ventana_min: int = 2
) -> list[dict]:
    """R001: >= `umbral` fallos desde una IP dentro de `ventana_min` minutos."""
    ventana = timedelta(minutes=ventana_min)
    por_ip: dict[str, list[Evento]] = defaultdict(list)
    for e in eventos:
        if not e.exito:
            por_ip[e.ip].append(e)

    alertas: list[dict] = []
    for ip, fallos in por_ip.items():
        ts = [e.ts for e in fallos]
        inicio = 0
        pico = 0
        # Ventana deslizante de dos punteros sobre los timestamps ordenados.
        for fin in range(len(ts)):
            while ts[fin] - ts[inicio] > ventana:
                inicio += 1
            pico = max(pico, fin - inicio + 1)
        if pico >= umbral:
            alertas.append(_alerta(
                "R001", ip,
                f"{pico} fallos en <= {ventana_min} min (fuerza bruta)",
                fallos_en_ventana=pico, fallos_totales=len(fallos),
                primero=str(ts[0]), ultimo=str(ts[-1])))
    return alertas


def detectar_spraying(
    eventos: list[Evento], min_usuarios: int = 5, max_por_usuario: int = 3
) -> list[dict]:
    """R002: una IP que falla contra muchos usuarios distintos, pocos intentos c/u."""
    intentos: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for e in eventos:
        if not e.exito:
            intentos[e.ip][e.usuario] += 1

    alertas: list[dict] = []
    for ip, usuarios in intentos.items():
        if len(usuarios) >= min_usuarios and max(usuarios.values()) <= max_por_usuario:
            alertas.append(_alerta(
                "R002", ip,
                f"{len(usuarios)} usuarios distintos con <= {max_por_usuario} intentos c/u (password spraying)",
                usuarios_distintos=len(usuarios),
                usuarios=sorted(usuarios)))
    return alertas


def detectar_enumeracion(eventos: list[Evento], umbral: int = 3) -> list[dict]:
    """R003: muchos fallos contra usuarios inexistentes desde una IP."""
    por_ip: dict[str, set[str]] = defaultdict(set)
    for e in eventos:
        if not e.exito and e.usuario_invalido:
            por_ip[e.ip].add(e.usuario)
    return [
        _alerta("R003", ip,
                f"{len(usuarios)} usuarios inexistentes probados (enumeración)",
                usuarios=sorted(usuarios))
        for ip, usuarios in por_ip.items() if len(usuarios) >= umbral
    ]


def detectar_compromiso(eventos: list[Evento], min_fallos_previos: int = 3) -> list[dict]:
    """R004: un login exitoso desde una IP que acumuló fallos antes (posible breach)."""
    fallos: dict[str, int] = defaultdict(int)
    alertas: list[dict] = []
    for e in eventos:  # eventos ya vienen ordenados por tiempo
        if e.exito:
            if fallos[e.ip] >= min_fallos_previos:
                alertas.append(_alerta(
                    "R004", e.ip,
                    f"login EXITOSO como '{e.usuario}' tras {fallos[e.ip]} fallos previos",
                    usuario=e.usuario, fallos_previos=fallos[e.ip], momento=str(e.ts)))
        else:
            fallos[e.ip] += 1
    return alertas


def analizar(
    lineas: list[str],
    umbral: int = 5,
    ventana_min: int = 2,
    watchlist: set[str] | None = None,
) -> list[dict]:
    """Corre todas las reglas y devuelve la lista de alertas, ordenada por severidad."""
    eventos = parsear(lineas)
    alertas = (
        detectar_fuerza_bruta(eventos, umbral, ventana_min)
        + detectar_spraying(eventos)
        + detectar_enumeracion(eventos)
        + detectar_compromiso(eventos)
    )
    watchlist = watchlist or set()
    for a in alertas:
        if a["ip"] in watchlist:
            a["severidad"] = "crítica"
            a["en_watchlist"] = True
    orden = {"crítica": 0, "alta": 1, "media": 2, "baja": 3}
    return sorted(alertas, key=lambda a: orden.get(a["severidad"], 9))


def analizar_archivo(ruta: str, umbral: int = 5, ventana_min: int = 2,
                     watchlist: set[str] | None = None) -> list[dict]:
    with open(ruta, encoding="utf-8", errors="ignore") as archivo:
        return analizar(archivo.readlines(), umbral, ventana_min, watchlist)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detección estilo SIEM sobre logs de autenticación.")
    parser.add_argument("archivo", help="Ruta al archivo de log (ej. auth.log)")
    parser.add_argument("-u", "--umbral", type=int, default=5,
                        help="Fallos para marcar fuerza bruta (por defecto 5)")
    parser.add_argument("-v", "--ventana", type=int, default=2,
                        help="Ventana en minutos para la fuerza bruta (por defecto 2)")
    parser.add_argument("-w", "--watchlist", default="",
                        help="IPs en watchlist separadas por coma")
    parser.add_argument("--json", action="store_true", help="Salida en formato JSON")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    watchlist = {ip.strip() for ip in args.watchlist.split(",") if ip.strip()}
    alertas = analizar_archivo(args.archivo, args.umbral, args.ventana, watchlist)

    if args.json:
        print(json.dumps(alertas, ensure_ascii=False, indent=2))
        return

    if not alertas:
        print("Sin alertas: no se detectaron patrones sospechosos.")
        return

    print(f"{len(alertas)} alerta(s) detectada(s):\n")
    for a in alertas:
        marca = "  [watchlist]" if a.get("en_watchlist") else ""
        print(f"[{a['severidad'].upper():<8}] {a['regla']}  {a['ip']:<16}{marca}")
        print(f"           {a['descripcion']}")


if __name__ == "__main__":
    main()
