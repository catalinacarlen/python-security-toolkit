"""Analizador de logs de autenticación con detecciones estilo SIEM.

Parsea un `auth.log` de Linux y, en lugar de solo contar fallos por IP, aplica
varias reglas de detección como lo haría un motor de correlación básico:

- R001 Fuerza bruta: muchos fallos desde una misma IP dentro de una ventana de
  tiempo deslizante (no solo un total acumulado).
- R002 Password spraying: una IP que prueba MUCHOS usuarios distintos con pocos
  intentos cada uno (el patrón inverso a la fuerza bruta, suele evadir umbrales).
- R003 Enumeración de usuarios: fallos contra usuarios inexistentes ("invalid user").
- R004 Posible compromiso: un login EXITOSO correlacionado con fallos PREVIOS del
  mismo (IP, usuario) dentro de una ventana (reduce falsos positivos detrás de NAT).
- Watchlist: cualquier actividad desde IPs marcadas se eleva de severidad.

Procesamiento: el análisis de archivo es **streaming** (línea por línea, sin cargar
el archivo entero ni la lista completa de eventos en memoria); el estado de cada
detector está acotado por su ventana temporal. Asume que el log es cronológico
(como lo es syslog). `analizar()` sobre una lista en memoria ordena por tiempo antes.

Cobertura de parsing: password y publickey (fallo y éxito), IPv4 e IPv6 (validados con
ipaddress), timestamps BSD ("May 11 10:12:01", con inferencia de cruce de año) y
ISO 8601 / RFC 5424 (con año y zona horaria), y expansión de "message repeated N
times". Las líneas con fecha o IP inválida se descartan sin abortar el análisis.

Solo librería estándar. Para uso en entornos autorizados.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from collections import Counter, deque
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone

# Prefijo de timestamp de syslog BSD: "May 11 10:12:01 host sshd[123]: <cuerpo>"
_PREFIJO_BSD = re.compile(
    r"^(?P<mes>\w{3})\s+(?P<dia>\d+)\s+(?P<hora>\d{2}:\d{2}:\d{2})\s+(?P<cuerpo>.*)$"
)
# Prefijo ISO 8601 / RFC 5424: "2024-05-11T10:12:01.123+00:00 host sshd[1]: <cuerpo>"
_PREFIJO_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<cuerpo>.*)$"
)
# rsyslog/journald colapsan líneas idénticas: "message repeated N times: [ <linea> ]".
# Sin esto, una ráfaga de fuerza bruta se contaría como UN solo fallo (evasión).
_REPETIDO = re.compile(r"message repeated (?P<n>\d+) times:\s*\[\s*(?P<inner>.*?)\s*\]")
# Eventos de autenticación SSH. Cubre password Y publickey, fallo Y éxito. La IP se
# captura de forma agnóstica (v4/v6) y se valida aparte con el módulo ipaddress.
_AUTH = re.compile(
    r"(?P<resultado>Failed|Accepted) (?:password|publickey) for "
    r"(?P<invalido>invalid user )?(?P<usuario>\S+) from (?P<ip>\S+)"
)
# Cota anti-DoS: una línea no puede inyectar un número arbitrario de eventos.
_MAX_REPETICIONES = 100_000

_MESES = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

SEVERIDAD = {"R001": "alta", "R002": "alta", "R003": "media", "R004": "crítica"}

# Ventanas por defecto (minutos) de las reglas agregadas. Acotan el estado en memoria.
_VENTANA_SPRAY_MIN = 10
_VENTANA_ENUM_MIN = 10
_VENTANA_COMPROMISO_MIN = 60


class Evento:
    """Un intento de autenticación normalizado a partir de una línea de log."""

    __slots__ = ("ts", "ip", "usuario", "exito", "usuario_invalido")

    def __init__(self, ts: datetime, ip: str, usuario: str, exito: bool, usuario_invalido: bool):
        self.ts = ts
        self.ip = ip
        self.usuario = usuario
        self.exito = exito
        self.usuario_invalido = usuario_invalido


# Año base sintético para los timestamps BSD (que no traen año). Se usa uno bisiesto
# para que las líneas legítimas del 29 de febrero no rompan el parseo.
_ANIO_BASE = 2020


def _timestamp(mes: str, dia: str, hora: str, anio: int = _ANIO_BASE) -> datetime:
    """Construye un datetime desde los campos de syslog BSD (que no traen año)."""
    h, m, s = (int(x) for x in hora.split(":"))
    return datetime(anio, _MESES.get(mes, 1), int(dia), h, m, s)


def _ts_iso(texto: str) -> datetime | None:
    """Parsea un timestamp ISO 8601 / RFC 5424 a datetime naive en UTC, o None."""
    s = texto.replace("Z", "+00:00")
    s = re.sub(r"^(\d{4}-\d{2}-\d{2}) ", r"\1T", s)   # separador espacio -> T
    s = re.sub(r"\.\d+", "", s)                       # descartamos fracciones de segundo
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is not None:                         # normalizamos a UTC naive para comparar
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _sanitizar(texto: str) -> str:
    """Quita caracteres de control de un campo del log.

    El nombre de usuario proviene del log (lo controla el atacante en los intentos de
    login) y llega a la salida de texto. Eliminar los caracteres no imprimibles evita
    la inyección de secuencias de escape en la terminal al mostrar las alertas.
    """
    return "".join(c for c in texto if c.isprintable())


def _ip_valida(token: str) -> str | None:
    """Normaliza y valida una IP (v4 o v6). Devuelve None si el token no es una IP.

    Usar ipaddress.ip_address en lugar de un regex casero da soporte a IPv6 gratis y
    rechaza octetos imposibles (p. ej. 999.999.999.999) que un regex laxo dejaría pasar.
    """
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


def _evento_desde_cuerpo(cuerpo: str, ts: datetime) -> Evento | None:
    """Extrae un Evento de autenticación del cuerpo de una línea, o None si no aplica."""
    m = _AUTH.search(cuerpo)
    if not m:
        return None
    ip = _ip_valida(m["ip"])
    if ip is None:
        return None
    return Evento(
        ts, ip, _sanitizar(m["usuario"]),
        exito=(m["resultado"] == "Accepted"),
        usuario_invalido=bool(m["invalido"]),
    )


def _iter_eventos(lineas: Iterable[str]) -> Iterator[Evento]:
    """Genera Eventos a partir de líneas, de forma perezosa (no materializa la lista).

    Soporta timestamps BSD e ISO. Para BSD (sin año) infiere el cruce de año cuando el
    mes decrece (Dic -> Ene) dentro del mismo archivo, asumiendo orden cronológico.
    """
    anio = _ANIO_BASE
    mes_prev: int | None = None
    for linea in lineas:
        iso = _PREFIJO_ISO.match(linea)
        if iso:
            ts = _ts_iso(iso["ts"])
            if ts is None:
                continue
            cuerpo = iso["cuerpo"]
        else:
            bsd = _PREFIJO_BSD.match(linea)
            if not bsd:
                continue
            mes = _MESES.get(bsd["mes"], 1)
            if mes_prev is not None and mes < mes_prev:
                anio += 1  # rollover Dic -> Ene en el mismo archivo
            mes_prev = mes
            try:
                ts = _timestamp(bsd["mes"], bsd["dia"], bsd["hora"], anio)
            except ValueError:
                continue  # fecha imposible (p. ej. "Feb 30"): se descarta la línea
            cuerpo = bsd["cuerpo"]

        veces = 1
        rep = _REPETIDO.search(cuerpo)
        if rep:
            veces = min(int(rep["n"]), _MAX_REPETICIONES)
            cuerpo = rep["inner"]
        evento = _evento_desde_cuerpo(cuerpo, ts)
        if evento is not None:
            for _ in range(veces):
                yield evento


def parsear(lineas: list[str]) -> list[Evento]:
    """Convierte líneas en una lista de Eventos ordenada por tiempo (uso en memoria)."""
    return sorted(_iter_eventos(lineas), key=lambda e: e.ts)


def _alerta(regla: str, ip: str, descripcion: str, **evidencia) -> dict:
    return {
        "regla": regla,
        "severidad": SEVERIDAD.get(regla, "media"),
        "ip": ip,
        "descripcion": descripcion,
        "evidencia": evidencia,
    }


# --- Detectores stateful (procesan un evento por vez, estado acotado por ventana) ---

class _Detector:
    """Interfaz de un detector: consume un Evento y devuelve las alertas que dispara."""

    def feed(self, e: Evento) -> list[dict]:
        raise NotImplementedError


class _DetectorFuerzaBruta(_Detector):
    """R001: >= `umbral` fallos de una IP dentro de la ventana. Alerta una vez por episodio."""

    def __init__(self, umbral: int, ventana: timedelta, ventana_min: int):
        self.umbral = umbral
        self.ventana = ventana
        self.ventana_min = ventana_min
        self.por_ip: dict[str, deque] = {}
        self.alertando: set[str] = set()

    def feed(self, e: Evento) -> list[dict]:
        if e.exito:
            return []
        dq = self.por_ip.setdefault(e.ip, deque())
        dq.append(e.ts)
        while dq and e.ts - dq[0] > self.ventana:
            dq.popleft()
        if len(dq) >= self.umbral:
            if e.ip not in self.alertando:
                self.alertando.add(e.ip)
                return [_alerta("R001", e.ip,
                                f"{len(dq)} fallos en <= {self.ventana_min} min (fuerza bruta)",
                                fallos_en_ventana=len(dq), ultimo=str(e.ts))]
        else:
            self.alertando.discard(e.ip)
        return []


class _DetectorSpraying(_Detector):
    """R002: una IP con muchos usuarios distintos, pocos intentos c/u, dentro de la ventana."""

    def __init__(self, min_usuarios: int, max_por_usuario: int, ventana: timedelta):
        self.min_usuarios = min_usuarios
        self.max_por_usuario = max_por_usuario
        self.ventana = ventana
        self.por_ip: dict[str, deque] = {}
        self.alertando: set[str] = set()

    def feed(self, e: Evento) -> list[dict]:
        if e.exito:
            return []
        dq = self.por_ip.setdefault(e.ip, deque())
        dq.append((e.ts, e.usuario))
        while dq and e.ts - dq[0][0] > self.ventana:
            dq.popleft()
        cuenta = Counter(u for _, u in dq)
        if len(cuenta) >= self.min_usuarios and max(cuenta.values()) <= self.max_por_usuario:
            if e.ip not in self.alertando:
                self.alertando.add(e.ip)
                return [_alerta("R002", e.ip,
                                f"{len(cuenta)} usuarios distintos con <= {self.max_por_usuario} "
                                f"intentos c/u (password spraying)",
                                usuarios_distintos=len(cuenta), usuarios=sorted(cuenta))]
        else:
            self.alertando.discard(e.ip)
        return []


class _DetectorEnumeracion(_Detector):
    """R003: una IP que prueba muchos usuarios inexistentes dentro de la ventana."""

    def __init__(self, umbral: int, ventana: timedelta):
        self.umbral = umbral
        self.ventana = ventana
        self.por_ip: dict[str, deque] = {}
        self.alertando: set[str] = set()

    def feed(self, e: Evento) -> list[dict]:
        if e.exito or not e.usuario_invalido:
            return []
        dq = self.por_ip.setdefault(e.ip, deque())
        dq.append((e.ts, e.usuario))
        while dq and e.ts - dq[0][0] > self.ventana:
            dq.popleft()
        usuarios = {u for _, u in dq}
        if len(usuarios) >= self.umbral:
            if e.ip not in self.alertando:
                self.alertando.add(e.ip)
                return [_alerta("R003", e.ip,
                                f"{len(usuarios)} usuarios inexistentes probados (enumeración)",
                                usuarios=sorted(usuarios))]
        else:
            self.alertando.discard(e.ip)
        return []


class _DetectorCompromiso(_Detector):
    """R004: login exitoso correlacionado con fallos PREVIOS del mismo (IP, usuario).

    Correlacionar por (IP, usuario) y exigir que los fallos estén dentro de una ventana
    antes del éxito evita los falsos positivos detrás de NAT (un usuario falla, OTRO
    entra). El contador se resetea tras el login exitoso, así no re-alerta.
    """

    def __init__(self, min_fallos: int, ventana: timedelta):
        self.min_fallos = min_fallos
        self.ventana = ventana
        self.fallos: dict[tuple, deque] = {}

    def feed(self, e: Evento) -> list[dict]:
        clave = (e.ip, e.usuario)
        if e.exito:
            dq = self.fallos.pop(clave, None)  # reset on success
            if dq is None:
                return []
            while dq and e.ts - dq[0] > self.ventana:
                dq.popleft()
            n = len(dq)
            if n >= self.min_fallos:
                return [_alerta("R004", e.ip,
                                f"login EXITOSO como '{e.usuario}' tras {n} fallos previos",
                                usuario=e.usuario, fallos_previos=n, momento=str(e.ts))]
            return []
        dq = self.fallos.setdefault(clave, deque())
        dq.append(e.ts)
        while dq and e.ts - dq[0] > self.ventana:
            dq.popleft()
        return []


def _correr(detector: _Detector, eventos: Iterable[Evento]) -> list[dict]:
    """Alimenta un detector con un stream de eventos y junta sus alertas."""
    alertas: list[dict] = []
    for e in eventos:
        alertas.extend(detector.feed(e))
    return alertas


def detectar_fuerza_bruta(eventos: Iterable[Evento], umbral: int = 5,
                          ventana_min: int = 2) -> list[dict]:
    """R001: >= `umbral` fallos desde una IP dentro de `ventana_min` minutos."""
    return _correr(_DetectorFuerzaBruta(umbral, timedelta(minutes=ventana_min), ventana_min), eventos)


def detectar_spraying(eventos: Iterable[Evento], min_usuarios: int = 5, max_por_usuario: int = 3,
                      ventana_min: int = _VENTANA_SPRAY_MIN) -> list[dict]:
    """R002: una IP que falla contra muchos usuarios distintos, pocos intentos c/u."""
    return _correr(_DetectorSpraying(min_usuarios, max_por_usuario, timedelta(minutes=ventana_min)),
                   eventos)


def detectar_enumeracion(eventos: Iterable[Evento], umbral: int = 3,
                         ventana_min: int = _VENTANA_ENUM_MIN) -> list[dict]:
    """R003: muchos fallos contra usuarios inexistentes desde una IP."""
    return _correr(_DetectorEnumeracion(umbral, timedelta(minutes=ventana_min)), eventos)


def detectar_compromiso(eventos: Iterable[Evento], min_fallos_previos: int = 3,
                        ventana_min: int = _VENTANA_COMPROMISO_MIN) -> list[dict]:
    """R004: un login exitoso correlacionado con fallos previos del mismo (IP, usuario)."""
    return _correr(_DetectorCompromiso(min_fallos_previos, timedelta(minutes=ventana_min)), eventos)


def _motor(eventos: Iterable[Evento], umbral: int, ventana_min: int,
           watchlist: set[str] | None) -> list[dict]:
    """Corre las cuatro reglas sobre un stream de eventos y devuelve las alertas."""
    detectores: list[_Detector] = [
        _DetectorFuerzaBruta(umbral, timedelta(minutes=ventana_min), ventana_min),
        _DetectorSpraying(5, 3, timedelta(minutes=_VENTANA_SPRAY_MIN)),
        _DetectorEnumeracion(3, timedelta(minutes=_VENTANA_ENUM_MIN)),
        _DetectorCompromiso(3, timedelta(minutes=_VENTANA_COMPROMISO_MIN)),
    ]
    alertas: list[dict] = []
    for e in eventos:
        for d in detectores:
            alertas.extend(d.feed(e))

    watchlist = watchlist or set()
    for a in alertas:
        if a["ip"] in watchlist:
            a["severidad"] = "crítica"
            a["en_watchlist"] = True
    orden = {"crítica": 0, "alta": 1, "media": 2, "baja": 3}
    return sorted(alertas, key=lambda a: orden.get(a["severidad"], 9))


def analizar(lineas: list[str], umbral: int = 5, ventana_min: int = 2,
             watchlist: set[str] | None = None) -> list[dict]:
    """Corre todas las reglas sobre líneas en memoria (las ordena por tiempo antes)."""
    return _motor(parsear(lineas), umbral, ventana_min, watchlist)


def analizar_archivo(ruta: str, umbral: int = 5, ventana_min: int = 2,
                     watchlist: set[str] | None = None) -> list[dict]:
    """Analiza un archivo en streaming: no carga el archivo ni los eventos completos.

    Itera el log línea por línea; el estado vive solo en los detectores, acotado por su
    ventana. Asume orden cronológico (como en syslog).
    """
    with open(ruta, encoding="utf-8", errors="ignore") as archivo:
        return _motor(_iter_eventos(archivo), umbral, ventana_min, watchlist)


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
