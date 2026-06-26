"""Analizador de logs de autenticación con detecciones estilo SIEM.

Parsea un `auth.log` de Linux y, en lugar de solo contar fallos por IP, aplica
varias reglas de detección como lo haría un motor de correlación básico:

- R001 Fuerza bruta (MITRE ATT&CK T1110.001): muchos fallos desde una misma IP
  dentro de una ventana de tiempo deslizante.
- R002 Password spraying (T1110.003): una IP que prueba MUCHOS usuarios distintos
  con pocos intentos cada uno.
- R003 Enumeración de usuarios (T1087): fallos contra usuarios inexistentes.
- R004 Posible compromiso (T1078): un login EXITOSO correlacionado con fallos PREVIOS
  del mismo (IP, usuario) dentro de una ventana.
- Watchlist: eleva la severidad de IPs marcadas. Allowlist: suprime IPs conocidas-buenas.

Cada alerta sale etiquetada con su técnica de MITRE ATT&CK, enriquecida con el alcance
de la IP (privada/pública/loopback…) y, opcionalmente, país/ASN desde una base offline.
La herramienta también puede exportar sus detecciones como reglas Sigma (`--sigma`).

Procesamiento: el análisis de archivo es streaming (línea por línea); el estado de cada
detector está acotado por su ventana temporal. Asume log cronológico (como syslog).

Cobertura de parsing: password y publickey (fallo y éxito), IPv4 e IPv6 (validados con
ipaddress), timestamps BSD (con inferencia de cruce de año) e ISO 8601 / RFC 5424, y
expansión de "message repeated N times". Solo librería estándar. Para entornos autorizados.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import uuid
from collections import Counter, deque
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone
from functools import lru_cache

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
_REPETIDO = re.compile(r"message repeated (?P<n>\d+) times:\s*\[\s*(?P<inner>.*?)\s*\]")
# Eventos de autenticación SSH. Cubre password Y publickey, fallo Y éxito.
_AUTH = re.compile(
    r"(?P<resultado>Failed|Accepted) (?:password|publickey) for "
    r"(?P<invalido>invalid user )?(?P<usuario>\S+) from (?P<ip>\S+)"
)
# Cotas anti-DoS.
_MAX_REPETICIONES = 100_000
_MAX_LINEA = 64 * 1024

_MESES = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

SEVERIDAD = {"R001": "alta", "R002": "alta", "R003": "media", "R004": "crítica"}

# Mapeo de cada regla a su técnica de MITRE ATT&CK (id, nombre).
ATTACK = {
    "R001": ("T1110.001", "Brute Force: Password Guessing"),
    "R002": ("T1110.003", "Brute Force: Password Spraying"),
    "R003": ("T1087", "Account Discovery"),
    "R004": ("T1078", "Valid Accounts"),
}

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


# Año base sintético para los timestamps BSD (que no traen año). Bisiesto para que el
# 29 de febrero no rompa el parseo.
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
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _sanitizar(texto: str) -> str:
    """Quita caracteres de control de un campo del log (evita escape injection al imprimir)."""
    return "".join(c for c in texto if c.isprintable())


def _ip_valida(token: str) -> str | None:
    """Normaliza y valida una IP (v4 o v6). Devuelve None si el token no es una IP."""
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
    """Genera Eventos a partir de líneas, de forma perezosa (no materializa la lista)."""
    anio = _ANIO_BASE
    mes_prev: int | None = None
    for linea in lineas:
        if len(linea) > _MAX_LINEA:
            continue  # línea patológica: se descarta (hardening anti-DoS de regex)
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
                continue  # fecha imposible (p. ej. "Feb 30")
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


def _alerta(regla: str, ip: str, descripcion: str, severidad: str | None = None,
            **evidencia) -> dict:
    """Construye una alerta estructurada, etiquetada con su técnica de ATT&CK."""
    tid, tnombre = ATTACK.get(regla, ("", ""))
    return {
        "regla": regla,
        "tecnica": tid,
        "tecnica_nombre": tnombre,
        "severidad": severidad or SEVERIDAD.get(regla, "media"),
        "ip": ip,
        "descripcion": descripcion,
        "evidencia": evidencia,
    }


# --- Enriquecimiento de IP (alcance + país/ASN opcional desde base offline) ----------

def _alcance_ip(ip: str) -> str:
    """Clasifica el alcance de una IP usando ipaddress (privada, pública, loopback…)."""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return "desconocido"
    if obj.is_loopback:
        return "loopback"
    if obj.is_link_local:
        return "link-local"
    if obj.is_private:
        return "privada"
    if obj.is_multicast or obj.is_reserved:
        return "reservada"
    return "pública"


@lru_cache(maxsize=4)
def _cargar_geodb(ruta: str) -> tuple:
    """Carga una base offline de geo/ASN: líneas 'cidr,pais,asn'. Cacheada por ruta."""
    redes = []
    try:
        with open(ruta, encoding="utf-8") as archivo:
            for linea in archivo:
                linea = linea.strip()
                if not linea or linea.startswith("#"):
                    continue
                partes = [p.strip() for p in linea.split(",")]
                try:
                    red = ipaddress.ip_network(partes[0], strict=False)
                except (ValueError, IndexError):
                    continue
                pais = partes[1] if len(partes) > 1 else ""
                asn = partes[2] if len(partes) > 2 else ""
                redes.append((red, pais, asn))
    except OSError:
        return ()
    return tuple(redes)


def _enriquecer(ip: str, geodb: str | None) -> dict:
    """Devuelve contexto de red de la IP: alcance siempre; país/ASN si hay base."""
    info = {"alcance": _alcance_ip(ip)}
    if geodb:
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            return info
        for red, pais, asn in _cargar_geodb(geodb):
            if obj in red:
                if pais:
                    info["pais"] = pais
                if asn:
                    info["asn"] = asn
                break
    return info


# --- Detectores stateful (procesan un evento por vez, estado acotado por ventana) ---

class _Detector:
    """Interfaz de un detector: consume un Evento y devuelve las alertas que dispara."""

    def feed(self, e: Evento) -> list[dict]:
        raise NotImplementedError


class _DetectorFuerzaBruta(_Detector):
    """R001: >= `umbral` fallos de una IP dentro de la ventana, con severidad por volumen.

    Escala: emite una alerta `alta` al cruzar el umbral y una `crítica` adicional si el
    volumen alcanza 10x el umbral (R001 con 6 fallos y con 6000 no pesan igual). El estado
    se resetea cuando la ventana cae por debajo del umbral, así un nuevo episodio re-alerta.
    """

    def __init__(self, umbral: int, ventana: timedelta, ventana_min: int):
        self.umbral = umbral
        self.ventana = ventana
        self.ventana_min = ventana_min
        self.por_ip: dict[str, deque] = {}
        self.nivel: dict[str, int] = {}  # ip -> nivel ya alertado (0 ninguno, 1 alta, 2 crítica)

    def feed(self, e: Evento) -> list[dict]:
        if e.exito:
            return []
        dq = self.por_ip.setdefault(e.ip, deque())
        dq.append(e.ts)
        while dq and e.ts - dq[0] > self.ventana:
            dq.popleft()
        n = len(dq)
        if n < self.umbral:
            self.nivel.pop(e.ip, None)  # episodio cerrado: permite re-alertar más adelante
            return []
        nivel = 2 if n >= self.umbral * 10 else 1
        if nivel > self.nivel.get(e.ip, 0):
            self.nivel[e.ip] = nivel
            sev = "crítica" if nivel == 2 else "alta"
            return [_alerta("R001", e.ip,
                            f"{n} fallos en <= {self.ventana_min} min (fuerza bruta)",
                            severidad=sev, fallos_en_ventana=n, ultimo=str(e.ts))]
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
    """R004: login exitoso correlacionado con fallos PREVIOS del mismo (IP, usuario)."""

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
           watchlist: set[str] | None = None, allowlist: set[str] | None = None,
           geodb: str | None = None) -> list[dict]:
    """Corre las cuatro reglas sobre un stream de eventos y devuelve las alertas.

    `allowlist` suprime por completo los eventos de IPs conocidas-buenas (no se evalúan).
    `watchlist` eleva la severidad de las IPs marcadas. Cada alerta se enriquece con el
    contexto de red de su IP.
    """
    allowlist = allowlist or set()
    watchlist = watchlist or set()
    detectores: list[_Detector] = [
        _DetectorFuerzaBruta(umbral, timedelta(minutes=ventana_min), ventana_min),
        _DetectorSpraying(5, 3, timedelta(minutes=_VENTANA_SPRAY_MIN)),
        _DetectorEnumeracion(3, timedelta(minutes=_VENTANA_ENUM_MIN)),
        _DetectorCompromiso(3, timedelta(minutes=_VENTANA_COMPROMISO_MIN)),
    ]
    alertas: list[dict] = []
    for e in eventos:
        if e.ip in allowlist:
            continue  # IP conocida-buena: se suprime antes de evaluar
        for d in detectores:
            alertas.extend(d.feed(e))

    for a in alertas:
        a["red"] = _enriquecer(a["ip"], geodb)
        if a["ip"] in watchlist:
            a["severidad"] = "crítica"
            a["en_watchlist"] = True
    orden = {"crítica": 0, "alta": 1, "media": 2, "baja": 3}
    return sorted(alertas, key=lambda a: orden.get(a["severidad"], 9))


def analizar(lineas: list[str], umbral: int = 5, ventana_min: int = 2,
             watchlist: set[str] | None = None, allowlist: set[str] | None = None,
             geodb: str | None = None) -> list[dict]:
    """Corre todas las reglas sobre líneas en memoria (las ordena por tiempo antes)."""
    return _motor(parsear(lineas), umbral, ventana_min, watchlist, allowlist, geodb)


def analizar_archivo(ruta: str, umbral: int = 5, ventana_min: int = 2,
                     watchlist: set[str] | None = None, allowlist: set[str] | None = None,
                     geodb: str | None = None) -> list[dict]:
    """Analiza un archivo en streaming: no carga el archivo ni los eventos completos."""
    with open(ruta, encoding="utf-8", errors="ignore") as archivo:
        return _motor(_iter_eventos(archivo), umbral, ventana_min, watchlist, allowlist, geodb)


# --- Export a reglas Sigma (estándar abierto de detección) --------------------------

_SIGMA = {
    "R001": {
        "title": "SSH password brute force",
        "desc": "Multiple failed SSH password authentications from a single source IP "
                "within a short time window.",
        "keyword": "Failed password for",
        "condition": "keywords | count() by src_ip >= {umbral}",
        "timeframe": True, "tactic": "credential_access", "level": "high",
        "fp": "Users repeatedly mistyping their password; vulnerability scanners",
    },
    "R002": {
        "title": "SSH password spraying",
        "desc": "A single source IP attempting authentication against many distinct "
                "usernames (password spraying).",
        "keyword": "Failed password for",
        "condition": "keywords | count(user) by src_ip >= 5",
        "timeframe": True, "tactic": "credential_access", "level": "high",
        "fp": "Misconfigured service accounts; shared NAT egress",
    },
    "R003": {
        "title": "SSH user enumeration (invalid users)",
        "desc": "Repeated SSH authentication attempts for non-existent (invalid) users "
                "from one source IP.",
        "keyword": "Failed password for invalid user",
        "condition": "keywords | count(user) by src_ip >= 3",
        "timeframe": True, "tactic": "discovery", "level": "medium",
        "fp": "Health checks using rotating test usernames",
    },
    "R004": {
        "title": "SSH login after repeated failures (possible compromise)",
        "desc": "A successful SSH login from a source IP that previously produced "
                "authentication failures for the same user. Requires temporal correlation.",
        "keyword": "Accepted password for",
        "condition": "keywords",
        "timeframe": False, "tactic": "persistence", "level": "high",
        "fp": "Legitimate login after the user mistyped their password",
    },
}


def _regla_sigma(regla: str, umbral: int, ventana_min: int) -> str:
    """Construye una regla Sigma (YAML) para una de las reglas de detección."""
    tid, _ = ATTACK[regla]
    spec = _SIGMA[regla]
    rid = uuid.uuid5(uuid.NAMESPACE_DNS, f"pstk.log_analyzer.{regla}")
    ref = "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
    lineas = [
        f"title: {spec['title']} ({regla})",
        f"id: {rid}",
        "status: experimental",
        f"description: {spec['desc']}",
        "references:",
        f"    - {ref}",
        "author: Catalina Carlen",
        "logsource:",
        "    product: linux",
        "    service: sshd",
        "detection:",
        "    keywords:",
        f"        - '{spec['keyword']}'",
        f"    condition: {str(spec['condition']).format(umbral=umbral)}",
    ]
    if spec["timeframe"]:
        lineas.append(f"    timeframe: {ventana_min}m")
    lineas += [
        "fields:",
        "    - src_ip",
        "    - user",
        "falsepositives:",
        f"    - {spec['fp']}",
        f"level: {spec['level']}",
        "tags:",
        f"    - attack.{spec['tactic']}",
        f"    - attack.{tid.lower()}",
    ]
    return "\n".join(lineas)


def exportar_sigma(umbral: int = 5, ventana_min: int = 2) -> str:
    """Devuelve las cuatro reglas de detección como un documento Sigma (YAML multi-doc)."""
    return "\n---\n".join(_regla_sigma(r, umbral, ventana_min) for r in ("R001", "R002", "R003", "R004"))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detección estilo SIEM sobre logs de autenticación.")
    parser.add_argument("archivo", nargs="?", help="Ruta al archivo de log (ej. auth.log)")
    parser.add_argument("-u", "--umbral", type=int, default=5,
                        help="Fallos para marcar fuerza bruta (por defecto 5)")
    parser.add_argument("-v", "--ventana", type=int, default=2,
                        help="Ventana en minutos para la fuerza bruta (por defecto 2)")
    parser.add_argument("-w", "--watchlist", default="",
                        help="IPs en watchlist (eleva severidad), separadas por coma")
    parser.add_argument("-a", "--allowlist", default="",
                        help="IPs conocidas-buenas a suprimir, separadas por coma")
    parser.add_argument("--geodb", default=None,
                        help="Base offline 'cidr,pais,asn' para enriquecer país/ASN")
    parser.add_argument("--sigma", action="store_true",
                        help="Emite las detecciones como reglas Sigma y termina")
    parser.add_argument("--json", action="store_true", help="Salida en formato JSON")
    return parser.parse_args()


def _codigo_salida(alertas: list[dict]) -> int:
    """1 si hay alertas de severidad alta o crítica (para encadenar en pipelines), si no 0."""
    return 1 if any(a["severidad"] in ("crítica", "alta") for a in alertas) else 0


def main() -> None:
    args = _parse_args()
    if args.sigma:
        print(exportar_sigma(args.umbral, args.ventana))
        raise SystemExit(0)
    if not args.archivo:
        print("Falta el archivo de log (o usá --sigma para exportar las reglas).", file=sys.stderr)
        raise SystemExit(2)

    watchlist = {ip.strip() for ip in args.watchlist.split(",") if ip.strip()}
    allowlist = {ip.strip() for ip in args.allowlist.split(",") if ip.strip()}
    alertas = analizar_archivo(args.archivo, args.umbral, args.ventana, watchlist, allowlist, args.geodb)

    if args.json:
        print(json.dumps(alertas, ensure_ascii=False, indent=2))
    elif not alertas:
        print("Sin alertas: no se detectaron patrones sospechosos.")
    else:
        print(f"{len(alertas)} alerta(s) detectada(s):\n")
        for a in alertas:
            marca = "  [watchlist]" if a.get("en_watchlist") else ""
            pais = f" {a['red'].get('pais')}" if a.get("red", {}).get("pais") else ""
            print(f"[{a['severidad'].upper():<8}] {a['regla']} {a['tecnica']:<10} "
                  f"{a['ip']:<16} ({a['red']['alcance']}{pais}){marca}")
            print(f"           {a['descripcion']}")

    raise SystemExit(_codigo_salida(alertas))


if __name__ == "__main__":
    main()
