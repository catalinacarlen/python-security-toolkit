"""Escáner de puertos TCP con banner grabbing y detección de servicio.

Comprueba qué puertos TCP están abiertos en un host y, para los que lo están,
intenta leer el **banner** que el servicio anuncia al conectarse. A partir de ese
banner (y del puerto) infiere qué servicio corre realmente, no solo el nombre
"de catálogo" del puerto. Incluye control de concurrencia y de rate, y salida JSON.

Pensado con fines educativos y de auditoría sobre sistemas propios o con
autorización explícita. Solo librería estándar.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor

# Puertos comunes y el servicio que suelen exponer (referencia rápida).
COMMON_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt",
}

# Firmas para reconocer el servicio a partir del banner (independiente del puerto).
_FIRMAS: list[tuple[str, str]] = [
    (r"SSH-\d", "SSH"),
    (r"^220.*(FTP|FileZilla|vsFTPd|ProFTPD)", "FTP"),
    (r"^220.*SMTP|ESMTP", "SMTP"),
    (r"HTTP/\d\.\d", "HTTP"),
    (r"^\+OK", "POP3"),
    (r"^\* OK.*IMAP", "IMAP"),
    (r"-ERR|^\$|redis", "Redis"),
    (r"mysql_native_password|^.\x00\x00\x00\n", "MySQL"),
]


def scan_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """Devuelve True si el puerto TCP está abierto en el host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            return sock.connect_ex((host, port)) == 0
        except (socket.gaierror, OSError):
            return False


def agarrar_banner(host: str, port: int, timeout: float = 1.0) -> str:
    """Intenta leer el banner de un puerto abierto.

    Muchos servicios saludan apenas uno se conecta (SSH, FTP, SMTP). Para los que
    no lo hacen (como HTTP), enviamos un pequeño estímulo y leemos la respuesta.
    Devuelve el banner limpio o "" si no se obtuvo nada.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) != 0:
                return ""
            try:
                datos = sock.recv(256)
                if not datos and port in (80, 8080, 443):
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    datos = sock.recv(256)
            except (socket.timeout, OSError):
                # Servicio mudo: probamos con un estímulo HTTP genérico.
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    datos = sock.recv(256)
                except OSError:
                    return ""
            return datos.decode("latin-1", errors="replace").strip()
    except (socket.gaierror, OSError):
        return ""


def identificar_servicio(port: int, banner: str) -> str:
    """Infiere el servicio: primero por el banner, si no por el puerto conocido."""
    for patron, nombre in _FIRMAS:
        if re.search(patron, banner, re.IGNORECASE):
            return nombre
    return COMMON_PORTS.get(port, "desconocido")


def describir(puerto: int) -> str:
    """Nombre del servicio habitual para un puerto, o 'desconocido'."""
    return COMMON_PORTS.get(puerto, "desconocido")


def scan_range(
    host: str,
    start: int = 1,
    end: int = 1024,
    timeout: float = 0.5,
    workers: int = 100,
) -> list[int]:
    """Escanea un rango y devuelve la lista ordenada de puertos abiertos."""
    ports = list(range(start, end + 1))
    abiertos: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        resultados = pool.map(lambda p: (p, scan_port(host, p, timeout)), ports)
        for puerto, esta_abierto in resultados:
            if esta_abierto:
                abiertos.append(puerto)
    return sorted(abiertos)


def escanear(
    host: str,
    start: int = 1,
    end: int = 1024,
    timeout: float = 0.5,
    workers: int = 100,
    delay: float = 0.0,
    con_banner: bool = True,
) -> list[dict]:
    """Escanea y devuelve, por cada puerto abierto, un dict con banner y servicio.

    `delay` introduce una pausa entre lanzamientos para limitar el rate (útil para
    no saturar la red ni disparar defensas). `workers` controla la concurrencia.
    """
    abiertos = scan_range(host, start, end, timeout, workers)
    resultados: list[dict] = []
    for puerto in abiertos:
        if delay:
            time.sleep(delay)
        banner = agarrar_banner(host, puerto, max(timeout, 1.0)) if con_banner else ""
        resultados.append({
            "puerto": puerto,
            "servicio": identificar_servicio(puerto, banner),
            "banner": banner or None,
        })
    return resultados


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Escáner de puertos TCP con banner grabbing (uso autorizado).")
    parser.add_argument("host", help="Host o IP objetivo (ej. 127.0.0.1)")
    parser.add_argument("-s", "--start", type=int, default=1, help="Puerto inicial")
    parser.add_argument("-e", "--end", type=int, default=1024, help="Puerto final")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="Timeout por puerto (s)")
    parser.add_argument("-W", "--workers", type=int, default=100, help="Hilos concurrentes")
    parser.add_argument("-d", "--delay", type=float, default=0.0,
                        help="Pausa entre banners (s) para limitar el rate")
    parser.add_argument("--no-banner", action="store_true", help="No intentar leer banners")
    parser.add_argument("--json", action="store_true", help="Salida en formato JSON")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    resultados = escanear(args.host, args.start, args.end, args.timeout,
                          args.workers, args.delay, con_banner=not args.no_banner)
    if args.json:
        print(json.dumps({"host": args.host, "abiertos": resultados}, ensure_ascii=False, indent=2))
        return
    if not resultados:
        print(f"No se encontraron puertos abiertos en {args.host} ({args.start}-{args.end}).")
        return
    print(f"Puertos abiertos en {args.host} ({len(resultados)}):\n")
    for r in resultados:
        linea = f"  {r['puerto']:>5}/tcp  {r['servicio']}"
        if r["banner"]:
            linea += f"   ── {r['banner'][:60]}"
        print(linea)


if __name__ == "__main__":
    main()
