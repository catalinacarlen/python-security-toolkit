"""Escáner de puertos TCP simple.

Comprueba qué puertos TCP están abiertos en un host usando sockets de la
librería estándar. Pensado con fines educativos y de auditoría sobre sistemas
propios o con autorización explícita.

Conceptos de la materia aplicados: funciones, ciclos, arreglos (listas),
estructuras de decisión y manejo de excepciones.
"""

from __future__ import annotations

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor


# Puertos comunes y el servicio que suelen exponer (referencia rápida).
COMMON_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
    3389: "RDP", 8080: "HTTP-alt",
}


def scan_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """Devuelve True si el puerto TCP está abierto en el host.

    Abre un socket y realiza un connect_ex: si devuelve 0, el puerto acepta
    conexiones (está abierto).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            return sock.connect_ex((host, port)) == 0
        except (socket.gaierror, OSError):
            return False


def scan_range(
    host: str,
    start: int = 1,
    end: int = 1024,
    timeout: float = 0.5,
    workers: int = 100,
) -> list[int]:
    """Escanea un rango de puertos y devuelve la lista ordenada de abiertos.

    Usa un pool de hilos para acelerar el barrido sin complejizar la lógica.
    """
    ports = list(range(start, end + 1))
    abiertos: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        resultados = pool.map(lambda p: (p, scan_port(host, p, timeout)), ports)
        for puerto, esta_abierto in resultados:
            if esta_abierto:
                abiertos.append(puerto)
    return sorted(abiertos)


def describir(puerto: int) -> str:
    """Devuelve el nombre del servicio habitual para un puerto, o 'desconocido'."""
    return COMMON_PORTS.get(puerto, "desconocido")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Escáner de puertos TCP (uso autorizado).")
    parser.add_argument("host", help="Host o IP objetivo (ej. 127.0.0.1)")
    parser.add_argument("-s", "--start", type=int, default=1, help="Puerto inicial")
    parser.add_argument("-e", "--end", type=int, default=1024, help="Puerto final")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="Timeout por puerto (s)")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    print(f"Escaneando {args.host} (puertos {args.start}-{args.end})...\n")
    abiertos = scan_range(args.host, args.start, args.end, args.timeout)
    if not abiertos:
        print("No se encontraron puertos abiertos en el rango indicado.")
        return
    print(f"Puertos abiertos ({len(abiertos)}):")
    for puerto in abiertos:
        print(f"  {puerto:>5}/tcp  {describir(puerto)}")


if __name__ == "__main__":
    main()
