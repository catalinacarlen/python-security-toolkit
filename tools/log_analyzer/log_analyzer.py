"""Analizador de logs de autenticación.

Parsea un archivo de log tipo `auth.log` de Linux, cuenta los intentos fallidos
de inicio de sesión por dirección IP y marca las IPs que superan un umbral, un
patrón típico de ataque de fuerza bruta.

Conceptos de la materia aplicados: expresiones regulares, lectura de archivos,
diccionarios (arreglos asociativos), ciclos y ordenamiento.
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict

# Captura la IP de líneas como:
# "Failed password for invalid user admin from 192.168.0.5 port 22 ssh2"
PATRON_FALLO = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (\d{1,3}(?:\.\d{1,3}){3})"
)


def contar_fallos(lineas: list[str]) -> dict[str, int]:
    """Devuelve un diccionario {ip: cantidad_de_intentos_fallidos}."""
    conteo: dict[str, int] = defaultdict(int)
    for linea in lineas:
        coincidencia = PATRON_FALLO.search(linea)
        if coincidencia:
            ip = coincidencia.group(1)
            conteo[ip] += 1
    return dict(conteo)


def detectar_fuerza_bruta(conteo: dict[str, int], umbral: int = 5) -> list[tuple[str, int]]:
    """Devuelve las IPs con intentos >= umbral, ordenadas de mayor a menor."""
    sospechosas = [(ip, n) for ip, n in conteo.items() if n >= umbral]
    return sorted(sospechosas, key=lambda par: par[1], reverse=True)


def analizar_archivo(ruta: str, umbral: int = 5) -> list[tuple[str, int]]:
    """Lee un archivo de log y devuelve las IPs sospechosas de fuerza bruta."""
    with open(ruta, encoding="utf-8", errors="ignore") as archivo:
        lineas = archivo.readlines()
    return detectar_fuerza_bruta(contar_fallos(lineas), umbral)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detecta fuerza bruta en logs de autenticación.")
    parser.add_argument("archivo", help="Ruta al archivo de log (ej. auth.log)")
    parser.add_argument("-u", "--umbral", type=int, default=5,
                        help="Intentos fallidos para marcar una IP (por defecto 5)")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    sospechosas = analizar_archivo(args.archivo, args.umbral)
    if not sospechosas:
        print("No se detectaron IPs por encima del umbral.")
        return
    print(f"IPs sospechosas (>= {args.umbral} intentos fallidos):\n")
    for ip, intentos in sospechosas:
        print(f"  {ip:<16} {intentos} intentos")


if __name__ == "__main__":
    main()
