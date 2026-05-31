"""Verificador de integridad de archivos.

Calcula el hash SHA-256 de los archivos de un directorio y guarda una línea de
base (manifiesto). En ejecuciones posteriores compara el estado actual contra
esa base y reporta archivos modificados, nuevos o eliminados, igual que un
control de integridad (FIM) básico.

Conceptos de la materia aplicados: funciones, diccionarios, lectura/escritura
de archivos y estructuras de decisión.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os


def hash_archivo(ruta: str, bloque: int = 65536) -> str:
    """Devuelve el SHA-256 de un archivo leyéndolo por bloques."""
    h = hashlib.sha256()
    with open(ruta, "rb") as archivo:
        for trozo in iter(lambda: archivo.read(bloque), b""):
            h.update(trozo)
    return h.hexdigest()


def generar_manifiesto(directorio: str) -> dict[str, str]:
    """Devuelve {ruta_relativa: hash} para todos los archivos del directorio."""
    manifiesto: dict[str, str] = {}
    for raiz, _dirs, archivos in os.walk(directorio):
        for nombre in archivos:
            completa = os.path.join(raiz, nombre)
            relativa = os.path.relpath(completa, directorio)
            manifiesto[relativa] = hash_archivo(completa)
    return manifiesto


def comparar(base: dict[str, str], actual: dict[str, str]) -> dict[str, list[str]]:
    """Compara dos manifiestos y clasifica los cambios."""
    base_set, actual_set = set(base), set(actual)
    modificados = [r for r in base_set & actual_set if base[r] != actual[r]]
    return {
        "modificados": sorted(modificados),
        "nuevos": sorted(actual_set - base_set),
        "eliminados": sorted(base_set - actual_set),
    }


def guardar_manifiesto(manifiesto: dict[str, str], ruta: str) -> None:
    with open(ruta, "w", encoding="utf-8") as archivo:
        json.dump(manifiesto, archivo, indent=2, ensure_ascii=False)


def cargar_manifiesto(ruta: str) -> dict[str, str]:
    with open(ruta, encoding="utf-8") as archivo:
        return json.load(archivo)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verificador de integridad de archivos (FIM).")
    sub = parser.add_subparsers(dest="accion", required=True)

    p_base = sub.add_parser("baseline", help="Genera la línea de base")
    p_base.add_argument("directorio")
    p_base.add_argument("-o", "--salida", default="baseline.json")

    p_check = sub.add_parser("check", help="Compara el estado actual contra la base")
    p_check.add_argument("directorio")
    p_check.add_argument("-b", "--base", default="baseline.json")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if args.accion == "baseline":
        manifiesto = generar_manifiesto(args.directorio)
        guardar_manifiesto(manifiesto, args.salida)
        print(f"Línea de base guardada en {args.salida} ({len(manifiesto)} archivos).")
    elif args.accion == "check":
        cambios = comparar(cargar_manifiesto(args.base), generar_manifiesto(args.directorio))
        total = sum(len(v) for v in cambios.values())
        if total == 0:
            print("Sin cambios: la integridad se mantiene.")
            return
        for categoria, rutas in cambios.items():
            if rutas:
                print(f"\n{categoria.upper()} ({len(rutas)}):")
                for r in rutas:
                    print(f"  {r}")


if __name__ == "__main__":
    main()
