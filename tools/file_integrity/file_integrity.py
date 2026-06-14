"""Verificador de integridad de archivos (FIM) con permisos, firma y modo watch.

Calcula el hash SHA-256 y los permisos de cada archivo de un directorio y guarda
una línea de base. En ejecuciones posteriores compara el estado actual y reporta
archivos modificados, nuevos, eliminados o con **permisos cambiados**.

Mejoras sobre un FIM básico:
- Detecta cambios de **permisos** (modo), no solo de contenido — un atacante que
  hace world-writable un archivo sin tocar su contenido también es una amenaza.
- La línea de base puede **firmarse con HMAC**: si alguien la altera para ocultar
  un cambio, la verificación de la firma falla y se detecta la manipulación.
- **Modo watch**: vigila el directorio en intervalos y avisa apenas algo cambia.

Solo librería estándar. Para uso en entornos autorizados.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import time


def hash_archivo(ruta: str, bloque: int = 65536) -> str:
    """Devuelve el SHA-256 de un archivo leyéndolo por bloques."""
    h = hashlib.sha256()
    with open(ruta, "rb") as archivo:
        for trozo in iter(lambda: archivo.read(bloque), b""):
            h.update(trozo)
    return h.hexdigest()


def modo_archivo(ruta: str) -> str:
    """Devuelve los permisos del archivo como string octal (ej. '0o644')."""
    return oct(os.stat(ruta).st_mode & 0o777)


def generar_manifiesto(directorio: str) -> dict[str, dict]:
    """Devuelve {ruta_relativa: {hash, modo}} para todos los archivos del directorio."""
    manifiesto: dict[str, dict] = {}
    for raiz, _dirs, archivos in os.walk(directorio):
        for nombre in archivos:
            completa = os.path.join(raiz, nombre)
            relativa = os.path.relpath(completa, directorio)
            try:
                manifiesto[relativa] = {"hash": hash_archivo(completa), "modo": modo_archivo(completa)}
            except OSError:
                continue  # archivo desaparecido o sin permiso de lectura
    return manifiesto


def comparar(base: dict[str, dict], actual: dict[str, dict]) -> dict[str, list[str]]:
    """Compara dos manifiestos y clasifica los cambios (incluye permisos)."""
    base_set, actual_set = set(base), set(actual)
    comunes = base_set & actual_set
    modificados = [r for r in comunes if base[r]["hash"] != actual[r]["hash"]]
    permisos = [r for r in comunes
                if base[r]["hash"] == actual[r]["hash"] and base[r].get("modo") != actual[r].get("modo")]
    return {
        "modificados": sorted(modificados),
        "permisos": sorted(permisos),
        "nuevos": sorted(actual_set - base_set),
        "eliminados": sorted(base_set - actual_set),
    }


# --- Firma del baseline (anti-manipulación) ---------------------------------

def _canonico(manifiesto: dict[str, dict]) -> bytes:
    """Serialización determinista del manifiesto para firmarlo/verificarlo."""
    return json.dumps(manifiesto, sort_keys=True, ensure_ascii=False).encode("utf-8")


def firmar(manifiesto: dict[str, dict], clave: str) -> str:
    """Devuelve el HMAC-SHA256 del manifiesto con la clave dada."""
    return hmac.new(clave.encode("utf-8"), _canonico(manifiesto), hashlib.sha256).hexdigest()


def verificar_firma(manifiesto: dict[str, dict], firma: str, clave: str) -> bool:
    """True si la firma corresponde al manifiesto (comparación en tiempo constante)."""
    return hmac.compare_digest(firmar(manifiesto, clave), firma)


def guardar_manifiesto(manifiesto: dict[str, dict], ruta: str, clave: str | None = None) -> None:
    """Guarda el manifiesto; si se da una clave, incluye su firma HMAC."""
    envoltura: dict[str, object] = {"manifiesto": manifiesto}
    if clave:
        envoltura["firma"] = firmar(manifiesto, clave)
    with open(ruta, "w", encoding="utf-8") as archivo:
        json.dump(envoltura, archivo, indent=2, ensure_ascii=False)


def cargar_manifiesto(ruta: str, clave: str | None = None) -> dict[str, dict]:
    """Carga el manifiesto. Si hay clave, verifica la firma y lanza si no coincide."""
    with open(ruta, encoding="utf-8") as archivo:
        envoltura = json.load(archivo)
    # Retrocompatibilidad: un baseline viejo era el manifiesto plano.
    manifiesto = envoltura.get("manifiesto", envoltura) if isinstance(envoltura, dict) else envoltura
    if clave:
        firma = envoltura.get("firma") if isinstance(envoltura, dict) else None
        if not firma or not verificar_firma(manifiesto, firma, clave):
            raise ValueError("Firma inválida: la línea de base pudo haber sido manipulada.")
    return manifiesto


def vigilar(directorio: str, base: dict[str, dict], intervalo: float = 2.0) -> None:
    """Modo watch: compara el directorio contra la base cada `intervalo` segundos."""
    print(f"Vigilando {directorio} cada {intervalo}s (Ctrl+C para salir)...")
    actual = base
    try:
        while True:
            time.sleep(intervalo)
            nuevo = generar_manifiesto(directorio)
            cambios = comparar(actual, nuevo)
            if any(cambios.values()):
                ts = time.strftime("%H:%M:%S")
                for categoria, rutas in cambios.items():
                    for r in rutas:
                        print(f"[{ts}] {categoria.upper():<11} {r}")
            actual = nuevo
    except KeyboardInterrupt:
        print("\nFin de la vigilancia.")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verificador de integridad de archivos (FIM).")
    parser.add_argument("--json", action="store_true", help="Salida en formato JSON (en check)")
    sub = parser.add_subparsers(dest="accion", required=True)

    p_base = sub.add_parser("baseline", help="Genera la línea de base")
    p_base.add_argument("directorio")
    p_base.add_argument("-o", "--salida", default="baseline.json")
    p_base.add_argument("-k", "--clave", default=None, help="Clave para firmar el baseline (HMAC)")

    p_check = sub.add_parser("check", help="Compara el estado actual contra la base")
    p_check.add_argument("directorio")
    p_check.add_argument("-b", "--base", default="baseline.json")
    p_check.add_argument("-k", "--clave", default=None, help="Clave para verificar la firma")

    p_watch = sub.add_parser("watch", help="Vigila el directorio en tiempo real")
    p_watch.add_argument("directorio")
    p_watch.add_argument("-i", "--intervalo", type=float, default=2.0)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if args.accion == "baseline":
        manifiesto = generar_manifiesto(args.directorio)
        guardar_manifiesto(manifiesto, args.salida, args.clave)
        firmado = " (firmado)" if args.clave else ""
        print(f"Línea de base guardada en {args.salida} ({len(manifiesto)} archivos){firmado}.")
    elif args.accion == "check":
        base = cargar_manifiesto(args.base, args.clave)
        cambios = comparar(base, generar_manifiesto(args.directorio))
        if args.json:
            print(json.dumps(cambios, ensure_ascii=False, indent=2))
            return
        total = sum(len(v) for v in cambios.values())
        if total == 0:
            print("Sin cambios: la integridad se mantiene.")
            return
        for categoria, rutas in cambios.items():
            if rutas:
                print(f"\n{categoria.upper()} ({len(rutas)}):")
                for r in rutas:
                    print(f"  {r}")
    elif args.accion == "watch":
        base = generar_manifiesto(args.directorio)
        vigilar(args.directorio, base, args.intervalo)


if __name__ == "__main__":
    main()
