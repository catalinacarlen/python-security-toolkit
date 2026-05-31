"""Laboratorio de SQL Injection (entorno controlado y local).

Crea una base de datos SQLite en memoria con una tabla de usuarios y demuestra
la diferencia entre una consulta VULNERABLE (concatenando strings) y una SEGURA
(con consultas parametrizadas). Sirve para entender por qué nunca se debe armar
SQL pegando texto del usuario.

ADVERTENCIA: este código incluye una función vulnerable A PROPÓSITO, con fines
educativos. Nunca se debe escribir así en producción.

Conceptos de la materia aplicados: funciones, strings, estructuras de decisión
y manejo de datos.
"""

from __future__ import annotations

import argparse
import sqlite3


def crear_db() -> sqlite3.Connection:
    """Crea una base SQLite en memoria con usuarios de ejemplo."""
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE usuarios (id INTEGER PRIMARY KEY, usuario TEXT, password TEXT)")
    con.executemany(
        "INSERT INTO usuarios (usuario, password) VALUES (?, ?)",
        [("admin", "s3cr3t"), ("cata", "pythonista"), ("invitado", "guest")],
    )
    con.commit()
    return con


def login_vulnerable(con: sqlite3.Connection, usuario: str, password: str) -> bool:
    """INSEGURO: arma la consulta concatenando la entrada del usuario.

    Una entrada como  usuario = "admin' --"  comenta el resto de la consulta y
    permite entrar sin contraseña. NO USAR JAMÁS EN PRODUCCIÓN.
    """
    consulta = (
        "SELECT * FROM usuarios "
        f"WHERE usuario = '{usuario}' AND password = '{password}'"
    )
    return con.execute(consulta).fetchone() is not None


def login_seguro(con: sqlite3.Connection, usuario: str, password: str) -> bool:
    """SEGURO: usa parámetros (?) para que la entrada nunca se interprete como SQL."""
    consulta = "SELECT * FROM usuarios WHERE usuario = ? AND password = ?"
    return con.execute(consulta, (usuario, password)).fetchone() is not None


# Cadena de ataque clásica: cierra la comilla y comenta el resto de la consulta.
PAYLOAD_INYECCION = "admin' --"


def _demo() -> None:
    con = crear_db()
    print("== Credenciales correctas ==")
    print("  vulnerable:", login_vulnerable(con, "admin", "s3cr3t"))
    print("  seguro    :", login_seguro(con, "admin", "s3cr3t"))

    print(f"\n== Intento de inyección  (usuario = {PAYLOAD_INYECCION!r}, sin password) ==")
    print("  vulnerable:", login_vulnerable(con, PAYLOAD_INYECCION, "loquesea"),
          "  <- ¡acceso indebido!")
    print("  seguro    :", login_seguro(con, PAYLOAD_INYECCION, "loquesea"),
          "  <- ataque bloqueado")
    con.close()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Demo educativa de SQL Injection (local).")
    parser.add_argument("--demo", action="store_true", help="Ejecuta la demostración comparativa")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if args.demo or True:  # por simplicidad, siempre corre la demo
        _demo()


if __name__ == "__main__":
    main()
