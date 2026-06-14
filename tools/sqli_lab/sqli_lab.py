"""Laboratorio de SQL Injection (entorno controlado y local).

Crea una base SQLite en memoria y demuestra varias familias de inyección contra
una consulta VULNERABLE (concatenación de strings) frente a una SEGURA
(parametrizada). Además incluye un **clasificador** que, dado un payload, infiere
de qué tipo de inyección se trata — el tipo de heurística que usaría un WAF o un
analizador estático para alertar.

Familias demostradas:
- Authentication bypass clásico (`' OR '1'='1` / `admin' --`).
- UNION-based (extraer datos de otras columnas/tablas).
- Boolean-based blind (inferir información por verdadero/falso).
- Time-based blind (inferir información por demora de la respuesta).

El código vulnerable es intencionalmente inseguro y existe solo con fines de
demostración. No debe usarse en producción. Solo librería estándar.
"""

from __future__ import annotations

import argparse
import re
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


def buscar_vulnerable(con: sqlite3.Connection, termino: str) -> list[tuple]:
    """Búsqueda VULNERABLE por nombre de usuario (permite demostrar UNION-based)."""
    consulta = f"SELECT usuario, password FROM usuarios WHERE usuario = '{termino}'"
    return con.execute(consulta).fetchall()


# Payloads de ejemplo, etiquetados por familia.
PAYLOADS: dict[str, str] = {
    "auth_bypass": "admin' --",
    "or_true": "' OR '1'='1",
    "union": "x' UNION SELECT usuario, password FROM usuarios --",
    "boolean_blind": "admin' AND '1'='1",
    "time_blind": "admin'; SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 0 END --",
}
PAYLOAD_INYECCION = PAYLOADS["auth_bypass"]  # compatibilidad con tests previos


def clasificar(payload: str) -> str:
    """Clasifica un payload en una familia de inyección SQL (heurística tipo WAF).

    Devuelve una etiqueta: 'union', 'time_blind', 'boolean_blind', 'auth_bypass',
    'tautologia', 'stacked' o 'ninguna' si no parece una inyección.
    """
    p = payload.lower()
    if not re.search(r"['\";]|--|\bor\b|\band\b|\bunion\b", p):
        return "ninguna"
    if "union" in p and "select" in p:
        return "union"
    if re.search(r"sleep\s*\(|pg_sleep|waitfor\s+delay|randomblob|benchmark\s*\(", p):
        return "time_blind"
    if ";" in payload.strip().rstrip(";") and "select" in p:
        return "stacked"  # consultas apiladas
    if re.search(r"or\s+'?1'?\s*=\s*'?1'?|or\s+1\s*=\s*1", p):
        return "tautologia"
    if "--" in p or "#" in p:
        return "auth_bypass"
    if re.search(r"and\s+'?\w+'?\s*=\s*'?\w+'?", p):
        return "boolean_blind"
    return "sospechosa"


def _demo() -> None:
    con = crear_db()
    print("== 1) Credenciales correctas ==")
    print("  vulnerable:", login_vulnerable(con, "admin", "s3cr3t"))
    print("  seguro    :", login_seguro(con, "admin", "s3cr3t"))

    print(f"\n== 2) Bypass de autenticación  (usuario = {PAYLOADS['auth_bypass']!r}) ==")
    print("  vulnerable:", login_vulnerable(con, PAYLOADS["auth_bypass"], "x"), "  <- ¡acceso indebido!")
    print("  seguro    :", login_seguro(con, PAYLOADS["auth_bypass"], "x"), "  <- ataque bloqueado")

    print("\n== 3) UNION-based  (extracción de datos) ==")
    filas = buscar_vulnerable(con, PAYLOADS["union"])
    print(f"  la búsqueda vulnerable filtró {len(filas)} filas, incluyendo contraseñas:")
    for usuario, password in filas:
        print(f"     {usuario} : {password}")

    print("\n== 4) Clasificador de payloads ==")
    for payload in PAYLOADS.values():
        print(f"  {clasificar(payload):<13} <- {payload}")
    print(f"  {clasificar('Cata'):<13} <- Cata   (entrada legítima)")

    con.close()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Demostración local de SQL Injection.")
    parser.add_argument("--demo", action="store_true", help="Ejecuta la demostración completa")
    parser.add_argument("--clasificar", metavar="PAYLOAD",
                        help="Clasifica un payload e indica su familia de inyección")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if args.clasificar is not None:
        print(clasificar(args.clasificar))
        return
    _demo()


if __name__ == "__main__":
    main()
