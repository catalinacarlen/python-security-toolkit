"""Tests del laboratorio de SQL Injection.

Demuestran de forma automatizada que la consulta vulnerable puede ser burlada y
que la versión parametrizada resiste el mismo ataque.
"""

from sqli_lab import (
    PAYLOAD_INYECCION,
    crear_db,
    login_seguro,
    login_vulnerable,
)


def test_login_correcto_funciona_en_ambas_versiones() -> None:
    con = crear_db()
    assert login_vulnerable(con, "admin", "s3cr3t") is True
    assert login_seguro(con, "admin", "s3cr3t") is True
    con.close()


def test_password_incorrecta_es_rechazada() -> None:
    con = crear_db()
    assert login_vulnerable(con, "admin", "incorrecta") is False
    assert login_seguro(con, "admin", "incorrecta") is False
    con.close()


def test_la_inyeccion_burla_la_version_vulnerable() -> None:
    con = crear_db()
    # Sin saber la contraseña, la inyección logra entrar en la versión vulnerable.
    assert login_vulnerable(con, PAYLOAD_INYECCION, "cualquier") is True
    con.close()


def test_la_version_segura_resiste_la_inyeccion() -> None:
    con = crear_db()
    # El mismo ataque NO funciona contra la consulta parametrizada.
    assert login_seguro(con, PAYLOAD_INYECCION, "cualquier") is False
    con.close()
