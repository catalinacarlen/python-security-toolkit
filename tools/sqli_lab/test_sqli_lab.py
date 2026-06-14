"""Tests del laboratorio de SQL Injection.

Demuestran de forma automatizada que la consulta vulnerable puede ser burlada,
que la versión parametrizada resiste el mismo ataque, y que el clasificador
reconoce las distintas familias de inyección.
"""

from sqli_lab import (
    PAYLOAD_INYECCION,
    PAYLOADS,
    buscar_vulnerable,
    clasificar,
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
    assert login_vulnerable(con, PAYLOAD_INYECCION, "cualquier") is True
    con.close()


def test_la_version_segura_resiste_la_inyeccion() -> None:
    con = crear_db()
    assert login_seguro(con, PAYLOAD_INYECCION, "cualquier") is False
    con.close()


def test_union_based_filtra_todas_las_filas() -> None:
    con = crear_db()
    # Sin UNION, "x" no existe -> 0 filas. Con el payload UNION, salen todas.
    assert buscar_vulnerable(con, "x") == []
    filas = buscar_vulnerable(con, PAYLOADS["union"])
    assert len(filas) == 3
    assert ("admin", "s3cr3t") in filas
    con.close()


def test_clasificador_reconoce_cada_familia() -> None:
    assert clasificar(PAYLOADS["union"]) == "union"
    assert clasificar(PAYLOADS["time_blind"]) == "time_blind"
    assert clasificar(PAYLOADS["or_true"]) == "tautologia"
    assert clasificar(PAYLOADS["auth_bypass"]) == "auth_bypass"


def test_clasificador_ignora_entrada_legitima() -> None:
    assert clasificar("Cata") == "ninguna"
    assert clasificar("usuario_normal_123") == "ninguna"
