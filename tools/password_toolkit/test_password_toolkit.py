"""Tests del kit de contraseñas."""

import string

import pytest

from password_toolkit import evaluar_fortaleza, generar_password, hashear


def test_password_debil_tiene_puntaje_bajo() -> None:
    puntaje, _ = evaluar_fortaleza("abc")
    assert puntaje <= 1


def test_password_fuerte_tiene_puntaje_alto() -> None:
    puntaje, etiqueta = evaluar_fortaleza("Abcdef1!ghij")
    assert puntaje == 4
    assert etiqueta == "Muy fuerte"


def test_generar_respeta_longitud() -> None:
    assert len(generar_password(20)) == 20


def test_generar_incluye_todas_las_clases() -> None:
    pwd = generar_password(16)
    assert any(c.islower() for c in pwd)
    assert any(c.isupper() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(c in string.punctuation for c in pwd)


def test_generar_longitud_invalida_lanza_error() -> None:
    with pytest.raises(ValueError):
        generar_password(3)


def test_hash_es_deterministico_y_el_salt_lo_cambia() -> None:
    assert hashear("secreto") == hashear("secreto")
    assert hashear("secreto", salt="a") != hashear("secreto", salt="b")
    # SHA-256 produce 64 caracteres hexadecimales
    assert len(hashear("secreto")) == 64
