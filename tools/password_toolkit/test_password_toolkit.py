"""Tests del kit de contraseñas."""

import string
from unittest import mock

import pytest
from password_toolkit import (
    auditar,
    derivar,
    entropia_bits,
    evaluar_fortaleza,
    generar_password,
    hashear,
    tiempo_crackeo,
    verificar_derivado,
    verificar_filtrada,
)

# --- Fortaleza por entropía -------------------------------------------------

def test_password_debil_tiene_puntaje_bajo() -> None:
    puntaje, _ = evaluar_fortaleza("abc")
    assert puntaje <= 1


def test_password_larga_y_variada_es_fuerte() -> None:
    puntaje, etiqueta = evaluar_fortaleza("C0rr3ct-H0rs3_Battery$taple!9")
    assert puntaje >= 3
    assert etiqueta in {"Fuerte", "Muy fuerte"}


def test_mas_longitud_implica_mas_entropia() -> None:
    assert entropia_bits("aaaaaaaaaaaa") < entropia_bits("Xj9$mK2!pQ7@wL")


def test_password_comun_es_penalizada() -> None:
    # "password" es común: debe quedar por debajo de su entropía "bruta".
    assert entropia_bits("password") < 8 * 4  # 8 chars * log2(26) ~= 37 bruto
    assert evaluar_fortaleza("password")[0] <= 1


def test_tiempo_crackeo_devuelve_texto_legible() -> None:
    assert tiempo_crackeo(10) == "instantáneo"
    assert "siglos" in tiempo_crackeo(200) or "miles" in tiempo_crackeo(200)


# --- Generación -------------------------------------------------------------

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


# --- Hashing ----------------------------------------------------------------

def test_sha256_es_deterministico_y_el_salt_lo_cambia() -> None:
    assert hashear("secreto") == hashear("secreto")
    assert hashear("secreto", salt="a") != hashear("secreto", salt="b")
    assert len(hashear("secreto")) == 64


def test_pbkdf2_genera_salt_distinto_cada_vez() -> None:
    a, b = derivar("secreto"), derivar("secreto")
    assert a != b  # salt aleatorio distinto
    assert a.startswith("pbkdf2_sha256$")


def test_pbkdf2_se_verifica_correctamente() -> None:
    codificado = derivar("secreto")
    assert verificar_derivado("secreto", codificado) is True
    assert verificar_derivado("incorrecta", codificado) is False
    assert verificar_derivado("secreto", "formato-invalido") is False


# --- Breach check (HIBP, mockeado para no depender de la red) ----------------

class _RespFalsa:
    def __init__(self, texto: str):
        self._texto = texto

    def read(self):
        return self._texto.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_verificar_filtrada_detecta_password_comprometida() -> None:
    # SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    # prefijo = 5BAA6, sufijo = 1E4C9B93F3F0682250B6CF8331B7EE68FD8
    cuerpo = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:99999\nFFFF:1"
    with mock.patch("password_toolkit.request.urlopen", return_value=_RespFalsa(cuerpo)):
        assert verificar_filtrada("password") == 99999


def test_verificar_filtrada_password_no_listada() -> None:
    with mock.patch("password_toolkit.request.urlopen", return_value=_RespFalsa("AAAA:1\nBBBB:2")):
        assert verificar_filtrada("una-pass-rarisima") == 0


def test_verificar_filtrada_sin_red_devuelve_none() -> None:
    from urllib import error
    with mock.patch("password_toolkit.request.urlopen", side_effect=error.URLError("sin red")):
        assert verificar_filtrada("password") is None


# --- Reporte combinado ------------------------------------------------------

def test_auditar_offline_no_consulta_red() -> None:
    rep = auditar("Xj9$mK2!pQ7@wL", offline=True)
    assert rep["apariciones_en_filtraciones"] is None
    assert rep["comprometida"] is None
    assert rep["entropia_bits"] > 0
    assert "tiempo_crackeo_estimado" in rep


# --- Detección de patrones humanos ------------------------------------------

def test_palabra_mas_anio_es_debil() -> None:
    # El patrón "palabra + año + símbolo" no debe puntuar como fuerte.
    for pwd in ("Princesa2002!", "Verano2024!", "Santiago1990", "boca2024"):
        puntaje, _ = evaluar_fortaleza(pwd)
        assert puntaje <= 1, pwd
        assert entropia_bits(pwd) < 30, pwd


def test_sustituciones_leet_no_evaden_la_deteccion() -> None:
    # P4ssw0rd se normaliza a password y debe quedar muy débil.
    assert entropia_bits("P4ssw0rd!") < 30
    assert evaluar_fortaleza("Pr1nc3sa")[0] <= 1


def test_passphrase_se_mantiene_fuerte() -> None:
    # Varias palabras no listadas no deben penalizarse como una sola débil.
    assert evaluar_fortaleza("correct horse battery staple")[0] >= 3


def test_aleatoria_larga_se_mantiene_fuerte() -> None:
    assert evaluar_fortaleza("C0rr3ct-H0rs3_Battery$taple!9")[0] >= 3
    assert evaluar_fortaleza("tR0ub4dour&3xKp9zL")[0] >= 3


def test_anio_embebido_penaliza() -> None:
    assert entropia_bits("MNbVcXz2001") < entropia_bits("MNbVcXzqplm")


def test_palabra_embebida_del_diccionario_es_debil() -> None:
    # 'catalina' y 'juan' están en la lista curada.
    assert evaluar_fortaleza("Catalina123")[0] <= 1
    assert evaluar_fortaleza("juan1985")[0] <= 1


# --- Entrada segura y wordlist externa --------------------------------------

def test_resolver_password_pide_sin_eco_si_falta(monkeypatch) -> None:
    import password_toolkit as p
    monkeypatch.setattr(p.getpass, "getpass", lambda *a, **k: "desde-getpass")
    assert p._resolver_password(None) == "desde-getpass"
    assert p._resolver_password("dada") == "dada"


def test_wordlist_externa_amplia_el_diccionario(tmp_path, monkeypatch) -> None:
    import password_toolkit as p
    wl = tmp_path / "wl.txt"
    wl.write_text("supersecretosolomio\n")
    # sin la wordlist, es fuerte; con ella, la palabra embebida la vuelve débil.
    assert evaluar_fortaleza("Supersecretosolomio99")[0] >= 3
    monkeypatch.setenv("PSTK_WORDLIST", str(wl))
    p._diccionario.cache_clear()
    try:
        assert evaluar_fortaleza("Supersecretosolomio99")[0] <= 1
    finally:
        p._diccionario.cache_clear()
