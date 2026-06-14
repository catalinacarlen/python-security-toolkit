"""Tests del analizador de logs (detecciones estilo SIEM)."""

import os

from log_analyzer import (
    analizar,
    analizar_archivo,
    detectar_compromiso,
    detectar_enumeracion,
    detectar_fuerza_bruta,
    detectar_spraying,
    parsear,
)


def _reglas(alertas: list[dict]) -> set[str]:
    return {a["regla"] for a in alertas}


# --- Parseo -----------------------------------------------------------------

def test_parsear_distingue_fallo_y_exito() -> None:
    lineas = [
        "May 11 10:00:01 h sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2",
        "May 11 10:00:05 h sshd[2]: Accepted password for cata from 5.6.7.8 port 22 ssh2",
    ]
    eventos = parsear(lineas)
    assert len(eventos) == 2
    assert eventos[0].exito is False
    assert eventos[0].usuario_invalido is True
    assert eventos[1].exito is True
    assert eventos[1].ip == "5.6.7.8"


# --- R001 fuerza bruta (con ventana temporal) -------------------------------

def test_fuerza_bruta_dentro_de_ventana() -> None:
    lineas = [
        f"May 11 10:00:0{n} h sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2"
        for n in range(6)
    ]
    alertas = detectar_fuerza_bruta(parsear(lineas), umbral=5, ventana_min=2)
    assert len(alertas) == 1
    assert alertas[0]["regla"] == "R001"


def test_fuerza_bruta_ignora_fallos_muy_espaciados() -> None:
    # 6 fallos pero separados por horas: no es una ráfaga, no debe disparar.
    lineas = [
        f"May 11 1{n}:00:00 h sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2"
        for n in range(6)
    ]
    alertas = detectar_fuerza_bruta(parsear(lineas), umbral=5, ventana_min=2)
    assert alertas == []


# --- R002 password spraying -------------------------------------------------

def test_spraying_muchos_usuarios_pocos_intentos() -> None:
    lineas = [
        f"May 11 10:00:0{n} h sshd[1]: Failed password for user{n} from 8.8.8.8 port 22 ssh2"
        for n in range(6)
    ]
    alertas = detectar_spraying(parsear(lineas), min_usuarios=5, max_por_usuario=3)
    assert len(alertas) == 1
    assert alertas[0]["regla"] == "R002"


# --- R003 enumeración de usuarios -------------------------------------------

def test_enumeracion_usuarios_invalidos() -> None:
    lineas = [
        f"May 11 10:00:0{n} h sshd[1]: Failed password for invalid user x{n} from 7.7.7.7 port 22 ssh2"
        for n in range(4)
    ]
    alertas = detectar_enumeracion(parsear(lineas), umbral=3)
    assert len(alertas) == 1
    assert alertas[0]["regla"] == "R003"


# --- R004 posible compromiso ------------------------------------------------

def test_compromiso_exito_tras_fallos() -> None:
    lineas = [
        "May 11 10:00:01 h sshd[1]: Failed password for cata from 6.6.6.6 port 22 ssh2",
        "May 11 10:00:02 h sshd[1]: Failed password for cata from 6.6.6.6 port 22 ssh2",
        "May 11 10:00:03 h sshd[1]: Failed password for cata from 6.6.6.6 port 22 ssh2",
        "May 11 10:00:09 h sshd[1]: Accepted password for cata from 6.6.6.6 port 22 ssh2",
    ]
    alertas = detectar_compromiso(parsear(lineas), min_fallos_previos=3)
    assert len(alertas) == 1
    assert alertas[0]["regla"] == "R004"
    assert alertas[0]["severidad"] == "crítica"


# --- Orquestador + watchlist ------------------------------------------------

def test_analizar_ordena_por_severidad_y_aplica_watchlist() -> None:
    lineas = [
        "May 11 10:00:01 h sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2",
        "May 11 10:00:02 h sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2",
        "May 11 10:00:03 h sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2",
        "May 11 10:00:04 h sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2",
        "May 11 10:00:05 h sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2",
    ]
    alertas = analizar(lineas, umbral=5, ventana_min=2, watchlist={"9.9.9.9"})
    assert alertas
    assert alertas[0]["severidad"] == "crítica"
    assert alertas[0].get("en_watchlist") is True


def test_analizar_archivo_de_ejemplo_dispara_alertas() -> None:
    ruta = os.path.join(os.path.dirname(__file__), "sample_auth.log")
    alertas = analizar_archivo(ruta, umbral=5, ventana_min=5)
    # El log de ejemplo está armado para disparar varias reglas distintas.
    assert len(_reglas(alertas)) >= 3
