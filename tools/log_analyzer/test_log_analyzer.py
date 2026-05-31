"""Tests del analizador de logs."""

import os

from log_analyzer import analizar_archivo, contar_fallos, detectar_fuerza_bruta

LINEAS = [
    "Failed password for invalid user admin from 192.168.0.5 port 22 ssh2",
    "Failed password for root from 192.168.0.5 port 22 ssh2",
    "Failed password for root from 192.168.0.5 port 22 ssh2",
    "Accepted password for cata from 10.0.0.20 port 51000 ssh2",
    "Failed password for invalid user pi from 203.0.113.9 port 40222 ssh2",
]


def test_contar_fallos_agrupa_por_ip() -> None:
    conteo = contar_fallos(LINEAS)
    assert conteo["192.168.0.5"] == 3
    assert conteo["203.0.113.9"] == 1
    assert "10.0.0.20" not in conteo  # el login exitoso no se cuenta


def test_detectar_fuerza_bruta_respeta_umbral() -> None:
    conteo = {"192.168.0.5": 3, "203.0.113.9": 1}
    assert detectar_fuerza_bruta(conteo, umbral=3) == [("192.168.0.5", 3)]
    assert detectar_fuerza_bruta(conteo, umbral=5) == []


def test_detectar_ordena_de_mayor_a_menor() -> None:
    conteo = {"a": 2, "b": 9, "c": 5}
    resultado = detectar_fuerza_bruta(conteo, umbral=1)
    assert [ip for ip, _ in resultado] == ["b", "c", "a"]


def test_analizar_archivo_de_ejemplo() -> None:
    ruta = os.path.join(os.path.dirname(__file__), "sample_auth.log")
    sospechosas = analizar_archivo(ruta, umbral=5)
    # 192.168.0.5 acumula 6 fallos en el log de ejemplo
    assert ("192.168.0.5", 6) in sospechosas
