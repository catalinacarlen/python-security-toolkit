"""Tests del escáner de puertos.

Abrimos un socket de escucha en un puerto efímero del propio equipo para tener
un puerto realmente abierto que comprobar, sin depender de servicios externos.
"""

import socket

from port_scanner import describir, scan_port, scan_range


def _abrir_puerto_de_escucha() -> tuple[socket.socket, int]:
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.bind(("127.0.0.1", 0))  # 0 = el SO asigna un puerto libre
    servidor.listen(1)
    return servidor, servidor.getsockname()[1]


def test_scan_port_detecta_puerto_abierto() -> None:
    servidor, puerto = _abrir_puerto_de_escucha()
    try:
        assert scan_port("127.0.0.1", puerto) is True
    finally:
        servidor.close()


def test_scan_port_puerto_cerrado() -> None:
    servidor, puerto = _abrir_puerto_de_escucha()
    servidor.close()  # lo cerramos: el puerto ya no acepta conexiones
    assert scan_port("127.0.0.1", puerto, timeout=0.2) is False


def test_scan_range_incluye_el_puerto_abierto() -> None:
    servidor, puerto = _abrir_puerto_de_escucha()
    try:
        abiertos = scan_range("127.0.0.1", puerto, puerto, timeout=0.2)
        assert abiertos == [puerto]
    finally:
        servidor.close()


def test_describir_servicios_conocidos_y_desconocidos() -> None:
    assert describir(443) == "HTTPS"
    assert describir(22) == "SSH"
    assert describir(49999) == "desconocido"
