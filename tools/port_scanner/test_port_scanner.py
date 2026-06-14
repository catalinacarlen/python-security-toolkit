"""Tests del escáner de puertos.

Levantamos sockets de escucha reales en puertos efímeros del propio equipo, así
probamos contra puertos verdaderamente abiertos sin depender de servicios externos.
"""

import socket
import threading

from port_scanner import (
    agarrar_banner,
    describir,
    escanear,
    identificar_servicio,
    scan_port,
    scan_range,
)


def _abrir_puerto_de_escucha() -> tuple[socket.socket, int]:
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.bind(("127.0.0.1", 0))  # 0 = el SO asigna un puerto libre
    servidor.listen(1)
    return servidor, servidor.getsockname()[1]


def _servidor_con_banner(banner: bytes) -> tuple[socket.socket, int]:
    """Servidor que atiende varias conexiones y a cada una le envía un banner.

    Acepta en bucle porque `escanear()` se conecta primero para detectar el puerto
    abierto y luego otra vez para leer el banner: hacen falta varios accept().
    """
    servidor, puerto = _abrir_puerto_de_escucha()

    def _atender() -> None:
        while True:
            try:
                cliente, _ = servidor.accept()
            except OSError:
                return  # servidor cerrado
            try:
                cliente.sendall(banner)
            except OSError:
                pass
            finally:
                cliente.close()

    threading.Thread(target=_atender, daemon=True).start()
    return servidor, puerto


# --- detección básica de puertos -------------------------------------------

def test_scan_port_detecta_puerto_abierto() -> None:
    servidor, puerto = _abrir_puerto_de_escucha()
    try:
        assert scan_port("127.0.0.1", puerto) is True
    finally:
        servidor.close()


def test_scan_port_puerto_cerrado() -> None:
    servidor, puerto = _abrir_puerto_de_escucha()
    servidor.close()
    assert scan_port("127.0.0.1", puerto, timeout=0.2) is False


def test_scan_range_incluye_el_puerto_abierto() -> None:
    servidor, puerto = _abrir_puerto_de_escucha()
    try:
        assert scan_range("127.0.0.1", puerto, puerto, timeout=0.2) == [puerto]
    finally:
        servidor.close()


# --- banner grabbing y servicio --------------------------------------------

def test_agarrar_banner_lee_el_saludo_del_servicio() -> None:
    servidor, puerto = _servidor_con_banner(b"SSH-2.0-OpenSSH_9.6\r\n")
    try:
        banner = agarrar_banner("127.0.0.1", puerto, timeout=1.0)
        assert "SSH-2.0-OpenSSH" in banner
    finally:
        servidor.close()


def test_identificar_servicio_por_banner_supera_al_puerto() -> None:
    # Un banner SSH en un puerto "raro" debe identificarse como SSH igual.
    assert identificar_servicio(40000, "SSH-2.0-OpenSSH_9.6") == "SSH"


def test_identificar_servicio_cae_al_puerto_conocido_sin_banner() -> None:
    assert identificar_servicio(443, "") == "HTTPS"
    assert identificar_servicio(49999, "") == "desconocido"


def test_escanear_devuelve_estructura_con_servicio() -> None:
    servidor, puerto = _servidor_con_banner(b"SSH-2.0-OpenSSH_9.6\r\n")
    try:
        resultado = escanear("127.0.0.1", puerto, puerto, timeout=0.5, con_banner=True)
        assert len(resultado) == 1
        assert resultado[0]["puerto"] == puerto
        assert resultado[0]["servicio"] == "SSH"
    finally:
        servidor.close()


def test_describir_servicios_conocidos_y_desconocidos() -> None:
    assert describir(443) == "HTTPS"
    assert describir(22) == "SSH"
    assert describir(49999) == "desconocido"
