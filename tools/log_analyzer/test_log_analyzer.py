"""Tests del analizador de logs (detecciones estilo SIEM)."""

import os
import types

from log_analyzer import (
    _MAX_LINEA,
    _alcance_ip,
    _codigo_salida,
    _iter_eventos,
    analizar,
    analizar_archivo,
    detectar_compromiso,
    detectar_enumeracion,
    detectar_fuerza_bruta,
    detectar_spraying,
    exportar_sigma,
    parsear,
)


def _fallos(ip: str, n: int) -> list[str]:
    return [f"May 11 10:00:{k:02d} h sshd[1]: Failed password for root from {ip} port 22 ssh2"
            for k in range(n)]


def _reglas(alertas: list[dict]) -> set[str]:
    return {a["regla"] for a in alertas}


# --- Parseo -----------------------------------------------------------------

def test_parsear_acepta_29_de_febrero() -> None:
    # Una línea legítima de un año bisiesto no debe romper el parseo.
    linea = "Feb 29 10:00:01 h sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    eventos = parsear([linea])
    assert len(eventos) == 1
    assert eventos[0].ts.month == 2 and eventos[0].ts.day == 29


def test_parsear_sanitiza_caracteres_de_control_en_usuario() -> None:
    # Usuario con secuencia de escape: no debe propagarse a la salida.
    linea = "May 11 10:00:01 h sshd[1]: Accepted password for ro\x1b[2Jot from 1.2.3.4 port 22 ssh2"
    ev = parsear([linea])
    assert ev and "\x1b" not in ev[0].usuario


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


# --- Cobertura de parsing (LOG-001/002/003) ---------------------------------

def test_message_repeated_se_expande_en_n_eventos() -> None:
    # rsyslog colapsa fallos idénticos: deben contar como N, no como 1.
    linea = "May 11 10:00:01 h sshd[1]: message repeated 5 times: [ Failed password for root from 9.9.9.9 port 22 ssh2]"
    eventos = parsear([linea])
    assert len(eventos) == 5
    alertas = detectar_fuerza_bruta(eventos, umbral=5, ventana_min=2)
    assert len(alertas) == 1  # la ráfaga ya no evade el umbral


def test_publickey_fallo_y_exito_se_reconocen() -> None:
    eventos = parsear([
        "May 11 10:00:01 h sshd[1]: Failed publickey for root from 1.2.3.4 port 22 ssh2",
        "May 11 10:00:02 h sshd[2]: Accepted publickey for cata from 5.6.7.8 port 22 ssh2",
    ])
    assert len(eventos) == 2
    assert eventos[0].exito is False
    assert eventos[1].exito is True


def test_compromiso_detecta_login_exitoso_por_clave() -> None:
    # R004 no debe ser ciego a un login por publickey tras fallos.
    lineas = [
        "May 11 10:00:01 h sshd[1]: Failed password for cata from 6.6.6.6 port 22 ssh2",
        "May 11 10:00:02 h sshd[1]: Failed password for cata from 6.6.6.6 port 22 ssh2",
        "May 11 10:00:03 h sshd[1]: Failed password for cata from 6.6.6.6 port 22 ssh2",
        "May 11 10:00:09 h sshd[1]: Accepted publickey for cata from 6.6.6.6 port 22 ssh2",
    ]
    alertas = detectar_compromiso(parsear(lineas), min_fallos_previos=3)
    assert len(alertas) == 1 and alertas[0]["regla"] == "R004"


def test_ipv6_se_parsea_y_normaliza() -> None:
    linea = "May 11 10:00:01 h sshd[1]: Failed password for root from 2001:DB8::1 port 22 ssh2"
    ev = parsear([linea])
    assert len(ev) == 1
    assert ev[0].ip == "2001:db8::1"  # normalizada por ipaddress


def test_ip_invalida_se_descarta() -> None:
    linea = "May 11 10:00:01 h sshd[1]: Failed password for root from 999.999.999.999 port 22 ssh2"
    assert parsear([linea]) == []


def test_fecha_imposible_no_crashea() -> None:
    linea = "Feb 30 10:00:01 h sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    assert parsear([linea]) == []  # se descarta sin abortar


def test_message_repeated_respeta_cota_anti_dos() -> None:
    from log_analyzer import _MAX_REPETICIONES
    linea = "May 11 10:00:01 h sshd[1]: message repeated 999999999 times: [ Failed password for root from 9.9.9.9 port 22 ssh2]"
    assert len(parsear([linea])) == _MAX_REPETICIONES


# --- LOG-004 streaming ------------------------------------------------------

def test_iter_eventos_es_perezoso() -> None:
    # No debe materializar la lista: es un generador (procesamiento en streaming).
    assert isinstance(_iter_eventos([]), types.GeneratorType)


# --- LOG-005 R004 sin falsos positivos --------------------------------------

def test_compromiso_no_alerta_si_entra_otro_usuario_nat() -> None:
    # Detrás de un NAT: 'ana' falla, 'beto' entra. NO debe ser un compromiso.
    lineas = [
        "May 11 10:00:01 h sshd[1]: Failed password for ana from 7.7.7.7 port 22 ssh2",
        "May 11 10:00:02 h sshd[1]: Failed password for ana from 7.7.7.7 port 22 ssh2",
        "May 11 10:00:03 h sshd[1]: Failed password for ana from 7.7.7.7 port 22 ssh2",
        "May 11 10:00:05 h sshd[1]: Accepted password for beto from 7.7.7.7 port 22 ssh2",
    ]
    assert detectar_compromiso(parsear(lineas)) == []


def test_compromiso_no_realerta_tras_reset() -> None:
    # Tras el primer éxito el contador se resetea: un segundo éxito no re-alerta.
    lineas = [
        "May 11 10:00:01 h sshd[1]: Failed password for cata from 6.6.6.6 port 22 ssh2",
        "May 11 10:00:02 h sshd[1]: Failed password for cata from 6.6.6.6 port 22 ssh2",
        "May 11 10:00:03 h sshd[1]: Failed password for cata from 6.6.6.6 port 22 ssh2",
        "May 11 10:00:04 h sshd[1]: Accepted password for cata from 6.6.6.6 port 22 ssh2",
        "May 11 10:00:30 h sshd[1]: Accepted password for cata from 6.6.6.6 port 22 ssh2",
    ]
    assert len(detectar_compromiso(parsear(lineas))) == 1


def test_compromiso_respeta_ventana() -> None:
    # Fallos muy anteriores al éxito (fuera de ventana) no deben disparar R004.
    lineas = [
        "May 11 08:00:01 h sshd[1]: Failed password for cata from 6.6.6.6 port 22 ssh2",
        "May 11 08:00:02 h sshd[1]: Failed password for cata from 6.6.6.6 port 22 ssh2",
        "May 11 08:00:03 h sshd[1]: Failed password for cata from 6.6.6.6 port 22 ssh2",
        "May 11 10:00:00 h sshd[1]: Accepted password for cata from 6.6.6.6 port 22 ssh2",
    ]
    assert detectar_compromiso(parsear(lineas), ventana_min=60) == []


# --- LOG-006 timestamps (ISO 8601 y rollover de año) ------------------------

def test_parsea_timestamp_iso8601_con_ipv6() -> None:
    linea = "2024-05-11T10:00:01.123+00:00 h sshd[1]: Failed password for root from 2001:db8::5 port 22 ssh2"
    ev = parsear([linea])
    assert len(ev) == 1
    assert ev[0].ts.year == 2024 and ev[0].ip == "2001:db8::5"


def test_rollover_de_anio_en_formato_bsd() -> None:
    lineas = [
        "Dec 31 23:59:59 h sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2",
        "Jan 01 00:00:30 h sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2",
    ]
    ev = parsear(lineas)
    assert ev[1].ts.year == ev[0].ts.year + 1  # Ene quedó en el año siguiente


# --- LOG-007 exit codes / LOG-008 cap de línea ------------------------------

def test_codigo_salida_segun_severidad() -> None:
    assert _codigo_salida([]) == 0
    assert _codigo_salida([{"severidad": "media"}]) == 0
    assert _codigo_salida([{"severidad": "alta"}]) == 1
    assert _codigo_salida([{"severidad": "crítica"}]) == 1


def test_linea_gigante_se_descarta() -> None:
    relleno = "A" * (_MAX_LINEA + 1)
    linea = f"May 11 10:00:01 h sshd[1]: {relleno} Failed password for root from 1.2.3.4 port 22 ssh2"
    assert parsear([linea]) == []  # no se procesa la línea patológica


# --- MITRE ATT&CK, severidad dinámica, allowlist, enriquecimiento, Sigma -----

def test_alerta_lleva_tecnica_attack() -> None:
    al = detectar_fuerza_bruta(parsear(_fallos("9.9.9.9", 6)))
    assert al[0]["tecnica"] == "T1110.001"
    assert "Password Guessing" in al[0]["tecnica_nombre"]


def test_severidad_escala_por_volumen() -> None:
    al = detectar_fuerza_bruta(parsear(_fallos("9.9.9.9", 55)))
    severidades = {a["severidad"] for a in al}
    assert "alta" in severidades and "crítica" in severidades


def test_allowlist_suprime_eventos() -> None:
    assert analizar(_fallos("9.9.9.9", 6), allowlist={"9.9.9.9"}) == []


def test_enriquecimiento_alcance_de_ip() -> None:
    assert _alcance_ip("127.0.0.1") == "loopback"
    assert _alcance_ip("10.0.0.1") == "privada"
    assert _alcance_ip("8.8.8.8") == "pública"


def test_alerta_se_enriquece_con_contexto_de_red() -> None:
    al = analizar(_fallos("8.8.8.8", 6))
    assert al[0]["red"]["alcance"] == "pública"


def test_geodb_externa_agrega_pais_y_asn(tmp_path) -> None:
    db = tmp_path / "geo.csv"
    db.write_text("9.9.9.0/24,US,AS999\n")
    al = analizar(_fallos("9.9.9.9", 6), geodb=str(db))
    assert al[0]["red"].get("pais") == "US"
    assert al[0]["red"].get("asn") == "AS999"


def test_exportar_sigma_incluye_tags_attack() -> None:
    yaml = exportar_sigma()
    for tag in ("attack.t1110.001", "attack.t1110.003", "attack.t1087", "attack.t1078"):
        assert tag in yaml
    assert yaml.count("title:") == 4
    assert "logsource:" in yaml and "level:" in yaml


def test_exportar_sigma_es_determinista() -> None:
    assert exportar_sigma() == exportar_sigma()  # uuids estables (uuid5)


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
