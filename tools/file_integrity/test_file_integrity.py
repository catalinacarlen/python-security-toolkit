"""Tests del verificador de integridad."""


import pytest
from file_integrity import (
    cargar_manifiesto,
    comparar,
    firmar,
    generar_manifiesto,
    guardar_manifiesto,
    hash_archivo,
    verificar_firma,
)


def test_hash_cambia_si_cambia_el_contenido(tmp_path) -> None:
    archivo = tmp_path / "dato.txt"
    archivo.write_text("hola")
    h1 = hash_archivo(str(archivo))
    archivo.write_text("hola mundo")
    h2 = hash_archivo(str(archivo))
    assert h1 != h2
    assert len(h1) == 64  # SHA-256 en hex


def test_manifiesto_lista_archivos_con_hash_y_modo(tmp_path) -> None:
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    manifiesto = generar_manifiesto(str(tmp_path))
    assert set(manifiesto) == {"a.txt", "b.txt"}
    assert "hash" in manifiesto["a.txt"] and "modo" in manifiesto["a.txt"]


def test_comparar_detecta_los_tipos_de_cambio() -> None:
    base = {
        "igual.txt": {"hash": "h1", "modo": "0o644"},
        "mod.txt": {"hash": "h2", "modo": "0o644"},
        "borrado.txt": {"hash": "h3", "modo": "0o644"},
    }
    actual = {
        "igual.txt": {"hash": "h1", "modo": "0o644"},
        "mod.txt": {"hash": "DISTINTO", "modo": "0o644"},
        "nuevo.txt": {"hash": "h4", "modo": "0o644"},
    }
    cambios = comparar(base, actual)
    assert cambios["modificados"] == ["mod.txt"]
    assert cambios["nuevos"] == ["nuevo.txt"]
    assert cambios["eliminados"] == ["borrado.txt"]


def test_comparar_detecta_cambio_de_permisos() -> None:
    base = {"app.conf": {"hash": "h", "modo": "0o644"}}
    actual = {"app.conf": {"hash": "h", "modo": "0o777"}}  # mismo contenido, otros permisos
    cambios = comparar(base, actual)
    assert cambios["permisos"] == ["app.conf"]
    assert cambios["modificados"] == []


def test_baseline_firmado_se_verifica(tmp_path) -> None:
    (tmp_path / "a.txt").write_text("a")
    manifiesto = generar_manifiesto(str(tmp_path))
    firma = firmar(manifiesto, "clave-secreta")
    assert verificar_firma(manifiesto, firma, "clave-secreta") is True
    assert verificar_firma(manifiesto, firma, "clave-incorrecta") is False


def test_cargar_baseline_manipulado_lanza_error(tmp_path) -> None:
    (tmp_path / "a.txt").write_text("a")
    base_file = tmp_path / "baseline.json"
    guardar_manifiesto(generar_manifiesto(str(tmp_path)), str(base_file), clave="k")

    # Un atacante edita el baseline para ocultar un cambio.
    import json
    datos = json.loads(base_file.read_text())
    datos["manifiesto"]["a.txt"]["hash"] = "0" * 64
    base_file.write_text(json.dumps(datos))

    with pytest.raises(ValueError):
        cargar_manifiesto(str(base_file), clave="k")


def test_cargar_baseline_firmado_sin_clave_advierte(tmp_path, capsys) -> None:
    (tmp_path / "a.txt").write_text("a")
    base_file = tmp_path / "baseline.json"
    guardar_manifiesto(generar_manifiesto(str(tmp_path)), str(base_file), clave="k")
    # Cargar sin clave NO debe verificar la firma en silencio: tiene que avisar.
    cargar_manifiesto(str(base_file))  # sin clave
    assert "NO se verificó" in capsys.readouterr().err


def test_symlink_no_se_sigue_y_se_registra_por_destino(tmp_path) -> None:
    import os
    (tmp_path / "real.txt").write_text("contenido")
    enlace = tmp_path / "enlace"
    os.symlink("real.txt", enlace)
    manifiesto = generar_manifiesto(str(tmp_path))
    assert manifiesto["enlace"] == {"tipo": "symlink", "destino": "real.txt"}
    assert "hash" not in manifiesto["enlace"]  # no se hasheó el destino


def test_cambio_de_destino_de_symlink_se_detecta() -> None:
    base = {"e": {"tipo": "symlink", "destino": "a.txt"}}
    actual = {"e": {"tipo": "symlink", "destino": "/etc/passwd"}}
    assert comparar(base, actual)["modificados"] == ["e"]


def test_archivo_reemplazado_por_symlink_se_detecta() -> None:
    base = {"e": {"hash": "h", "modo": "0o644"}}
    actual = {"e": {"tipo": "symlink", "destino": "x"}}
    assert comparar(base, actual)["modificados"] == ["e"]


def test_ciclo_completo_baseline_y_check(tmp_path) -> None:
    datos = tmp_path / "datos"          # directorio vigilado
    datos.mkdir()
    base_file = tmp_path / "baseline.json"  # baseline FUERA del directorio vigilado
    (datos / "a.txt").write_text("contenido")
    guardar_manifiesto(generar_manifiesto(str(datos)), str(base_file))

    (datos / "a.txt").write_text("modificado")
    (datos / "nuevo.txt").write_text("x")
    cambios = comparar(cargar_manifiesto(str(base_file)), generar_manifiesto(str(datos)))
    assert cambios["modificados"] == ["a.txt"]
    assert cambios["nuevos"] == ["nuevo.txt"]
