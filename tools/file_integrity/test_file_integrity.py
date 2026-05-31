"""Tests del verificador de integridad."""

from file_integrity import comparar, generar_manifiesto, hash_archivo


def test_hash_cambia_si_cambia_el_contenido(tmp_path) -> None:
    archivo = tmp_path / "dato.txt"
    archivo.write_text("hola")
    h1 = hash_archivo(str(archivo))
    archivo.write_text("hola mundo")
    h2 = hash_archivo(str(archivo))
    assert h1 != h2
    assert len(h1) == 64  # SHA-256 en hex


def test_manifiesto_lista_todos_los_archivos(tmp_path) -> None:
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    manifiesto = generar_manifiesto(str(tmp_path))
    assert set(manifiesto) == {"a.txt", "b.txt"}


def test_comparar_detecta_los_tres_tipos_de_cambio() -> None:
    base = {"igual.txt": "h1", "mod.txt": "h2", "borrado.txt": "h3"}
    actual = {"igual.txt": "h1", "mod.txt": "DISTINTO", "nuevo.txt": "h4"}
    cambios = comparar(base, actual)
    assert cambios["modificados"] == ["mod.txt"]
    assert cambios["nuevos"] == ["nuevo.txt"]
    assert cambios["eliminados"] == ["borrado.txt"]


def test_comparar_sin_cambios_da_listas_vacias() -> None:
    base = {"a.txt": "h"}
    cambios = comparar(base, dict(base))
    assert cambios == {"modificados": [], "nuevos": [], "eliminados": []}
