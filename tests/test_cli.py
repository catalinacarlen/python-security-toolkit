"""Tests del CLI unificado `pstk` (el dispatcher que delega en cada herramienta)."""

import pytest

import pstk.cli as cli


def test_ayuda_lista_todas_las_herramientas(capsys) -> None:
    cli.main([])
    salida = capsys.readouterr().out
    for cmd in ("scan", "logs", "pwd", "fim", "sqli"):
        assert cmd in salida


def test_version(capsys) -> None:
    cli.main(["--version"])
    assert "pstk" in capsys.readouterr().out


def test_herramienta_desconocida_sale_con_error() -> None:
    with pytest.raises(SystemExit):
        cli.main(["inexistente"])


def test_despacha_a_sqli(capsys) -> None:
    cli.main(["sqli", "--clasificar", "x' UNION SELECT a FROM t --"])
    assert capsys.readouterr().out.strip() == "union"


def test_despacha_a_pwd_offline(capsys) -> None:
    cli.main(["pwd", "--json", "auditar", "--offline", "Abc123!"])
    salida = capsys.readouterr().out
    assert "entropia_bits" in salida


def test_despacha_a_logs_con_sample(capsys) -> None:
    ruta = cli.REPO_ROOT / "tools" / "log_analyzer" / "sample_auth.log"
    # logs sale con código 1 cuando hay alertas de severidad alta/crítica.
    with pytest.raises(SystemExit) as exc:
        cli.main(["logs", str(ruta), "--json"])
    assert exc.value.code == 1
    salida = capsys.readouterr().out
    assert "R001" in salida or "R004" in salida
