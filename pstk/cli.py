"""CLI unificado del toolkit: `pstk <herramienta> [args...]`.

En vez de correr cinco scripts sueltos, `pstk` expone un único punto de entrada
que despacha hacia cada herramienta. No duplica la lógica de argumentos: carga el
módulo de la herramienta y delega en su `main()`, así cada subcomando conserva
exactamente sus mismas opciones (incluido `--help`).

    pstk scan 127.0.0.1 --json
    pstk pwd auditar --offline "Abc123!"
    pstk logs tools/log_analyzer/sample_auth.log --json
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

__version__ = "0.5.0"

REPO_ROOT = Path(__file__).resolve().parent.parent

# subcomando -> (módulo, archivo, descripción corta)
HERRAMIENTAS: dict[str, tuple[str, str]] = {
    "scan": ("port_scanner", "Escáner de puertos TCP con banner grabbing"),
    "logs": ("log_analyzer", "Detección estilo SIEM sobre logs de autenticación"),
    "pwd": ("password_toolkit", "Auditoría de contraseñas (entropía, HIBP, hashing)"),
    "fim": ("file_integrity", "Monitor de integridad de archivos (FIM)"),
    "sqli": ("sqli_lab", "Demostración local de SQL injection"),
}


def _cargar(nombre: str) -> ModuleType:
    """Carga el módulo de una herramienta desde tools/<nombre>/<nombre>.py."""
    ruta = REPO_ROOT / "tools" / nombre / f"{nombre}.py"
    spec = importlib.util.spec_from_file_location(nombre, ruta)
    if spec is None or spec.loader is None:
        raise ImportError(f"No se pudo cargar la herramienta '{nombre}' desde {ruta}")
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def _ayuda() -> str:
    lineas = ["python-security-toolkit (pstk)\n", "Uso: pstk <herramienta> [opciones]\n", "Herramientas:"]
    ancho = max(len(c) for c in HERRAMIENTAS)
    for cmd, (_modulo, desc) in HERRAMIENTAS.items():
        lineas.append(f"  {cmd:<{ancho}}  {desc}")
    lineas.append("\nUsá 'pstk <herramienta> --help' para ver las opciones de cada una.")
    return "\n".join(lineas)


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)

    if not argv or argv[0] in ("-h", "--help", "help"):
        print(_ayuda())
        return
    if argv[0] in ("-V", "--version"):
        print(f"pstk {__version__}")
        return

    comando = argv[0]
    if comando not in HERRAMIENTAS:
        print(f"Herramienta desconocida: {comando!r}\n", file=sys.stderr)
        print(_ayuda(), file=sys.stderr)
        raise SystemExit(2)

    modulo_nombre = HERRAMIENTAS[comando][0]
    modulo = _cargar(modulo_nombre)
    # Reescribimos argv para que la herramienta vea su propio prog y sus args.
    sys.argv = [f"pstk {comando}", *argv[1:]]
    modulo.main()


if __name__ == "__main__":
    main()
