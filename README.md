# Python Security Toolkit

![tests](https://github.com/catalinacarlen/python-security-toolkit/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.8%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-green)
![lint](https://img.shields.io/badge/lint-ruff-blue)
![types](https://img.shields.io/badge/types-mypy-blue)
![coverage](https://img.shields.io/badge/coverage-72%25-green)
![license](https://img.shields.io/badge/license-MIT-green)

A collection of security-focused command-line tools written in pure Python (standard library only). Each tool ships with documentation and an automated test suite, and all tools are accessible through a single `pstk` command.

Intended for use in authorized environments only.

## Tools

| Tool | Description | Domain |
|------|-------------|--------|
| [port_scanner](tools/port_scanner) | Concurrent TCP port scanner with banner grabbing and service fingerprinting | Reconnaissance |
| [log_analyzer](tools/log_analyzer) | Authentication-log detection engine: brute force, password spraying, user enumeration, post-failure compromise | Log analysis |
| [password_toolkit](tools/password_toolkit) | Entropy-based strength scoring, crack-time estimation, HIBP breach check (k-anonymity), PBKDF2 hashing | Authentication |
| [file_integrity](tools/file_integrity) | File integrity monitoring with permission tracking, HMAC-signed baseline and watch mode | Integrity monitoring |
| [sqli_lab](tools/sqli_lab) | SQL injection demonstration (UNION, blind, time-based) with a payload classifier | Application security |

## Requirements

- Python 3.8 or newer
- No runtime dependencies (standard library only)

## Installation

```bash
git clone https://github.com/catalinacarlen/python-security-toolkit
cd python-security-toolkit
pip install -e .
```

This installs the unified `pstk` command. A virtual environment is recommended:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

All tools are available as subcommands of `pstk`:

```bash
pstk scan 127.0.0.1                              # port scan with banner grabbing
pstk logs tools/log_analyzer/sample_auth.log     # authentication-log analysis
pstk pwd auditar --offline "example"             # password audit
pstk fim baseline ./directory -k "secret-key"    # signed integrity baseline
pstk sqli --demo                                 # SQL injection demonstration
pstk <tool> --help                               # options for a given tool
```

Each tool can also be run as a standalone script, e.g. `python3 tools/port_scanner/port_scanner.py 127.0.0.1`.

## Development

```bash
pip install -e ".[dev]"     # pytest, ruff, mypy, coverage
ruff check .                # lint
mypy pstk tools             # type check
coverage run --source=tools,pstk -m pytest tools tests && coverage report
```

Linting, type checking and the test suite run on every push via GitHub Actions.

## Project structure

```
python-security-toolkit/
├── pstk/             # unified CLI that dispatches to each tool
├── tools/            # security tools, each with code, README and tests
├── tests/            # tests for the unified CLI
├── .github/workflows # continuous integration
├── pyproject.toml    # packaging, entry point and tooling configuration
├── CHANGELOG.md      # version history
└── LICENSE           # MIT
```

## License

Released under the MIT License. See [LICENSE](LICENSE).

---
---

# Python Security Toolkit (ES)

Colección de herramientas de línea de comandos orientadas a la seguridad, escritas en Python puro (solo librería estándar). Cada herramienta incluye documentación y una batería de tests automáticos, y todas son accesibles a través de un único comando `pstk`.

Destinado exclusivamente a entornos autorizados.

## Herramientas

| Herramienta | Descripción | Dominio |
|-------------|-------------|---------|
| [port_scanner](tools/port_scanner) | Escáner de puertos TCP concurrente con banner grabbing y fingerprinting de servicio | Reconocimiento |
| [log_analyzer](tools/log_analyzer) | Motor de detección sobre logs de autenticación: fuerza bruta, password spraying, enumeración de usuarios, compromiso tras fallos | Análisis de logs |
| [password_toolkit](tools/password_toolkit) | Fortaleza por entropía, estimación de tiempo de crackeo, verificación HIBP (k-anonymity), hashing PBKDF2 | Autenticación |
| [file_integrity](tools/file_integrity) | Monitoreo de integridad con control de permisos, baseline firmado con HMAC y modo watch | Integridad |
| [sqli_lab](tools/sqli_lab) | Demostración de inyección SQL (UNION, blind, time-based) con clasificador de payloads | Seguridad de aplicaciones |

## Requisitos

- Python 3.8 o superior
- Sin dependencias en tiempo de ejecución (solo librería estándar)

## Instalación

```bash
git clone https://github.com/catalinacarlen/python-security-toolkit
cd python-security-toolkit
pip install -e .
```

Esto instala el comando unificado `pstk`. Se recomienda un entorno virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Uso

Todas las herramientas son subcomandos de `pstk`:

```bash
pstk scan 127.0.0.1                              # escaneo de puertos con banner grabbing
pstk logs tools/log_analyzer/sample_auth.log     # análisis de logs de autenticación
pstk pwd auditar --offline "ejemplo"             # auditoría de contraseña
pstk fim baseline ./directorio -k "clave"        # baseline de integridad firmado
pstk sqli --demo                                 # demostración de inyección SQL
pstk <herramienta> --help                        # opciones de cada herramienta
```

Cada herramienta también puede ejecutarse como script independiente, p. ej. `python3 tools/port_scanner/port_scanner.py 127.0.0.1`.

## Desarrollo

```bash
pip install -e ".[dev]"     # pytest, ruff, mypy, coverage
ruff check .                # lint
mypy pstk tools             # chequeo de tipos
coverage run --source=tools,pstk -m pytest tools tests && coverage report
```

El lint, el chequeo de tipos y los tests se ejecutan en cada push mediante GitHub Actions.

## Estructura del proyecto

```
python-security-toolkit/
├── pstk/             # CLI unificado que despacha a cada herramienta
├── tools/            # herramientas, cada una con código, README y tests
├── tests/            # tests del CLI unificado
├── .github/workflows # integración continua
├── pyproject.toml    # empaquetado, entry point y configuración de tooling
├── CHANGELOG.md      # historial de versiones
└── LICENSE           # MIT
```

## Licencia

Distribuido bajo la Licencia MIT. Ver [LICENSE](LICENSE).
