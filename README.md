# Python Security Toolkit

![tests](https://github.com/catalinacarlen/python-security-toolkit/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.8%2B-blue)
![deps](https://img.shields.io/badge/dependencies-stdlib%20only-green)
![lint](https://img.shields.io/badge/lint-ruff-blue)
![types](https://img.shields.io/badge/types-mypy-blue)
![coverage](https://img.shields.io/badge/coverage-72%25-green)

A small collection of **security-focused command-line tools written in pure Python** (standard library only), each with its own documentation and automated tests. Built while studying Cybersecurity at Universidad de Palermo, applying core programming concepts to practical security tasks.

> ⚠️ For educational use and authorized environments only.

---

## Tools

| Tool | What it does | Security concept |
|------|--------------|------------------|
| [**port_scanner**](tools/port_scanner) | Concurrent TCP scanner with banner grabbing & service fingerprinting | Reconnaissance / asset discovery |
| [**log_analyzer**](tools/log_analyzer) | SIEM-style rules over `auth.log`: brute force, spraying, enumeration, compromise | Log analysis / detection engineering |
| [**password_toolkit**](tools/password_toolkit) | Entropy-based strength, crack-time, HIBP breach check (k-anonymity), PBKDF2 | Authentication / cryptography |
| [**file_integrity**](tools/file_integrity) | FIM with permission tracking, HMAC-signed baseline & watch mode | Integrity monitoring |
| [**sqli_lab**](tools/sqli_lab) | Multiple SQLi families (UNION/blind/time) + payload classifier | Secure development / OWASP |

Each tool folder contains the code, a focused `README.md`, and a `test_*.py` test suite.

## Install

```bash
git clone https://github.com/catalinacarlen/python-security-toolkit
cd python-security-toolkit
pip install -e .          # installs the unified `pstk` command (stdlib only)
```

## Quick start

Everything is reachable through a single command — `pstk <tool>`:

```bash
pstk scan 127.0.0.1                              # port scan + banner grabbing
pstk logs tools/log_analyzer/sample_auth.log     # SIEM-style detections
pstk pwd auditar --offline "Abc123!"             # password audit (entropy, crack-time)
pstk fim baseline ./my_dir -k "secret-key"       # signed integrity baseline
pstk sqli --demo                                 # SQL injection lab
pstk <tool> --help                               # options for each tool
```

Each tool is also runnable as a standalone script (e.g. `python3 tools/port_scanner/port_scanner.py 127.0.0.1`).

## Quality & tests

```bash
pip install -e ".[dev]"     # pytest, ruff, mypy, coverage
ruff check .                # lint
mypy pstk tools             # type check
coverage run --source=tools,pstk -m pytest tools tests && coverage report
```

Lint, type check and tests run automatically on every push via GitHub Actions (see the badges above).

## Documentation

The [`docs/`](docs) folder contains the theory behind the code, organized as a reference:

1. [Fundamentos de Python](docs/01-fundamentos-python.md)
2. [Estructuras de control](docs/02-estructuras-control.md)
3. [Funciones](docs/03-funciones.md)
4. [Arreglos (listas)](docs/04-arreglos.md)
5. [Pensar un algoritmo](docs/05-algoritmos.md)

## Project structure

```
python-security-toolkit/
├── pstk/             # unified `pstk` CLI that dispatches to each tool
├── tools/            # 5 security tools, each with code + README + tests
├── tests/            # tests for the unified CLI
├── docs/             # programming theory as reference
├── .github/workflows # CI: ruff + mypy + pytest/coverage on every push
└── pyproject.toml    # packaging, entry point and tooling config (stdlib only)
```

---
---

# Python Security Toolkit (ES)

Una colección de **herramientas de línea de comandos orientadas a la seguridad, escritas en Python puro** (solo librería estándar), cada una con su documentación y tests automáticos. Desarrollado mientras estudio Ciberseguridad en la Universidad de Palermo, aplicando los conceptos base de programación a tareas prácticas de seguridad.

> ⚠️ Solo para uso educativo y entornos autorizados.

## Herramientas

| Herramienta | Qué hace | Concepto de seguridad |
|-------------|----------|------------------------|
| [**port_scanner**](tools/port_scanner) | Escáner TCP concurrente con banner grabbing y fingerprinting de servicio | Reconocimiento / descubrimiento de activos |
| [**log_analyzer**](tools/log_analyzer) | Reglas estilo SIEM sobre `auth.log`: fuerza bruta, spraying, enumeración, compromiso | Análisis de logs / detección |
| [**password_toolkit**](tools/password_toolkit) | Fortaleza por entropía, tiempo de crackeo, chequeo HIBP (k-anonymity), PBKDF2 | Autenticación / criptografía |
| [**file_integrity**](tools/file_integrity) | FIM con control de permisos, baseline firmado (HMAC) y modo watch | Monitoreo de integridad |
| [**sqli_lab**](tools/sqli_lab) | Varias familias de SQLi (UNION/blind/time) + clasificador de payloads | Desarrollo seguro / OWASP |

Cada carpeta contiene el código, un `README.md` propio y una batería de tests `test_*.py`.

## Instalación

```bash
git clone https://github.com/catalinacarlen/python-security-toolkit
cd python-security-toolkit
pip install -e .          # instala el comando unificado `pstk` (solo stdlib)
```

## Uso rápido

Todo se accede desde un único comando — `pstk <herramienta>`:

```bash
pstk scan 127.0.0.1                              # escaneo de puertos + banner grabbing
pstk logs tools/log_analyzer/sample_auth.log     # detecciones estilo SIEM
pstk pwd auditar --offline "Abc123!"             # auditoría de contraseña (entropía, crack-time)
pstk fim baseline ./mi_dir -k "clave-secreta"    # baseline de integridad firmado
pstk sqli --demo                                 # laboratorio de SQL injection
pstk <herramienta> --help                        # opciones de cada herramienta
```

Cada herramienta también se puede correr como script suelto (ej. `python3 tools/port_scanner/port_scanner.py 127.0.0.1`).

## Calidad y tests

```bash
pip install -e ".[dev]"     # pytest, ruff, mypy, coverage
ruff check .                # lint
mypy pstk tools             # chequeo de tipos
coverage run --source=tools,pstk -m pytest tools tests && coverage report
```

El lint, el chequeo de tipos y los tests corren automáticamente en cada push mediante GitHub Actions (ver los badges de arriba).

## Documentación

La carpeta [`docs/`](docs) contiene la teoría detrás del código, organizada como referencia: fundamentos de Python, estructuras de control, funciones, arreglos y diseño de algoritmos.

---

Hecho por [Catalina Carlen](https://github.com/catalinacarlen) — Universidad de Palermo, Ciberseguridad
