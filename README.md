# Python Security Toolkit

![tests](https://github.com/catalinacarlen/python-security-toolkit/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.8%2B-blue)
![deps](https://img.shields.io/badge/dependencies-stdlib%20only-green)

A small collection of **security-focused command-line tools written in pure Python** (standard library only), each with its own documentation and automated tests. Built while studying Cybersecurity at Universidad de Palermo, applying core programming concepts to practical security tasks.

> ⚠️ For educational use and authorized environments only.

---

## Tools

| Tool | What it does | Security concept |
|------|--------------|------------------|
| [**port_scanner**](tools/port_scanner) | Concurrent TCP port scanner using `socket` | Reconnaissance / asset discovery |
| [**log_analyzer**](tools/log_analyzer) | Detects SSH brute-force in `auth.log` | Log analysis / SIEM rules |
| [**password_toolkit**](tools/password_toolkit) | Strength meter, secure generator, hashing | Authentication / cryptography |
| [**file_integrity**](tools/file_integrity) | SHA-256 baseline & change detection (FIM) | Integrity monitoring |
| [**sqli_lab**](tools/sqli_lab) | Vulnerable vs. parameterized SQL demo | Secure development / OWASP |

Each tool folder contains the code, a focused `README.md`, and a `test_*.py` test suite.

## Quick start

```bash
git clone https://github.com/catalinacarlen/python-security-toolkit
cd python-security-toolkit

python3 tools/port_scanner/port_scanner.py 127.0.0.1
python3 tools/log_analyzer/log_analyzer.py tools/log_analyzer/sample_auth.log
python3 tools/sqli_lab/sqli_lab.py --demo
```

## Running the tests

```bash
pip install pytest
for dir in tools/*/; do (cd "$dir" && python -m pytest -q); done
```

Tests also run automatically on every push via GitHub Actions (see the badge above).

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
├── tools/            # 5 security tools, each with code + README + tests
├── docs/             # programming theory as reference
├── .github/workflows # CI: pytest on every push
└── requirements.txt  # stdlib only — no external dependencies
```

---
---

# Python Security Toolkit (ES)

Una colección de **herramientas de línea de comandos orientadas a la seguridad, escritas en Python puro** (solo librería estándar), cada una con su documentación y tests automáticos. Desarrollado mientras estudio Ciberseguridad en la Universidad de Palermo, aplicando los conceptos base de programación a tareas prácticas de seguridad.

> ⚠️ Solo para uso educativo y entornos autorizados.

## Herramientas

| Herramienta | Qué hace | Concepto de seguridad |
|-------------|----------|------------------------|
| [**port_scanner**](tools/port_scanner) | Escáner de puertos TCP concurrente con `socket` | Reconocimiento / descubrimiento de activos |
| [**log_analyzer**](tools/log_analyzer) | Detecta fuerza bruta SSH en `auth.log` | Análisis de logs / reglas de SIEM |
| [**password_toolkit**](tools/password_toolkit) | Evaluador de fortaleza, generador seguro, hashing | Autenticación / criptografía |
| [**file_integrity**](tools/file_integrity) | Línea de base SHA-256 y detección de cambios (FIM) | Monitoreo de integridad |
| [**sqli_lab**](tools/sqli_lab) | Demo SQL vulnerable vs. parametrizada | Desarrollo seguro / OWASP |

Cada carpeta contiene el código, un `README.md` propio y una batería de tests `test_*.py`.

## Uso rápido

```bash
git clone https://github.com/catalinacarlen/python-security-toolkit
cd python-security-toolkit

python3 tools/port_scanner/port_scanner.py 127.0.0.1
python3 tools/log_analyzer/log_analyzer.py tools/log_analyzer/sample_auth.log
python3 tools/sqli_lab/sqli_lab.py --demo
```

## Ejecutar los tests

```bash
pip install pytest
for dir in tools/*/; do (cd "$dir" && python -m pytest -q); done
```

Los tests también corren automáticamente en cada push mediante GitHub Actions (ver el badge de arriba).

## Documentación

La carpeta [`docs/`](docs) contiene la teoría detrás del código, organizada como referencia: fundamentos de Python, estructuras de control, funciones, arreglos y diseño de algoritmos.

---

Hecho por [Catalina Carlen](https://github.com/catalinacarlen) — Universidad de Palermo, Ciberseguridad
