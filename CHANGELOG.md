# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-06-14

### Changed

- **password_toolkit:** the entropy estimator now combines the character-pool upper
  bound with a structural estimate for recognizable human patterns (a common
  word or name followed by a year and/or trailing symbols) and takes the lower of
  the two. Added leet-substitution normalization (e.g. `P4ssw0rd` → `password`), an
  expanded list of weak base tokens (common passwords, names, words in ES/EN),
  embedded-year detection, and repeated-run penalties scaled by run length. As a
  result, templates such as `Princesa2002!` are now scored as very weak instead of
  very strong. Passphrases and random passwords are unaffected.

## [0.2.0] — 2026-06-14

The repository was packaged as an installable distribution with a unified CLI, and
each tool gained additional capabilities. No runtime dependencies were added
(standard library only). Test count increased from 45 to 51; lint and type checking
were added to CI; coverage is 72%.

### Added

- Unified `pstk` command (`pyproject.toml`, `pip install -e .`) dispatching to each
  tool (`scan`, `logs`, `pwd`, `fim`, `sqli`); tools remain runnable as standalone scripts.
- CI quality gates: `ruff` (lint), `mypy` (type checking) and `coverage`.
- `tests/test_cli.py` covering the unified CLI dispatcher.
- `LICENSE` (MIT).
- **password_toolkit:** entropy-based strength scoring, crack-time estimation, HIBP
  breach check via k-anonymity, PBKDF2-HMAC-SHA256 hashing with constant-time
  verification, `auditar` subcommand, `--json` and `--offline` flags.
- **log_analyzer:** sliding-window brute-force detection (R001), password spraying
  (R002), user enumeration (R003) and post-failure compromise (R004); IP watchlist;
  structured JSON alerts.
- **port_scanner:** banner grabbing, banner-based service fingerprinting, worker and
  delay controls, `--no-banner` mode, `--json` output.
- **file_integrity:** permission-change detection, HMAC-signed baseline, `watch` mode,
  `--json` output.
- **sqli_lab:** UNION-based, boolean-blind and time-based families; payload classifier;
  `--clasificar` flag.

### Changed

- Rewrote all tool test suites for the new functionality; the HIBP network call is
  mocked so tests run offline.
- Rewrote the root and per-tool READMEs.
- Replaced `log_analyzer/sample_auth.log` with scenarios covering all four rules.

### Removed

- `docs/` programming-theory reference and `requirements.txt` (superseded by
  `pyproject.toml`).

### Known limitations

- The mypy target is set to 3.10 (current mypy cannot target 3.8); the code remains
  3.8-compatible at runtime through `from __future__ import annotations`.

## [0.1.0]

Initial release: five command-line security tools (port scanner, log analyzer,
password toolkit, file integrity checker, SQL injection lab), each with a README and
test suite, and a GitHub Actions workflow running the tests.

---
---

# Registro de cambios (ES)

Todos los cambios relevantes del proyecto se documentan aquí.
El formato se basa en [Keep a Changelog](https://keepachangelog.com/),
y el proyecto sigue [Versionado Semántico](https://semver.org/).

## [0.3.0] — 2026-06-14

### Cambiado

- **password_toolkit:** el estimador de entropía ahora combina el límite superior por
  pool de caracteres con una estimación estructural para patrones humanos reconocibles
  (una palabra o nombre común seguido de un año y/o símbolos al final) y toma el menor
  de los dos. Se agregó normalización de sustituciones leet (p. ej. `P4ssw0rd` →
  `password`), una lista ampliada de tokens base débiles (contraseñas, nombres y
  palabras comunes en ES/EN), detección de años embebidos y penalización por corridas
  de caracteres repetidos escalada según su longitud. Como resultado, plantillas como
  `Princesa2002!` se evalúan como muy débiles en lugar de muy fuertes. Las passphrases
  y las contraseñas aleatorias no se ven afectadas.

## [0.2.0] — 2026-06-14

El repositorio se empaquetó como una distribución instalable con un CLI unificado, y
cada herramienta incorporó capacidades adicionales. No se agregaron dependencias en
tiempo de ejecución (solo librería estándar). La cantidad de tests pasó de 45 a 51; se
añadieron lint y chequeo de tipos al CI; la cobertura es del 72%.

### Agregado

- Comando unificado `pstk` (`pyproject.toml`, `pip install -e .`) que despacha a cada
  herramienta (`scan`, `logs`, `pwd`, `fim`, `sqli`); las herramientas siguen
  ejecutables como scripts independientes.
- Controles de calidad en CI: `ruff` (lint), `mypy` (chequeo de tipos) y `coverage`.
- `tests/test_cli.py` que cubre el dispatcher del CLI unificado.
- `LICENSE` (MIT).
- **password_toolkit:** evaluación de fortaleza por entropía, estimación de tiempo de
  crackeo, verificación HIBP mediante k-anonymity, hashing PBKDF2-HMAC-SHA256 con
  verificación en tiempo constante, subcomando `auditar`, flags `--json` y `--offline`.
- **log_analyzer:** detección de fuerza bruta con ventana deslizante (R001), password
  spraying (R002), enumeración de usuarios (R003) y compromiso tras fallos (R004);
  watchlist de IPs; alertas JSON estructuradas.
- **port_scanner:** banner grabbing, fingerprinting de servicio por banner, control de
  hilos y retardo, modo `--no-banner`, salida `--json`.
- **file_integrity:** detección de cambios de permisos, baseline firmado con HMAC, modo
  `watch`, salida `--json`.
- **sqli_lab:** familias UNION-based, blind booleano y por tiempo; clasificador de
  payloads; flag `--clasificar`.

### Cambiado

- Se reescribieron todas las baterías de tests para la nueva funcionalidad; la llamada
  de red a HIBP está mockeada para que los tests corran sin conexión.
- Se reescribieron el README raíz y los de cada herramienta.
- Se reemplazó `log_analyzer/sample_auth.log` por escenarios que cubren las cuatro reglas.

### Eliminado

- Referencia de teoría de programación `docs/` y `requirements.txt` (reemplazado por
  `pyproject.toml`).

### Limitaciones conocidas

- El target de mypy se fijó en 3.10 (la versión actual de mypy no puede apuntar a 3.8);
  el código permanece 3.8-compatible en runtime mediante `from __future__ import annotations`.

## [0.1.0]

Versión inicial: cinco herramientas de seguridad de línea de comandos (escáner de
puertos, analizador de logs, kit de contraseñas, verificador de integridad de archivos,
laboratorio de inyección SQL), cada una con su README y batería de tests, y un workflow
de GitHub Actions que ejecuta los tests.

[0.3.0]: https://github.com/catalinacarlen/python-security-toolkit/releases/tag/v0.3.0
[0.2.0]: https://github.com/catalinacarlen/python-security-toolkit/releases/tag/v0.2.0
