# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [0.2.0] — 2026-06-14

Major upgrade: every tool went from a textbook version to a portfolio-grade one,
and the repository became an installable package with a unified CLI and a stricter
CI pipeline. Still **standard library only** — no runtime dependencies.

**At a glance:** 45 → 51 tests, lint + type checking added, 72% coverage, single
`pstk` command, all five tools meaningfully deeper.

### password_toolkit — from arbitrary score to real cryptography

- **Added** entropy-based strength (`entropia_bits`): estimates the real search
  space in bits as `length × log2(charset_pool)`. This is why length matters more
  than adding one symbol — each extra character multiplies the attacker's work.
- **Added** weak-pattern penalties (`_penalizacion_patrones`): subtracts bits for
  common passwords (`password`, `qwerty`), repeated characters (`aaa`),
  keyboard/alphabet sequences (`1234`, `abcd`) and digit-only inputs — the things
  a real attacker tries first.
- **Added** crack-time estimation (`tiempo_crackeo`): translates bits into a human
  figure ("instant" → "thousands of centuries") at a configurable guess rate
  (default 10¹⁰/s, a modern GPU vs. a fast hash).
- **Added** breach check against Have I Been Pwned (`verificar_filtrada`) using
  **k-anonymity**: hashes the password with SHA-1 locally and sends only the first
  5 hex characters; the match is resolved on-device. **The password never leaves
  the machine.** Degrades gracefully with no network.
- **Added** correct password storage (`derivar` / `verificar_derivado`):
  PBKDF2-HMAC-SHA256 with a random per-user salt, 200k iterations, and
  constant-time verification (defeats timing attacks). SHA-256 is kept only for
  integrity, with a note that it must not be used to store passwords.
- **Changed** CLI: new `auditar` subcommand (combined report), `--json` output and
  an `--offline` flag.

### log_analyzer — from a counter to a SIEM-style detection engine

- **Added** **R001 brute force with a sliding time window** (two-pointer scan over
  sorted timestamps): fires on a burst (6 failures in 10s), not on a slow trickle
  (6 failures over a day) — a plain total can't tell them apart.
- **Added** **R002 password spraying**: one IP trying many distinct users with few
  attempts each — the inverse of brute force, which evades per-account thresholds.
- **Added** **R003 user enumeration**: counts `invalid user` events (the server
  revealing which accounts don't exist).
- **Added** **R004 compromise**: a successful login from an IP that was previously
  failing — the brute force that *worked*. Critical severity.
- **Added** structured alerts (rule, severity, IP, description, evidence), an IP
  **watchlist** that raises severity, and `--json` output.
- **Changed** `sample_auth.log`: rewritten with syslog timestamps and scenarios
  that trigger all four rules.

### port_scanner — from open/closed to banner grabbing + fingerprinting

- **Added** banner grabbing (`agarrar_banner`): reads the service greeting
  (SSH/FTP/SMTP greet on connect; HTTP gets a `HEAD` probe). The banner reveals
  **versions**, which is what maps to known CVEs.
- **Added** service fingerprinting (`identificar_servicio`): identifies the service
  from the **banner signature first** (an SSH on port 40000 is still recognized),
  falling back to the well-known-port table only when there's no banner.
- **Added** concurrency/rate control (`-W` workers, `-d` delay), a `--no-banner`
  fast mode, and `--json` output.

### file_integrity — from basic FIM to a trustworthy one

- **Added** permission tracking: stores each file's mode and flags permission
  changes even when the content is unchanged (e.g. a config made world-writable).
- **Added** HMAC-signed baseline (`firmar` / `verificar_firma`): if an attacker
  edits `baseline.json` to hide a change, signature verification fails — closing
  the obvious bypass of attacking the detector itself. Constant-time comparison.
- **Added** real-time `watch` mode (`vigilar`) via polling, and `--json` output.

### sqli_lab — from one demo to a multi-family lab + classifier

- **Added** multiple injection families: auth bypass (`admin' --`), tautology
  (`' OR '1'='1`), **UNION-based** (dumps every user's password), boolean blind and
  time blind.
- **Added** a `clasificar` function that infers a payload's injection family,
  mirroring how a WAF triages input (clean input → "none").
- **Changed** the demo to show each case side by side (vulnerable vs. parameterized)
  and added a `--clasificar` CLI flag.

### Repository — packaging & quality

- **Added** `pyproject.toml`: installable with `pip install -e .`, exposing a single
  **`pstk`** command (`pstk scan`, `pstk logs`, `pstk pwd`, `pstk fim`, `pstk sqli`).
  It dispatches to each tool's `main()`, so nothing is duplicated and every
  subcommand keeps its own `--help`. Tools still run standalone.
- **Added** quality gates to CI: **ruff** (lint), **mypy** (type checking) and
  **pytest + coverage**, on top of the existing test run.
- **Added** `tests/test_cli.py` covering the unified dispatcher; rewrote all five
  tool test suites for the new features (the HIBP network call is mocked so tests
  run offline). 51 tests, 72% coverage.
- **Changed** every README (root + per tool, bilingual EN/ES) to document the new
  features and the reasoning behind each decision; added ruff/mypy/coverage badges.

### Known limitation

- mypy's target is set to 3.10 (modern mypy can't target 3.8), while the code stays
  3.8-compatible at runtime thanks to `from __future__ import annotations`. Pending
  decision: align by raising `requires-python` to 3.10, or pin an older mypy.

---
---

# Registro de cambios (ES)

Todos los cambios relevantes del proyecto se documentan acá.
El formato sigue [Keep a Changelog](https://keepachangelog.com/) y el proyecto usa
[Versionado Semántico](https://semver.org/).

---

## [0.2.0] — 2026-06-14

Mejora mayor: cada herramienta pasó de su versión "de manual" a una de nivel
portfolio, y el repositorio se volvió un paquete instalable con un CLI unificado y
un CI más estricto. Sigue siendo **solo librería estándar** — sin dependencias en
tiempo de ejecución.

**De un vistazo:** 45 → 51 tests, se agregó lint + chequeo de tipos, 72% de
cobertura, un único comando `pstk`, y las cinco herramientas con profundidad real.

### password_toolkit — de un puntaje arbitrario a criptografía real

- **Agregado** fortaleza por entropía (`entropia_bits`): estima el espacio de
  búsqueda real en bits como `longitud × log2(pool_de_caracteres)`. Por eso la
  longitud pesa más que sumar un símbolo: cada carácter extra multiplica el trabajo
  del atacante.
- **Agregado** penalización por patrones débiles (`_penalizacion_patrones`): resta
  bits por contraseñas comunes (`password`, `qwerty`), caracteres repetidos (`aaa`),
  secuencias de teclado/alfabeto (`1234`, `abcd`) y entradas de solo dígitos — lo
  que un atacante prueba primero.
- **Agregado** estimación de tiempo de crackeo (`tiempo_crackeo`): traduce los bits
  a una cifra humana ("instantáneo" → "miles de siglos") a una tasa configurable
  (por defecto 10¹⁰/s, una GPU moderna contra un hash rápido).
- **Agregado** chequeo contra filtraciones vía Have I Been Pwned
  (`verificar_filtrada`) usando **k-anonymity**: calcula el SHA-1 local y solo envía
  los primeros 5 caracteres del hash; el match se resuelve en el equipo. **La
  contraseña nunca sale de la máquina.** Degrada con elegancia si no hay red.
- **Agregado** almacenamiento correcto de contraseñas (`derivar` /
  `verificar_derivado`): PBKDF2-HMAC-SHA256 con salt aleatorio por usuario, 200k
  iteraciones y verificación en tiempo constante (frena timing attacks). El SHA-256
  queda solo para integridad, con la nota de que no debe usarse para guardar
  contraseñas.
- **Cambiado** el CLI: nuevo subcomando `auditar` (reporte combinado), salida
  `--json` y flag `--offline`.

### log_analyzer — de un contador a un motor de detección estilo SIEM

- **Agregado** **R001 fuerza bruta con ventana temporal deslizante** (dos punteros
  sobre timestamps ordenados): dispara ante una ráfaga (6 fallos en 10s), no ante un
  goteo lento (6 fallos en un día) — un total pelado no los distingue.
- **Agregado** **R002 password spraying**: una IP probando muchos usuarios distintos
  con pocos intentos cada uno — el inverso de la fuerza bruta, que evade los
  umbrales por cuenta.
- **Agregado** **R003 enumeración de usuarios**: cuenta los eventos `invalid user`
  (el servidor revelando qué cuentas no existen).
- **Agregado** **R004 compromiso**: un login exitoso desde una IP que venía
  fallando — la fuerza bruta que *funcionó*. Severidad crítica.
- **Agregado** alertas estructuradas (regla, severidad, IP, descripción, evidencia),
  una **watchlist** de IPs que eleva la severidad, y salida `--json`.
- **Cambiado** el `sample_auth.log`: reescrito con timestamps tipo syslog y
  escenarios que disparan las cuatro reglas.

### port_scanner — de abierto/cerrado a banner grabbing + fingerprinting

- **Agregado** banner grabbing (`agarrar_banner`): lee el saludo del servicio
  (SSH/FTP/SMTP saludan al conectar; a HTTP le manda un `HEAD`). El banner revela
  **versiones**, que es lo que se mapea a CVEs conocidas.
- **Agregado** fingerprinting de servicio (`identificar_servicio`): identifica el
  servicio por la **firma del banner primero** (un SSH en el puerto 40000 lo
  reconoce igual) y cae a la tabla de puertos conocidos solo si no hay banner.
- **Agregado** control de concurrencia/rate (`-W` hilos, `-d` retardo), modo rápido
  `--no-banner` y salida `--json`.

### file_integrity — de un FIM básico a uno confiable

- **Agregado** control de permisos: guarda el modo de cada archivo y marca cambios
  de permisos aunque el contenido no cambie (ej. un config dejado world-writable).
- **Agregado** baseline firmado con HMAC (`firmar` / `verificar_firma`): si un
  atacante edita el `baseline.json` para ocultar un cambio, la verificación de la
  firma falla — cierra el bypass obvio de atacar al propio detector. Comparación en
  tiempo constante.
- **Agregado** modo `watch` en tiempo real (`vigilar`) por polling, y salida `--json`.

### sqli_lab — de un demo a un laboratorio multi-familia + clasificador

- **Agregado** varias familias de inyección: bypass de auth (`admin' --`),
  tautología (`' OR '1'='1`), **UNION-based** (vuelca la contraseña de cada
  usuario), blind booleano y blind por tiempo.
- **Agregado** una función `clasificar` que infiere la familia de un payload,
  imitando cómo un WAF triagea la entrada (entrada limpia → "ninguna").
- **Cambiado** el demo para mostrar cada caso lado a lado (vulnerable vs.
  parametrizado) y se sumó el flag `--clasificar` al CLI.

### Repositorio — empaquetado y calidad

- **Agregado** `pyproject.toml`: instalable con `pip install -e .`, que expone un
  único comando **`pstk`** (`pstk scan`, `pstk logs`, `pstk pwd`, `pstk fim`,
  `pstk sqli`). Delega en el `main()` de cada herramienta, así no se duplica nada y
  cada subcomando conserva su propio `--help`. Las herramientas siguen corriéndose
  sueltas.
- **Agregado** controles de calidad al CI: **ruff** (lint), **mypy** (tipos) y
  **pytest + coverage**, además de la corrida de tests existente.
- **Agregado** `tests/test_cli.py` que cubre el dispatcher unificado; se reescribieron
  las cinco suites de tests para las nuevas features (la llamada de red a HIBP está
  mockeada para correr offline). 51 tests, 72% de cobertura.
- **Cambiado** todos los README (raíz + por herramienta, bilingües EN/ES) para
  documentar las nuevas features y el razonamiento detrás de cada decisión; se
  agregaron badges de ruff/mypy/coverage.

### Limitación conocida

- El target de mypy quedó en 3.10 (mypy moderno no puede apuntar a 3.8), mientras el
  código sigue siendo 3.8-compatible en runtime gracias a
  `from __future__ import annotations`. Decisión pendiente: alinear subiendo
  `requires-python` a 3.10, o fijar una versión más vieja de mypy.

[0.2.0]: https://github.com/catalinacarlen/python-security-toolkit/releases/tag/v0.2.0
