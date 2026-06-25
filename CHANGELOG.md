# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.5.0] — 2026-06-14

### Changed

- **log_analyzer:** the engine is now streaming. File analysis processes the log line
  by line and keeps only per-detector state bounded by each rule's time window, instead
  of loading the whole file and the full event list into memory. The in-memory
  `analizar()` path still sorts events first.
- **log_analyzer:** R004 (post-failure compromise) is correlated by (IP, user) within a
  time window and resets on a successful login. This removes the false positives that
  occurred behind NAT (one user fails, another succeeds) and the repeated alerts on
  every subsequent success.
- **log_analyzer:** all rules now use sliding time windows and alert once per episode,
  reducing alert fatigue.

### Added

- **log_analyzer:** timestamp parsing for ISO 8601 / RFC 5424 logs (with year and time
  zone, normalized to UTC), in addition to the BSD syslog format. For BSD timestamps the
  year rollover (Dec → Jan within one file) is now inferred so events stay ordered.

## [0.4.0] — 2026-06-14

### Added

- **log_analyzer:** authentication coverage now includes public-key logins
  (`Failed`/`Accepted publickey`), so brute force (R001) and post-failure compromise
  (R004) are no longer blind to key-based authentication.
- **log_analyzer:** IPv6 support. Source addresses are validated and normalized with
  the `ipaddress` module, which also rejects malformed IPv4 addresses (e.g. octets > 255).

### Fixed

- **log_analyzer:** lines collapsed by syslog as `message repeated N times: [ ... ]`
  are now expanded into N events (capped to avoid resource exhaustion). Previously a
  brute-force burst collapsed by rsyslog/journald was counted as a single failure and
  could evade the threshold (MITRE ATT&CK T1110).
- **log_analyzer:** lines with an impossible date (e.g. `Feb 30`) are now skipped
  instead of aborting the analysis.

## [0.3.1] — 2026-06-14

### Security

- **port_scanner:** sanitize service banners before display. A banner is attacker-
  controlled data; control characters (including ANSI escape sequences) are now
  stripped to prevent terminal-escape injection when printing scan results.
- **log_analyzer:** sanitize the username field at parse time. Usernames originate from
  the log (attacker-controlled in login attempts) and reach the text output, so control
  characters are stripped to prevent terminal-escape injection.
- **file_integrity:** symlinks are no longer followed when building a manifest; they are
  recorded by their target, which avoids hashing files outside the monitored tree and
  detects type/target changes (e.g. a file replaced by a symlink).
- **file_integrity:** `check` now warns on stderr when the baseline is signed but no
  key is provided, instead of silently skipping signature verification.

### Fixed

- **log_analyzer:** the synthetic base year for syslog timestamps is now a leap year,
  so legitimate `Feb 29` entries no longer raise `ValueError` and abort the analysis.

## [0.3.0] — 2026-06-14

### Added

- **password_toolkit:** secure password input via `getpass` when the password is omitted
  (the password is no longer required on the command line, where it would be exposed in
  shell history and the process list); the password is never written to disk or logs.
- **password_toolkit:** dictionary-based weak-token detection with a curated bundled list
  (`data/common_passwords.txt`) and support for an external wordlist (`.txt` or `.gz`) via
  `--wordlist` or the `PSTK_WORDLIST` environment variable; embedded dictionary words are
  detected, not only exact matches.

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

## [0.5.0] — 2026-06-14

### Cambiado

- **log_analyzer:** el motor ahora es streaming. El análisis de archivo procesa el log
  línea por línea y mantiene solo el estado de cada detector, acotado por la ventana
  temporal de cada regla, en lugar de cargar el archivo entero y la lista completa de
  eventos en memoria. El camino en memoria `analizar()` sigue ordenando primero.
- **log_analyzer:** R004 (compromiso tras fallos) ahora se correlaciona por (IP, usuario)
  dentro de una ventana y se resetea con el login exitoso. Esto elimina los falsos
  positivos detrás de NAT (un usuario falla, otro entra) y las alertas repetidas en
  cada éxito posterior.
- **log_analyzer:** todas las reglas usan ventanas de tiempo deslizantes y alertan una
  vez por episodio, reduciendo la fatiga de alertas.

### Agregado

- **log_analyzer:** parseo de timestamps ISO 8601 / RFC 5424 (con año y zona horaria,
  normalizados a UTC), además del formato BSD de syslog. Para los timestamps BSD se
  infiere el cruce de año (Dic → Ene dentro de un mismo archivo) para que los eventos
  queden ordenados.

## [0.4.0] — 2026-06-14

### Agregado

- **log_analyzer:** la cobertura de autenticación ahora incluye los logins por clave
  pública (`Failed`/`Accepted publickey`), de modo que la fuerza bruta (R001) y el
  compromiso tras fallos (R004) dejan de ser ciegos a la autenticación por clave.
- **log_analyzer:** soporte de IPv6. Las direcciones de origen se validan y normalizan
  con el módulo `ipaddress`, que además rechaza direcciones IPv4 malformadas (p. ej.
  octetos > 255).

### Corregido

- **log_analyzer:** las líneas colapsadas por syslog como `message repeated N times: [ ... ]`
  ahora se expanden en N eventos (con una cota para evitar agotamiento de recursos).
  Antes, una ráfaga de fuerza bruta colapsada por rsyslog/journald se contaba como un
  único fallo y podía evadir el umbral (MITRE ATT&CK T1110).
- **log_analyzer:** las líneas con una fecha imposible (p. ej. `Feb 30`) ahora se
  descartan en lugar de abortar el análisis.

## [0.3.1] — 2026-06-14

### Seguridad

- **port_scanner:** se sanitizan los banners de servicio antes de mostrarlos. El banner
  es dato controlado por el host remoto; ahora se eliminan los caracteres de control
  (incluidas las secuencias de escape ANSI) para evitar la inyección de secuencias de
  escape en la terminal al imprimir los resultados.
- **log_analyzer:** se sanitiza el campo de usuario al parsear. El usuario proviene del
  log (controlado por el atacante en los intentos de login) y llega a la salida de texto,
  por lo que se eliminan los caracteres de control para evitar la inyección de secuencias
  de escape en la terminal.
- **file_integrity:** los symlinks ya no se siguen al generar el manifiesto; se registran
  por su destino, lo que evita hashear archivos fuera del árbol monitoreado y permite
  detectar cambios de tipo/destino (p. ej. un archivo reemplazado por un enlace).
- **file_integrity:** `check` ahora advierte por stderr cuando la línea de base está
  firmada pero no se indicó clave, en lugar de omitir la verificación en silencio.

### Corregido

- **log_analyzer:** el año base sintético de los timestamps de syslog ahora es bisiesto,
  por lo que las entradas legítimas del `29 de febrero` ya no lanzan `ValueError` ni
  abortan el análisis.

## [0.3.0] — 2026-06-14

### Agregado

- **password_toolkit:** entrada segura de la contraseña mediante `getpass` cuando se omite
  (la contraseña ya no es obligatoria en la línea de comandos, donde quedaría expuesta en
  el historial del shell y la lista de procesos); la contraseña nunca se escribe en disco
  ni en logs.
- **password_toolkit:** detección de tokens débiles por diccionario con una lista curada
  embebida (`data/common_passwords.txt`) y soporte para una wordlist externa (`.txt` o
  `.gz`) mediante `--wordlist` o la variable de entorno `PSTK_WORDLIST`; se detectan
  palabras del diccionario embebidas, no solo coincidencias exactas.

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

[0.5.0]: https://github.com/catalinacarlen/python-security-toolkit/releases/tag/v0.5.0
[0.4.0]: https://github.com/catalinacarlen/python-security-toolkit/releases/tag/v0.4.0
[0.3.1]: https://github.com/catalinacarlen/python-security-toolkit/releases/tag/v0.3.1
[0.3.0]: https://github.com/catalinacarlen/python-security-toolkit/releases/tag/v0.3.0
[0.2.0]: https://github.com/catalinacarlen/python-security-toolkit/releases/tag/v0.2.0
