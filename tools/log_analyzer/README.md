# Log Analyzer

Detection engine for Linux authentication logs (`auth.log`). It parses authentication events and applies a set of correlation rules, emitting structured alerts. Output is available as plain text or JSON.

## Detection rules

| Rule | ATT&CK | Condition | Severity |
|------|--------|-----------|----------|
| R001 | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute force: failures from one IP exceeding a threshold within a sliding time window | High → Critical by volume |
| R002 | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password spraying: one IP attempting many distinct usernames with few attempts each | High |
| R003 | [T1087](https://attack.mitre.org/techniques/T1087/) | User enumeration: repeated `invalid user` attempts from one IP | Medium |
| R004 | [T1078](https://attack.mitre.org/techniques/T1078/) | Compromise: a successful login correlated with prior failures of the same (IP, user) within a window | Critical |

## Features

- Every alert is tagged with its **MITRE ATT&CK** technique (`tecnica` field).
- **Sigma rule export** (`--sigma`): emits the four detections as Sigma rules, portable to
  SIEMs such as Splunk or ELK.
- **Allowlist** (`-a`) to suppress known-good IPs, in addition to the watchlist (which
  raises severity).
- **Per-IP enrichment**: each alert includes the IP scope (private/public/loopback/…), and
  optional country/ASN from an offline base (`--geodb`).
- **Volume-based severity** for R001 (escalates from high to critical on large bursts).
- Timestamp-aware parsing of failure and success events, for both password and
  public-key authentication, over IPv4 and IPv6 (addresses validated with `ipaddress`).
- Expansion of syslog `message repeated N times` lines, so collapsed brute-force
  bursts are not undercounted.
- BSD and ISO 8601 / RFC 5424 timestamps (the latter with year and time zone).
- Streaming file analysis: the log is processed line by line with per-rule state bounded
  by each detection window, so memory does not grow with the file size.
- Sliding time windows for all rules; each fires once per episode.
- Plain-text or JSON output.

## Usage

```bash
pstk logs sample_auth.log                                     # via the unified CLI
python3 log_analyzer.py sample_auth.log                       # as a standalone script
```

```bash
pstk logs /var/log/auth.log -u 10 -v 2                        # threshold 10, 2-minute window
pstk logs sample_auth.log -w 45.33.12.6,9.9.9.9               # watchlist (raise severity)
pstk logs sample_auth.log -a 10.0.0.20                        # allowlist (suppress)
pstk logs sample_auth.log --geodb geoip.csv --json           # enrich with country/ASN
pstk logs --sigma                                            # export Sigma rules and exit
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `archivo` | Path to the log file (optional with `--sigma`) | — |
| `-u`, `--umbral` | Failure threshold for brute force | 5 |
| `-v`, `--ventana` | Time window in minutes for brute force | 2 |
| `-w`, `--watchlist` | Comma-separated IPs to escalate | empty |
| `-a`, `--allowlist` | Comma-separated known-good IPs to suppress | empty |
| `--geodb` | Offline `cidr,country,asn` file for enrichment | none |
| `--sigma` | Emit detections as Sigma rules and exit | off |
| `--json` | JSON output | off |

## Sigma export

`pstk logs --sigma` prints the four detections as [Sigma](https://github.com/SigmaHQ/sigma)
rules (the open detection-rule standard), each carrying its MITRE ATT&CK tags and
references. Sigma rules can be converted to many SIEM query languages (Splunk SPL, ELK, etc.).

## Exit code

Exits with `1` when there are alerts of high or critical severity, and `0` otherwise.
This allows chaining the tool in a pipeline or cron job (e.g. page when a critical alert appears).

## Output

```
5 alerta(s) detectada(s):

[CRÍTICA ] R004  198.51.100.7    login EXITOSO como 'santi' tras 3 fallos previos
[ALTA    ] R001  192.168.0.5     6 fallos en <= 5 min (fuerza bruta)
[ALTA    ] R002  203.0.113.9     6 usuarios distintos con <= 3 intentos c/u (password spraying)
[MEDIA   ] R003  45.33.12.6      4 usuarios inexistentes probados (enumeración)
```

## Recommended mitigations

Rate-limit authentication attempts (e.g. `fail2ban`), prefer key-based SSH authentication over passwords, disable direct root login, and forward R004-type events to an alerting pipeline.

## Testing

```bash
pytest
```

---
---

# Log Analyzer (ES)

Motor de detección para logs de autenticación de Linux (`auth.log`). Parsea los eventos de autenticación y aplica un conjunto de reglas de correlación, emitiendo alertas estructuradas. La salida está disponible en texto plano o JSON.

## Reglas de detección

| Regla | ATT&CK | Condición | Severidad |
|-------|--------|-----------|-----------|
| R001 | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Fuerza bruta: fallos de una IP que superan un umbral dentro de una ventana de tiempo deslizante | Alta → Crítica por volumen |
| R002 | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password spraying: una IP que prueba muchos usuarios distintos con pocos intentos cada uno | Alta |
| R003 | [T1087](https://attack.mitre.org/techniques/T1087/) | Enumeración de usuarios: intentos repetidos de `invalid user` desde una IP | Media |
| R004 | [T1078](https://attack.mitre.org/techniques/T1078/) | Compromiso: un login exitoso correlacionado con fallos previos del mismo (IP, usuario) dentro de una ventana | Crítica |

## Características

- Cada alerta se etiqueta con su técnica de **MITRE ATT&CK** (campo `tecnica`).
- **Export a reglas Sigma** (`--sigma`): emite las cuatro detecciones como reglas Sigma,
  portables a SIEMs como Splunk o ELK.
- **Allowlist** (`-a`) para suprimir IPs conocidas-buenas, además de la watchlist (que
  eleva la severidad).
- **Enriquecimiento por IP**: cada alerta incluye el alcance de la IP (privada/pública/
  loopback/…) y, opcionalmente, país/ASN desde una base offline (`--geodb`).
- **Severidad por volumen** en R001 (escala de alta a crítica ante ráfagas grandes).
- Parseo de eventos de fallo y éxito con reconocimiento de timestamps, tanto para
  autenticación por password como por clave pública, sobre IPv4 e IPv6 (direcciones
  validadas con `ipaddress`).
- Expansión de las líneas `message repeated N times` de syslog, para no subcontar las
  ráfagas de fuerza bruta colapsadas.
- Timestamps BSD e ISO 8601 / RFC 5424 (estos últimos con año y zona horaria).
- Análisis de archivo en streaming: el log se procesa línea por línea con el estado de
  cada regla acotado por su ventana, de modo que la memoria no crece con el tamaño del
  archivo.
- Ventanas de tiempo deslizantes en todas las reglas; cada una alerta una vez por episodio.
- Salida en texto plano o JSON.

## Uso

```bash
pstk logs sample_auth.log                                     # mediante el CLI unificado
python3 log_analyzer.py sample_auth.log                       # como script independiente
```

```bash
pstk logs /var/log/auth.log -u 10 -v 2                        # umbral 10, ventana de 2 minutos
pstk logs sample_auth.log -w 45.33.12.6,9.9.9.9               # watchlist (eleva severidad)
pstk logs sample_auth.log -a 10.0.0.20                        # allowlist (suprime)
pstk logs sample_auth.log --geodb geoip.csv --json           # enriquece con país/ASN
pstk logs --sigma                                            # exporta las reglas Sigma y termina
```

## Opciones

| Opción | Descripción | Por defecto |
|--------|-------------|-------------|
| `archivo` | Ruta al archivo de log (opcional con `--sigma`) | — |
| `-u`, `--umbral` | Umbral de fallos para fuerza bruta | 5 |
| `-v`, `--ventana` | Ventana en minutos para fuerza bruta | 2 |
| `-w`, `--watchlist` | IPs separadas por coma a escalar | vacío |
| `-a`, `--allowlist` | IPs conocidas-buenas a suprimir, separadas por coma | vacío |
| `--geodb` | Archivo offline `cidr,pais,asn` para enriquecer | ninguno |
| `--sigma` | Emite las detecciones como reglas Sigma y termina | off |
| `--json` | Salida JSON | off |

## Export a Sigma

`pstk logs --sigma` imprime las cuatro detecciones como reglas [Sigma](https://github.com/SigmaHQ/sigma)
(el estándar abierto de reglas de detección), cada una con sus tags y referencias de MITRE
ATT&CK. Las reglas Sigma se pueden convertir a muchos lenguajes de SIEM (Splunk SPL, ELK, etc.).

## Código de salida

Sale con `1` cuando hay alertas de severidad alta o crítica, y `0` en caso contrario.
Esto permite encadenar la herramienta en un pipeline o cron (p. ej. paginar ante una alerta crítica).

## Salida

```
5 alerta(s) detectada(s):

[CRÍTICA ] R004  198.51.100.7    login EXITOSO como 'santi' tras 3 fallos previos
[ALTA    ] R001  192.168.0.5     6 fallos en <= 5 min (fuerza bruta)
[ALTA    ] R002  203.0.113.9     6 usuarios distintos con <= 3 intentos c/u (password spraying)
[MEDIA   ] R003  45.33.12.6      4 usuarios inexistentes probados (enumeración)
```

## Mitigaciones recomendadas

Limitar los intentos de autenticación (p. ej. `fail2ban`), preferir autenticación SSH por clave en lugar de contraseña, deshabilitar el login directo de root y reenviar los eventos tipo R004 a un pipeline de alertas.

## Tests

```bash
pytest
```
