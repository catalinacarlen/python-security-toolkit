# Log Analyzer

Detection engine for Linux authentication logs (`auth.log`). It parses authentication events and applies a set of correlation rules, emitting structured alerts. Output is available as plain text or JSON.

## Detection rules

| Rule | Condition | Severity |
|------|-----------|----------|
| R001 | Brute force: failures from one IP exceeding a threshold within a sliding time window | High |
| R002 | Password spraying: one IP attempting many distinct usernames with few attempts each | High |
| R003 | User enumeration: repeated `invalid user` attempts from one IP | Medium |
| R004 | Compromise: a successful login from an IP with prior failures | Critical |

## Features

- Timestamp-aware parsing of failure and success events.
- Sliding time window for brute-force detection.
- IP watchlist that raises the severity of matching alerts.
- Structured alerts (rule, severity, IP, description, evidence).
- Plain-text or JSON output.

## Usage

```bash
pstk logs sample_auth.log                                     # via the unified CLI
python3 log_analyzer.py sample_auth.log                       # as a standalone script
```

```bash
pstk logs /var/log/auth.log -u 10 -v 2                        # threshold 10, 2-minute window
pstk logs sample_auth.log -w 45.33.12.6,9.9.9.9               # watchlist
pstk logs sample_auth.log --json
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `archivo` | Path to the log file | — |
| `-u`, `--umbral` | Failure threshold for brute force | 5 |
| `-v`, `--ventana` | Time window in minutes for brute force | 2 |
| `-w`, `--watchlist` | Comma-separated IPs to escalate | empty |
| `--json` | JSON output | off |

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

| Regla | Condición | Severidad |
|-------|-----------|-----------|
| R001 | Fuerza bruta: fallos de una IP que superan un umbral dentro de una ventana de tiempo deslizante | Alta |
| R002 | Password spraying: una IP que prueba muchos usuarios distintos con pocos intentos cada uno | Alta |
| R003 | Enumeración de usuarios: intentos repetidos de `invalid user` desde una IP | Media |
| R004 | Compromiso: un login exitoso desde una IP con fallos previos | Crítica |

## Características

- Parseo de eventos de fallo y éxito con reconocimiento de timestamps.
- Ventana de tiempo deslizante para la detección de fuerza bruta.
- Watchlist de IPs que eleva la severidad de las alertas coincidentes.
- Alertas estructuradas (regla, severidad, IP, descripción, evidencia).
- Salida en texto plano o JSON.

## Uso

```bash
pstk logs sample_auth.log                                     # mediante el CLI unificado
python3 log_analyzer.py sample_auth.log                       # como script independiente
```

```bash
pstk logs /var/log/auth.log -u 10 -v 2                        # umbral 10, ventana de 2 minutos
pstk logs sample_auth.log -w 45.33.12.6,9.9.9.9               # watchlist
pstk logs sample_auth.log --json
```

## Opciones

| Opción | Descripción | Por defecto |
|--------|-------------|-------------|
| `archivo` | Ruta al archivo de log | — |
| `-u`, `--umbral` | Umbral de fallos para fuerza bruta | 5 |
| `-v`, `--ventana` | Ventana en minutos para fuerza bruta | 2 |
| `-w`, `--watchlist` | IPs separadas por coma a escalar | vacío |
| `--json` | Salida JSON | off |

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
