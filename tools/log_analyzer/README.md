# Log Analyzer

A mini detection engine for Linux `auth.log`. Instead of just counting failures per IP, it correlates events over time and emits structured **alerts** the way a basic SIEM rule set would — brute force, password spraying, user enumeration and post-failure compromise.

## What it does
Parses every authentication event (timestamp, IP, user, success/failure) and runs four detection rules, then prints prioritized alerts (text or JSON), raising severity for IPs on a watchlist.

| Rule | Detects | Why it matters |
|------|---------|----------------|
| **R001** Brute force | Many failures from one IP **within a time window** | A burst of guesses against an account |
| **R002** Password spraying | One IP trying **many distinct users**, few tries each | Low-and-slow attack that evades simple thresholds |
| **R003** User enumeration | Repeated `invalid user` attempts | Attacker is probing which accounts exist |
| **R004** Compromise | A **successful login after failures** from the same IP | A brute force that *worked* — highest priority |

## How it works (and why)
The key upgrade over naive counting is **time**. A plain total ("6 failures from this IP") can't tell a slow trickle over a day apart from a 5-second burst — only one is an attack. R001 uses a **sliding time window** (two-pointer scan over sorted timestamps) so it fires on bursts, not on noise.

The rules also separate *shapes* of attack. Brute force is many tries against **one** account; spraying is one try against **many** accounts (R002) — the same total, opposite intent, and only one trips a per-account threshold. Enumeration (R003) keys off `invalid user`, the server politely telling an attacker which usernames don't exist. R004 is the one that matters most: it tracks failures per IP and fires when a `Accepted password` arrives from an IP that was already failing — i.e. the attack succeeded.

Every finding is a structured dict (`rule`, `severity`, `ip`, `description`, `evidence`), which is why `--json` output drops cleanly into other tools or a real SIEM pipeline.

## Usage

With the toolkit installed (`pip install -e .`), use the unified CLI: `pstk logs ...` is equivalent to `python3 log_analyzer.py ...`.

```bash
pstk logs sample_auth.log                                     # same as the script below
python3 log_analyzer.py sample_auth.log                       # text report
python3 log_analyzer.py /var/log/auth.log -u 10 -v 2          # threshold 10, 2-min window
python3 log_analyzer.py sample_auth.log -w 45.33.12.6,9.9.9.9 # watchlist -> critical
python3 log_analyzer.py --json sample_auth.log               # JSON alerts
```

## Example output
```
5 alerta(s) detectada(s):

[CRÍTICA ] R004  198.51.100.7    
           login EXITOSO como 'santi' tras 3 fallos previos
[ALTA    ] R001  192.168.0.5     
           6 fallos en <= 5 min (fuerza bruta)
[ALTA    ] R002  203.0.113.9     
           6 usuarios distintos con <= 3 intentos c/u (password spraying)
[MEDIA   ] R003  45.33.12.6      
           4 usuarios inexistentes probados (enumeración)
```

## How to defend
Rate-limit with `fail2ban`, prefer SSH keys over passwords, disable root login, and alert on R004-type events immediately — a successful login after a burst of failures should page someone.

## Concepts applied
Regular expressions with named groups, `datetime` and sliding windows, dictionaries/sets, sorting, and structured (JSON) output.

## Tests
```bash
pytest
```

---
---

# Log Analyzer (ES)

Un mini motor de detección para el `auth.log` de Linux. En vez de solo contar fallos por IP, correlaciona eventos en el tiempo y emite **alertas** estructuradas como lo haría un conjunto de reglas de SIEM básico — fuerza bruta, password spraying, enumeración de usuarios y compromiso tras fallos.

## Qué hace
Parsea cada evento de autenticación (timestamp, IP, usuario, éxito/fallo) y corre cuatro reglas de detección, imprimiendo alertas priorizadas (texto o JSON) y elevando la severidad de las IPs en una watchlist.

| Regla | Detecta | Por qué importa |
|-------|---------|-----------------|
| **R001** Fuerza bruta | Muchos fallos de una IP **dentro de una ventana de tiempo** | Una ráfaga de intentos contra una cuenta |
| **R002** Password spraying | Una IP probando **muchos usuarios distintos**, pocos intentos c/u | Ataque lento que evade umbrales simples |
| **R003** Enumeración | Intentos repetidos de `invalid user` | El atacante tantea qué cuentas existen |
| **R004** Compromiso | Un **login exitoso tras fallos** desde la misma IP | Una fuerza bruta que *funcionó* — máxima prioridad |

## Cómo funciona (y por qué)
La mejora clave frente al conteo ingenuo es el **tiempo**. Un total pelado ("6 fallos de esta IP") no distingue un goteo lento durante un día de una ráfaga de 5 segundos — y solo una es un ataque. R001 usa una **ventana de tiempo deslizante** (recorrido de dos punteros sobre timestamps ordenados) para disparar ante ráfagas, no ante ruido.

Las reglas también separan las *formas* del ataque. La fuerza bruta es muchos intentos contra **una** cuenta; el spraying es un intento contra **muchas** cuentas (R002) — el mismo total, intención opuesta, y solo una cruza un umbral por cuenta. La enumeración (R003) se apoya en `invalid user`, el servidor avisándole amablemente al atacante qué usuarios no existen. R004 es la que más importa: lleva la cuenta de fallos por IP y dispara cuando llega un `Accepted password` desde una IP que ya venía fallando — es decir, el ataque tuvo éxito.

Cada hallazgo es un dict estructurado (`regla`, `severidad`, `ip`, `descripcion`, `evidencia`), por eso la salida `--json` encaja limpio en otras herramientas o en un pipeline de SIEM real.

## Uso

Con el toolkit instalado (`pip install -e .`), usá el CLI unificado: `pstk logs ...` equivale a `python3 log_analyzer.py ...`.

```bash
pstk logs sample_auth.log                                     # igual que el script de abajo
python3 log_analyzer.py sample_auth.log                       # reporte de texto
python3 log_analyzer.py /var/log/auth.log -u 10 -v 2          # umbral 10, ventana 2 min
python3 log_analyzer.py sample_auth.log -w 45.33.12.6,9.9.9.9 # watchlist -> crítica
python3 log_analyzer.py --json sample_auth.log               # alertas en JSON
```

## Ejemplo de salida
```
5 alerta(s) detectada(s):

[CRÍTICA ] R004  198.51.100.7    
           login EXITOSO como 'santi' tras 3 fallos previos
[ALTA    ] R001  192.168.0.5     
           6 fallos en <= 5 min (fuerza bruta)
[ALTA    ] R002  203.0.113.9     
           6 usuarios distintos con <= 3 intentos c/u (password spraying)
[MEDIA   ] R003  45.33.12.6      
           4 usuarios inexistentes probados (enumeración)
```

## Cómo defenderse
Limitar intentos con `fail2ban`, preferir claves SSH a contraseñas, desactivar el login de root y alertar de inmediato ante eventos tipo R004 — un login exitoso tras una ráfaga de fallos debería despertar a alguien.

## Conceptos aplicados
Expresiones regulares con grupos nombrados, `datetime` y ventanas deslizantes, diccionarios/conjuntos, ordenamiento y salida estructurada (JSON).

## Tests
```bash
pytest
```
