# SQL Injection Lab

A **local, controlled** lab (in-memory SQLite) that demonstrates several **families** of SQL injection against a vulnerable query vs. a parameterized one — and ships a **classifier** that, given a payload, infers which injection family it belongs to (the kind of heuristic a WAF or static analyzer uses to alert).

## What it does
Builds a tiny users database and shows, side by side, how different attacks defeat string-concatenated SQL while parameterized SQL resists them. It covers authentication bypass, UNION-based extraction, boolean-based blind and time-based blind — and classifies arbitrary payloads.

## Injection families
| Family | Example payload | Idea |
|--------|-----------------|------|
| **Auth bypass** | `admin' --` | Close the string and comment out the password check |
| **Tautology** | `' OR '1'='1` | A condition that's always true returns every row |
| **UNION-based** | `x' UNION SELECT user, pass FROM usuarios --` | Append a second result set to exfiltrate data |
| **Boolean blind** | `admin' AND '1'='1` | Infer data from true/false response differences |
| **Time blind** | `...CASE WHEN (1=1) THEN randomblob(…)…` | Infer data from how long the response takes |

## How it works (and why)
The root cause is always **mixing code and data**. The vulnerable query pastes input straight into the SQL string, so `admin' --` becomes part of the *command*: the `'` closes the string and `--` comments out the password check. UNION goes further — it doesn't just bypass a check, it **appends an attacker-controlled query** that dumps other rows (here, every user's password).

The fix is **parameterized queries**: the SQL (`… WHERE usuario = ?`) and the values travel separately, so input is always treated as plain data and `admin' --` is searched literally as a username — and not found. Same payloads, blocked.

The **classifier** mirrors how detection tools triage input: UNION+SELECT → `union`; sleep/`randomblob`/`waitfor` → `time_blind`; stacked `;` + SELECT → `stacked`; `OR 1=1` → `tautologia`; comment markers → `auth_bypass`; clean input → `ninguna`. It's a heuristic, not a guarantee — but it shows the reasoning behind a WAF rule.

## Usage

With the toolkit installed (`pip install -e .`), use the unified CLI: `pstk sqli ...` is equivalent to `python3 sqli_lab.py ...`.

```bash
pstk sqli --demo                                                      # same as the script below
python3 sqli_lab.py --demo
python3 sqli_lab.py --clasificar "x' UNION SELECT a,b FROM users --"   # -> union
python3 sqli_lab.py --clasificar "Cata"                                # -> ninguna
```

## Example output
```
== 2) Bypass de autenticación  (usuario = "admin' --") ==
  vulnerable: True   <- ¡acceso indebido!
  seguro    : False  <- ataque bloqueado

== 4) Clasificador de payloads ==
  union         <- x' UNION SELECT usuario, password FROM usuarios --
  time_blind    <- admin'; SELECT CASE WHEN (1=1) THEN randomblob(...) ...
```

## The lesson
Never build SQL by concatenating user input. Use **parameterized queries** (`?`) — they separate code from data and neutralize every family above at once.

> ⚠️ The vulnerable functions are written that way **on purpose**, for educational use. Do not replicate in production.

## Concepts applied
Strings, regular expressions, decision structures and `sqlite3` (parameterized vs. concatenated queries).

## Tests
```bash
pytest
```

---
---

# SQL Injection Lab (ES)

Laboratorio **local y controlado** (SQLite en memoria) que demuestra varias **familias** de inyección SQL contra una consulta vulnerable frente a una parametrizada — e incluye un **clasificador** que, dado un payload, infiere a qué familia pertenece (la heurística que usaría un WAF o un analizador estático para alertar).

## Qué hace
Construye una pequeña base de usuarios y muestra, lado a lado, cómo distintos ataques burlan al SQL armado por concatenación mientras el SQL parametrizado los resiste. Cubre bypass de autenticación, extracción con UNION, blind booleano y blind por tiempo — y clasifica payloads arbitrarios.

## Familias de inyección
| Familia | Payload de ejemplo | Idea |
|---------|--------------------|------|
| **Bypass de auth** | `admin' --` | Cerrar el string y comentar la verificación de la contraseña |
| **Tautología** | `' OR '1'='1` | Una condición siempre verdadera devuelve todas las filas |
| **UNION-based** | `x' UNION SELECT user, pass FROM usuarios --` | Anexar un segundo resultado para exfiltrar datos |
| **Blind booleano** | `admin' AND '1'='1` | Inferir datos por diferencias en respuestas true/false |
| **Blind por tiempo** | `...CASE WHEN (1=1) THEN randomblob(…)…` | Inferir datos por cuánto tarda la respuesta |

## Cómo funciona (y por qué)
La causa raíz siempre es **mezclar código y datos**. La consulta vulnerable pega la entrada directo en el string SQL, así que `admin' --` pasa a ser parte del *comando*: la `'` cierra el string y `--` comenta la verificación de la contraseña. UNION va más allá — no solo evade un control, **anexa una consulta controlada por el atacante** que vuelca otras filas (acá, la contraseña de cada usuario).

La solución son las **consultas parametrizadas**: el SQL (`… WHERE usuario = ?`) y los valores viajan por separado, así la entrada siempre se trata como dato plano y `admin' --` se busca literalmente como nombre de usuario — y no existe. Los mismos payloads, bloqueados.

El **clasificador** imita cómo las herramientas de detección triagean la entrada: UNION+SELECT → `union`; sleep/`randomblob`/`waitfor` → `time_blind`; `;` apilado + SELECT → `stacked`; `OR 1=1` → `tautologia`; marcadores de comentario → `auth_bypass`; entrada limpia → `ninguna`. Es una heurística, no una garantía — pero muestra el razonamiento detrás de una regla de WAF.

## Uso

Con el toolkit instalado (`pip install -e .`), usá el CLI unificado: `pstk sqli ...` equivale a `python3 sqli_lab.py ...`.

```bash
pstk sqli --demo                                                      # igual que el script de abajo
python3 sqli_lab.py --demo
python3 sqli_lab.py --clasificar "x' UNION SELECT a,b FROM users --"   # -> union
python3 sqli_lab.py --clasificar "Cata"                                # -> ninguna
```

## Ejemplo de salida
```
== 2) Bypass de autenticación  (usuario = "admin' --") ==
  vulnerable: True   <- ¡acceso indebido!
  seguro    : False  <- ataque bloqueado

== 4) Clasificador de payloads ==
  union         <- x' UNION SELECT usuario, password FROM usuarios --
  time_blind    <- admin'; SELECT CASE WHEN (1=1) THEN randomblob(...) ...
```

## La lección
Nunca armar SQL concatenando entrada del usuario. Usá **consultas parametrizadas** (`?`) — separan el código de los datos y neutralizan de una vez todas las familias de arriba.

> ⚠️ Las funciones vulnerables están escritas así **a propósito**, con fines educativos. No replicar en producción.

## Conceptos aplicados
Strings, expresiones regulares, estructuras de decisión y `sqlite3` (consultas parametrizadas vs. concatenadas).

## Tests
```bash
pytest
```
