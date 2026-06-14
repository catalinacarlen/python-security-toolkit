# SQL Injection Lab

Local demonstration of SQL injection against an in-memory SQLite database. It contrasts a vulnerable, string-concatenated query with a parameterized one across several injection families, and includes a classifier that labels a payload by injection family.

The vulnerable functions are intentionally insecure and exist solely for demonstration. They must not be used in production.

## Injection families

| Family | Example payload |
|--------|-----------------|
| Authentication bypass | `admin' --` |
| Tautology | `' OR '1'='1` |
| UNION-based | `x' UNION SELECT user, pass FROM usuarios --` |
| Boolean blind | `admin' AND '1'='1` |
| Time-based blind | `admin'; SELECT CASE WHEN (1=1) THEN randomblob(...) ... --` |

## Features

- Side-by-side comparison of vulnerable and parameterized queries.
- Demonstration of authentication bypass, UNION-based extraction, and blind techniques.
- Payload classifier returning the inferred injection family (`union`, `time_blind`, `tautologia`, `auth_bypass`, `boolean_blind`, `stacked`, or `ninguna`).
- Runs entirely locally; no external database.

## Usage

```bash
pstk sqli --demo                                             # via the unified CLI
python3 sqli_lab.py --demo                                   # as a standalone script
```

```bash
pstk sqli --clasificar "x' UNION SELECT a,b FROM users --"   # -> union
pstk sqli --clasificar "input"                               # -> ninguna
```

## Options

| Option | Description |
|--------|-------------|
| `--demo` | Run the full demonstration |
| `--clasificar PAYLOAD` | Classify a payload and print its injection family |

## Output

```
== 2) Bypass de autenticación  (usuario = "admin' --") ==
  vulnerable: True
  seguro    : False

== 4) Clasificador de payloads ==
  union         <- x' UNION SELECT usuario, password FROM usuarios --
  time_blind    <- admin'; SELECT CASE WHEN (1=1) THEN randomblob(...) ...
```

## Reference

Parameterized queries separate SQL code from data and prevent the injection families above. See OWASP guidance on SQL injection prevention.

## Testing

```bash
pytest
```

---
---

# SQL Injection Lab (ES)

Demostración local de inyección SQL contra una base SQLite en memoria. Contrasta una consulta vulnerable, armada por concatenación de strings, con una parametrizada, a través de varias familias de inyección, e incluye un clasificador que etiqueta un payload por familia de inyección.

Las funciones vulnerables son intencionalmente inseguras y existen únicamente con fines de demostración. No deben usarse en producción.

## Familias de inyección

| Familia | Payload de ejemplo |
|---------|--------------------|
| Bypass de autenticación | `admin' --` |
| Tautología | `' OR '1'='1` |
| UNION-based | `x' UNION SELECT user, pass FROM usuarios --` |
| Blind booleano | `admin' AND '1'='1` |
| Blind por tiempo | `admin'; SELECT CASE WHEN (1=1) THEN randomblob(...) ... --` |

## Características

- Comparación lado a lado de consultas vulnerable y parametrizada.
- Demostración de bypass de autenticación, extracción con UNION y técnicas blind.
- Clasificador de payloads que devuelve la familia inferida (`union`, `time_blind`, `tautologia`, `auth_bypass`, `boolean_blind`, `stacked` o `ninguna`).
- Se ejecuta enteramente en local; sin base de datos externa.

## Uso

```bash
pstk sqli --demo                                             # mediante el CLI unificado
python3 sqli_lab.py --demo                                   # como script independiente
```

```bash
pstk sqli --clasificar "x' UNION SELECT a,b FROM users --"   # -> union
pstk sqli --clasificar "entrada"                             # -> ninguna
```

## Opciones

| Opción | Descripción |
|--------|-------------|
| `--demo` | Ejecuta la demostración completa |
| `--clasificar PAYLOAD` | Clasifica un payload e imprime su familia de inyección |

## Salida

```
== 2) Bypass de autenticación  (usuario = "admin' --") ==
  vulnerable: True
  seguro    : False

== 4) Clasificador de payloads ==
  union         <- x' UNION SELECT usuario, password FROM usuarios --
  time_blind    <- admin'; SELECT CASE WHEN (1=1) THEN randomblob(...) ...
```

## Referencia

Las consultas parametrizadas separan el código SQL de los datos y previenen las familias de inyección anteriores. Ver la guía de OWASP sobre prevención de inyección SQL.

## Tests

```bash
pytest
```
