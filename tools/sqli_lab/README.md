# SQL Injection Lab

A **local, controlled** lab (in-memory SQLite) that compares a **vulnerable** login query (string concatenation) against a **safe** one (parameterized), and shows how an injection payload defeats the first but not the second.

## What it does
Builds a tiny users database and runs the same login attempt through two implementations — one insecure, one secure — so you can see, side by side, when an attacker gets in and when they don't.

## How it works (and why)
The vulnerability comes from **mixing code and data**. The vulnerable version builds the query by pasting the user input straight into the SQL string:

```python
"... WHERE usuario = '" + usuario + "' AND password = '" + password + "'"
```

If the input is `admin' --`, the resulting SQL becomes `... WHERE usuario = 'admin' --' AND password = '...'`. The `'` closes the string early and `--` comments out the rest, so the password check disappears and the attacker logs in. The database can't tell "data" from "command" because they arrived as one piece of text.

The secure version uses **parameterized queries**: the SQL (`... WHERE usuario = ? AND password = ?`) and the values travel **separately**. The driver always treats the input as plain data, never as SQL, so `admin' --` is searched literally as a username — and simply isn't found. That separation of code and data is the real fix.

## Usage
```bash
python3 sqli_lab.py --demo
```

## Example output
```
== Injection attempt  (usuario = "admin' --", no password) ==
  vulnerable: True   <- improper access!
  secure    : False  <- attack blocked
```

## The lesson
Never build SQL by concatenating user input. Always use **parameterized queries** (`?`), which separate the SQL code from the data.

> ⚠️ The vulnerable function is written that way **on purpose**, for educational use. Do not replicate in production.

## Concepts applied
Functions, strings, decision structures and data handling (`sqlite3`).

## Tests
```bash
pytest
```

---
---

# SQL Injection Lab (ES)

Laboratorio **local y controlado** (SQLite en memoria) que compara una consulta de login **vulnerable** (concatenando strings) contra una **segura** (parametrizada), y demuestra cómo un payload de inyección burla a la primera pero no a la segunda.

## Qué hace
Construye una pequeña base de usuarios y ejecuta el mismo intento de login con dos implementaciones — una insegura y una segura — para ver, lado a lado, cuándo entra un atacante y cuándo no.

## Cómo funciona (y por qué)
La vulnerabilidad surge de **mezclar código y datos**. La versión vulnerable arma la consulta pegando la entrada del usuario directamente en el string SQL:

```python
"... WHERE usuario = '" + usuario + "' AND password = '" + password + "'"
```

Si la entrada es `admin' --`, el SQL resultante queda `... WHERE usuario = 'admin' --' AND password = '...'`. La `'` cierra el string antes de tiempo y `--` comenta el resto, así que la verificación de la contraseña desaparece y el atacante entra. La base de datos no puede distinguir "dato" de "comando" porque llegaron como un único texto.

La versión segura usa **consultas parametrizadas**: el SQL (`... WHERE usuario = ? AND password = ?`) y los valores viajan **por separado**. El driver siempre trata la entrada como dato plano, nunca como SQL, así que `admin' --` se busca literalmente como nombre de usuario — y simplemente no existe. Esa separación entre código y datos es la verdadera solución.

## Uso
```bash
python3 sqli_lab.py --demo
```

## Ejemplo de salida
```
== Intento de inyección  (usuario = "admin' --", sin password) ==
  vulnerable: True   <- ¡acceso indebido!
  seguro    : False  <- ataque bloqueado
```

## La lección
Nunca armar SQL concatenando entrada del usuario. Usar siempre **consultas parametrizadas** (`?`), que separan el código SQL de los datos.

> ⚠️ La función vulnerable está escrita así **a propósito**, con fines educativos. No replicar en producción.

## Conceptos aplicados
Funciones, strings, estructuras de decisión y manejo de datos (`sqlite3`).

## Tests
```bash
pytest
```
