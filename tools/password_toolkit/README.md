# Password Toolkit

Three utilities in one: a strength **meter**, a cryptographically secure **generator** (`secrets`), and **hashing** with `hashlib`.

## What it does
Scores how strong a password is, generates robust random passwords, and computes a hash of a password (optionally with a salt).

## How it works (and why)
- **Strength meter:** a password's resistance to guessing grows with its *length* and its *variety of character classes* (lower, upper, digits, symbols). More length and more variety mean a far larger search space for an attacker, so the score rewards both.
- **Secure generator:** it uses the `secrets` module, not `random`. `random` is a pseudo-random generator designed for reproducibility, so its output can be predicted — useless for security. `secrets` draws from the operating system's cryptographically secure source. The generator also forces at least one character of every class so the result is always strong.
- **Hashing:** a hash is a **one-way** function — easy to compute, practically impossible to reverse. Storing the hash instead of the password means a leak doesn't expose the original. A **salt** (random text added before hashing) ensures two identical passwords produce different hashes, defeating precomputed-table attacks.

## Usage
```bash
python3 password_toolkit.py evaluar "Abc123!"
python3 password_toolkit.py generar -l 20
python3 password_toolkit.py hashear "my-key" --salt random
```

## Example output
```
Fortaleza: Muy fuerte (4/4)
7?.h9[AiQ_UmsH8K
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

## Security note
`SHA-256` is fine for integrity checks but **not** for storing passwords in production: for that, use slow, salted algorithms like **bcrypt, scrypt or Argon2**, which are deliberately expensive to brute-force.

## Concepts applied
Strings, functions, decision structures, logical operators and modules (`secrets`, `hashlib`, `string`).

## Tests
```bash
pytest
```

---
---

# Password Toolkit (ES)

Tres utilidades en una: **evaluador** de fortaleza, **generador** criptográficamente seguro (`secrets`) y **hashing** con `hashlib`.

## Qué hace
Puntúa qué tan fuerte es una contraseña, genera contraseñas aleatorias robustas y calcula el hash de una contraseña (con salt opcional).

## Cómo funciona (y por qué)
- **Evaluador de fortaleza:** la resistencia de una contraseña a ser adivinada crece con su *longitud* y su *variedad de tipos de caracteres* (minúsculas, mayúsculas, dígitos, símbolos). A mayor longitud y variedad, mucho mayor el espacio de búsqueda para un atacante, así que el puntaje premia ambas cosas.
- **Generador seguro:** usa el módulo `secrets`, no `random`. `random` es un generador pseudoaleatorio pensado para ser reproducible, por lo que su salida se puede predecir — inútil para seguridad. `secrets` toma valores de la fuente criptográficamente segura del sistema operativo. Además, el generador obliga a incluir al menos un carácter de cada clase para que el resultado siempre sea fuerte.
- **Hashing:** un hash es una función de **un solo sentido** — fácil de calcular, prácticamente imposible de revertir. Guardar el hash en vez de la contraseña hace que una filtración no exponga el original. Un **salt** (texto aleatorio añadido antes de hashear) logra que dos contraseñas iguales produzcan hashes distintos, frustrando los ataques con tablas precalculadas.

## Uso
```bash
python3 password_toolkit.py evaluar "Abc123!"
python3 password_toolkit.py generar -l 20
python3 password_toolkit.py hashear "mi-clave" --salt aleatorio
```

## Ejemplo de salida
```
Fortaleza: Muy fuerte (4/4)
7?.h9[AiQ_UmsH8K
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

## Nota de seguridad
`SHA-256` sirve para verificar integridad, **no** para guardar contraseñas en producción: para eso se usan algoritmos lentos y con *salt* como **bcrypt, scrypt o Argon2**, deliberadamente costosos de romper por fuerza bruta.

## Conceptos aplicados
Strings, funciones, estructuras de decisión, operadores lógicos y módulos (`secrets`, `hashlib`, `string`).

## Tests
```bash
pytest
```
