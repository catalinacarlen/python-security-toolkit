# Password Toolkit

An auditor for passwords: it measures strength by **real entropy (bits)**, estimates **crack time**, checks the password against **real-world breaches** (Have I Been Pwned, privately), generates secure passwords, and hashes them correctly.

## What it does
- **Audit** — one command returns entropy, strength, estimated crack time and breach status.
- **Strength by entropy** — instead of an arbitrary score, it computes the size of the search space in bits and penalizes weak patterns (common passwords, repeats, keyboard/alphabet sequences).
- **Breach check (HIBP)** — tells you how many times a password has appeared in known leaks.
- **Generator** — cryptographically secure, with `secrets`.
- **Hashing** — `SHA-256` for integrity and **PBKDF2-HMAC-SHA256** (salted, slow) for password storage.

## How it works (and why)
- **Entropy, not vibes.** Strength is estimated as `length × log2(pool)`, where *pool* is the size of the character set used. This is why length matters more than throwing in one symbol: every extra character multiplies the attacker's work. Weak structures (e.g. `password`, `aaa`, `qwerty`, `123456`) get bits subtracted, because a real attacker tries those first.
- **Crack time.** The bits are translated into an average guessing time at a configurable rate (default 10¹⁰ guesses/sec, a modern GPU against a fast hash). It turns an abstract number into "instant" vs "thousands of centuries".
- **Breach check via k-anonymity.** The password is hashed with SHA-1 locally and **only the first 5 characters** of that hash are sent to the HIBP range API. The API returns every suffix sharing that prefix and the match is resolved on your machine — **the password never leaves your computer**. With no network it degrades gracefully (returns "not verifiable").
- **Storage done right.** `SHA-256` is fast, which is exactly what you *don't* want for stored passwords. `derivar()` uses PBKDF2 with a random per-user salt and 200k iterations, and verification uses a constant-time comparison to avoid timing attacks.

## Usage

With the toolkit installed (`pip install -e .`), use the unified CLI: `pstk pwd ...` is equivalent to `python3 password_toolkit.py ...`.

```bash
# full report (entropy + crack time + breach check)
pstk pwd auditar "C0rr3ct-H0rs3_Battery$taple!9"            # same as the script below
python3 password_toolkit.py auditar "C0rr3ct-H0rs3_Battery$taple!9"
python3 password_toolkit.py --json auditar --offline "Abc123!"   # no network

python3 password_toolkit.py evaluar "Abc123!"
python3 password_toolkit.py generar -l 20
python3 password_toolkit.py hashear "my-key" --algoritmo pbkdf2
python3 password_toolkit.py filtrada "password"                  # query HIBP
```

## Example output
```
$ password_toolkit.py evaluar "C0rr3ct-H0rs3_Battery$taple!9"
Fortaleza: Muy fuerte (4/4) — 190.1 bits — crackeo: miles de siglos

$ password_toolkit.py --json auditar --offline "password"
{
  "longitud": 8,
  "entropia_bits": 17.6,
  "fortaleza": "Muy débil",
  "tiempo_crackeo_estimado": "instantáneo",
  ...
}
```

## Security note
`SHA-256` is for integrity, **not** password storage. For storage use slow, salted algorithms — PBKDF2 (shown here, stdlib) or, better still, **bcrypt, scrypt or Argon2**.

## Concepts applied
Strings, functions, decision structures, modules (`secrets`, `hashlib`, `urllib`), entropy/`math`, and safe network handling. Tests mock the network so they run offline.

## Tests
```bash
pytest
```

---
---

# Password Toolkit (ES)

Un auditor de contraseñas: mide la fortaleza por **entropía real (bits)**, estima el **tiempo de crackeo**, verifica la contraseña contra **filtraciones reales** (Have I Been Pwned, de forma privada), genera contraseñas seguras y las hashea como corresponde.

## Qué hace
- **Auditar** — un solo comando devuelve entropía, fortaleza, tiempo de crackeo estimado y estado de filtración.
- **Fortaleza por entropía** — en vez de un puntaje arbitrario, calcula el tamaño del espacio de búsqueda en bits y penaliza patrones débiles (contraseñas comunes, repeticiones, secuencias de teclado/alfabeto).
- **Chequeo de filtración (HIBP)** — te dice cuántas veces apareció la contraseña en brechas conocidas.
- **Generador** — criptográficamente seguro, con `secrets`.
- **Hashing** — `SHA-256` para integridad y **PBKDF2-HMAC-SHA256** (con salt, lento) para almacenamiento de contraseñas.

## Cómo funciona (y por qué)
- **Entropía, no intuición.** La fortaleza se estima como `longitud × log2(pool)`, donde *pool* es el tamaño del conjunto de caracteres usado. Por eso la longitud pesa más que meter un símbolo suelto: cada carácter extra multiplica el trabajo del atacante. Las estructuras débiles (`password`, `aaa`, `qwerty`, `123456`) restan bits, porque un atacante real las prueba primero.
- **Tiempo de crackeo.** Los bits se traducen a un tiempo medio de adivinanza a una tasa configurable (por defecto 10¹⁰ intentos/seg, una GPU moderna contra un hash rápido). Convierte un número abstracto en "instantáneo" vs "miles de siglos".
- **Chequeo por k-anonymity.** La contraseña se hashea con SHA-1 localmente y **solo se envían los 5 primeros caracteres** de ese hash a la API de rangos de HIBP. La API devuelve todos los sufijos que comparten ese prefijo y la coincidencia se resuelve en tu equipo — **la contraseña nunca sale de tu computadora**. Sin red, degrada con elegancia (devuelve "no verificable").
- **Almacenamiento bien hecho.** `SHA-256` es rápido, justo lo que *no* querés para contraseñas guardadas. `derivar()` usa PBKDF2 con salt aleatorio por usuario y 200k iteraciones, y la verificación usa comparación en tiempo constante para evitar ataques de temporización.

## Uso

Con el toolkit instalado (`pip install -e .`), usá el CLI unificado: `pstk pwd ...` equivale a `python3 password_toolkit.py ...`.

```bash
# reporte completo (entropía + crack time + filtraciones)
pstk pwd auditar "C0rr3ct-H0rs3_Battery$taple!9"            # igual que el script de abajo
python3 password_toolkit.py auditar "C0rr3ct-H0rs3_Battery$taple!9"
python3 password_toolkit.py --json auditar --offline "Abc123!"   # sin red

python3 password_toolkit.py evaluar "Abc123!"
python3 password_toolkit.py generar -l 20
python3 password_toolkit.py hashear "mi-clave" --algoritmo pbkdf2
python3 password_toolkit.py filtrada "password"                  # consulta HIBP
```

## Ejemplo de salida
```
$ password_toolkit.py evaluar "C0rr3ct-H0rs3_Battery$taple!9"
Fortaleza: Muy fuerte (4/4) — 190.1 bits — crackeo: miles de siglos

$ password_toolkit.py --json auditar --offline "password"
{
  "longitud": 8,
  "entropia_bits": 17.6,
  "fortaleza": "Muy débil",
  "tiempo_crackeo_estimado": "instantáneo",
  ...
}
```

## Nota de seguridad
`SHA-256` es para integridad, **no** para guardar contraseñas. Para almacenar, usá algoritmos lentos y con *salt* — PBKDF2 (mostrado acá, stdlib) o, mejor aún, **bcrypt, scrypt o Argon2**.

## Conceptos aplicados
Strings, funciones, estructuras de decisión, módulos (`secrets`, `hashlib`, `urllib`), entropía/`math` y manejo seguro de red. Los tests mockean la red para correr offline.

## Tests
```bash
pytest
```
