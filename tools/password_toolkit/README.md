# Password Toolkit

Password auditing utility. It scores password strength by estimated entropy, estimates crack time, checks a password against known breaches via Have I Been Pwned, generates secure passwords, and computes password hashes.

## Features

- Strength scoring based on estimated entropy in bits. The estimate combines a character-pool upper bound with a structural estimate for recognizable human patterns (a common word or name followed by a year and/or trailing symbols) and takes the lower of the two. Includes leet-substitution normalization, embedded-year detection, and penalties for repeated runs and keyboard/alphabet sequences.
- Crack-time estimation at a configurable guess rate.
- Breach check against Have I Been Pwned using the k-anonymity model: only the first five characters of the SHA-1 hash are sent; the password is never transmitted. Degrades gracefully when offline.
- Cryptographically secure password generation (`secrets`).
- Hashing with SHA-256 (integrity) and PBKDF2-HMAC-SHA256 with a per-call random salt (storage), verified in constant time.
- Plain-text or JSON output.

## Usage

```bash
pstk pwd auditar "C0rr3ct-H0rs3_Battery$taple!9"            # via the unified CLI
python3 password_toolkit.py auditar "C0rr3ct-H0rs3_Battery$taple!9"   # standalone
```

```bash
pstk pwd --json auditar --offline "example"                 # no network
pstk pwd evaluar "example"
pstk pwd generar -l 20
pstk pwd hashear "input" --algoritmo pbkdf2
pstk pwd filtrada "password"                                # queries HIBP (requires network)
```

## Subcommands

| Subcommand | Description |
|------------|-------------|
| `auditar` | Combined report: entropy, strength, crack time, breach status (`--offline` skips HIBP) |
| `evaluar` | Strength and entropy only |
| `generar` | Generate a secure password (`-l` length) |
| `hashear` | Hash a value (`--algoritmo sha256|pbkdf2`, `--salt`) |
| `filtrada` | Breach check against HIBP |

The global `--json` flag applies to all subcommands.

## Output

```
$ pstk pwd evaluar "C0rr3ct-H0rs3_Battery$taple!9"
Fortaleza: Muy fuerte (4/4) — 190.1 bits — crackeo: miles de siglos
```

## Security considerations

SHA-256 is suitable for integrity verification, not for password storage. For storage, use a slow, salted algorithm such as PBKDF2 (provided here), or bcrypt, scrypt or Argon2.

## Testing

```bash
pytest
```

Network access to HIBP is mocked in the test suite, so tests run offline.

---
---

# Password Toolkit (ES)

Utilidad de auditoría de contraseñas. Evalúa la fortaleza por entropía estimada, estima el tiempo de crackeo, verifica una contraseña contra filtraciones conocidas mediante Have I Been Pwned, genera contraseñas seguras y calcula hashes de contraseñas.

## Características

- Evaluación de fortaleza basada en entropía estimada en bits. La estimación combina un límite superior por pool de caracteres con una estimación estructural para patrones humanos reconocibles (una palabra o nombre común seguido de un año y/o símbolos al final) y toma el menor de los dos. Incluye normalización de sustituciones leet, detección de años embebidos y penalizaciones por corridas repetidas y secuencias de teclado/alfabeto.
- Estimación del tiempo de crackeo a una tasa de adivinanzas configurable.
- Verificación contra Have I Been Pwned mediante el modelo de k-anonymity: solo se envían los primeros cinco caracteres del hash SHA-1; la contraseña nunca se transmite. Degrada con elegancia sin conexión.
- Generación de contraseñas criptográficamente segura (`secrets`).
- Hashing con SHA-256 (integridad) y PBKDF2-HMAC-SHA256 con salt aleatorio por llamada (almacenamiento), verificado en tiempo constante.
- Salida en texto plano o JSON.

## Uso

```bash
pstk pwd auditar "C0rr3ct-H0rs3_Battery$taple!9"            # mediante el CLI unificado
python3 password_toolkit.py auditar "C0rr3ct-H0rs3_Battery$taple!9"   # script independiente
```

```bash
pstk pwd --json auditar --offline "ejemplo"                 # sin red
pstk pwd evaluar "ejemplo"
pstk pwd generar -l 20
pstk pwd hashear "entrada" --algoritmo pbkdf2
pstk pwd filtrada "password"                                # consulta HIBP (requiere red)
```

## Subcomandos

| Subcomando | Descripción |
|------------|-------------|
| `auditar` | Reporte combinado: entropía, fortaleza, tiempo de crackeo, estado de filtración (`--offline` omite HIBP) |
| `evaluar` | Solo fortaleza y entropía |
| `generar` | Genera una contraseña segura (`-l` longitud) |
| `hashear` | Hashea un valor (`--algoritmo sha256|pbkdf2`, `--salt`) |
| `filtrada` | Verificación contra HIBP |

El flag global `--json` aplica a todos los subcomandos.

## Salida

```
$ pstk pwd evaluar "C0rr3ct-H0rs3_Battery$taple!9"
Fortaleza: Muy fuerte (4/4) — 190.1 bits — crackeo: miles de siglos
```

## Consideraciones de seguridad

SHA-256 es adecuado para verificar integridad, no para almacenar contraseñas. Para almacenamiento, utilice un algoritmo lento y con salt como PBKDF2 (provisto aquí), o bcrypt, scrypt o Argon2.

## Tests

```bash
pytest
```

El acceso de red a HIBP está mockeado en la batería de tests, por lo que los tests corren sin conexión.
