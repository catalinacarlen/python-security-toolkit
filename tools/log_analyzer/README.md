# Log Analyzer

Parses a Linux `auth.log`, counts failed login attempts per IP and flags those above a threshold: the classic pattern of an SSH **brute-force** attack.

## What it does
Reads an authentication log, extracts the source IP of every failed login, counts how many failures each IP produced, and lists the ones that cross a configurable threshold.

## How it works (and why)
Each failed SSH login writes a predictable line such as `Failed password for ... from <IP>`. A **regular expression** extracts the IP from those lines and ignores the rest. The IPs are tallied in a **dictionary** (`{ip: count}`), which is the natural structure for grouping and counting.

The detection logic rests on a simple idea: a legitimate user mistypes a password once or twice; an **attacker tries hundreds**. So a high number of failures from a single IP is a strong signal of a brute-force attempt. The threshold separates noise from attacks, and sorting the results puts the worst offenders first.

## Usage
```bash
python3 log_analyzer.py sample_auth.log            # default threshold: 5
python3 log_analyzer.py /var/log/auth.log -u 10
```

## Example output
```
Suspicious IPs (>= 5 failed attempts):

  192.168.0.5      6 attempts
```

## How to defend
Rate-limit attempts with `fail2ban`, use SSH keys instead of passwords, and changing the default port reduces noise.

## Concepts applied
Regular expressions, file reading, dictionaries, loops and sorting.

## Tests
```bash
pytest
```

---
---

# Log Analyzer (ES)

Analiza un `auth.log` de Linux, cuenta los intentos fallidos de login por IP y marca las que superan un umbral: el patrón típico de un ataque de **fuerza bruta** por SSH.

## Qué hace
Lee un log de autenticación, extrae la IP de origen de cada login fallido, cuenta cuántos fallos produjo cada IP y lista las que cruzan un umbral configurable.

## Cómo funciona (y por qué)
Cada login SSH fallido escribe una línea predecible como `Failed password for ... from <IP>`. Una **expresión regular** extrae la IP de esas líneas e ignora el resto. Las IPs se acumulan en un **diccionario** (`{ip: cantidad}`), la estructura natural para agrupar y contar.

La lógica de detección se apoya en una idea simple: un usuario legítimo se equivoca una o dos veces; un **atacante prueba cientos**. Por eso, un número alto de fallos desde una misma IP es una señal fuerte de fuerza bruta. El umbral separa el ruido de los ataques, y ordenar los resultados pone primero a los más agresivos.

## Uso
```bash
python3 log_analyzer.py sample_auth.log            # umbral por defecto: 5
python3 log_analyzer.py /var/log/auth.log -u 10
```

## Ejemplo de salida
```
IPs sospechosas (>= 5 intentos fallidos):

  192.168.0.5      6 intentos
```

## Cómo defenderse
Limitar intentos con `fail2ban`, usar claves SSH en vez de contraseñas, y cambiar el puerto por defecto reduce el ruido.

## Conceptos aplicados
Expresiones regulares, lectura de archivos, diccionarios, ciclos y ordenamiento.

## Tests
```bash
pytest
```
