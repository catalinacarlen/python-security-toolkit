# File Integrity Checker

A File Integrity Monitor (FIM) that tracks not just **content** but **permissions**, can **sign its own baseline** so tampering is detectable, and offers a real-time **watch** mode. SHA-256 fingerprints + set comparison, the way Tripwire or AIDE work — plus the hardening those need to be trustworthy.

## What it does
Builds a baseline manifest (each file → hash + permissions). On later runs it re-scans and classifies every difference as **modified**, **permission-changed**, **new** or **deleted**. The baseline can be HMAC-signed, and `watch` reports changes as they happen.

## How it works (and why)
- **Hashing.** SHA-256 turns any file into a 64-char fingerprint that is deterministic and collision-resistant: change one byte and the hash changes completely. Comparing hashes is a fast, exact proxy for comparing whole files.
- **Permissions matter too.** An attacker can make a config `world-writable` or a script `setuid` **without changing a byte of content**. Storing the file mode and flagging permission changes catches that class of attack a content-only FIM would miss.
- **Signed baseline (the key upgrade).** A FIM is only as trustworthy as its baseline — if an attacker edits `baseline.json` to match their tampered files, you'd see "no changes". With `-k`, the baseline is signed with **HMAC-SHA256**; loading it recomputes the signature and **refuses a baseline that was altered** without the key. Verification uses a constant-time compare.
- **Detection = set comparison.** Files in both manifests with a different hash are *modified*; same hash but different mode are *permission* changes; only-in-new are *new*; only-in-baseline are *deleted*.

## Usage
```bash
# create a signed baseline
python3 file_integrity.py baseline ./my_dir -o baseline.json -k "secret-key"

# later, verify integrity (checks the signature too)
python3 file_integrity.py check ./my_dir -b baseline.json -k "secret-key"
python3 file_integrity.py --json check ./my_dir -b baseline.json   # structured

# watch a directory live
python3 file_integrity.py watch ./my_dir -i 2
```

## Example output
```
MODIFICADOS (1):
  config/app.conf

PERMISOS (1):
  scripts/deploy.sh

NUEVOS (1):
  uploads/shell.php
```

## Security relevance
A FIM detects unauthorized change: altered binaries, uploaded webshells, tampered configs, or a quietly relaxed permission. Signing the baseline closes the obvious bypass — attacking the detector itself.

## Concepts applied
Cryptographic hashing, HMAC signing (`hmac`), file permissions (`os.stat`), JSON read/write, directory traversal, polling, and set comparison.

## Tests
```bash
pytest
```

---
---

# File Integrity Checker (ES)

Un monitor de integridad de archivos (FIM) que vigila no solo el **contenido** sino los **permisos**, puede **firmar su propia línea de base** para detectar manipulación, y ofrece un modo **watch** en tiempo real. Huellas SHA-256 + comparación de conjuntos, como Tripwire o AIDE — más el blindaje que necesitan para ser confiables.

## Qué hace
Construye una línea de base (cada archivo → hash + permisos). En ejecuciones posteriores re-escanea y clasifica cada diferencia como **modificado**, **permiso cambiado**, **nuevo** o **eliminado**. La base puede firmarse con HMAC, y `watch` reporta cambios apenas ocurren.

## Cómo funciona (y por qué)
- **Hashing.** SHA-256 convierte cualquier archivo en una huella de 64 caracteres determinista y resistente a colisiones: cambiás un byte y el hash cambia por completo. Comparar hashes equivale a comparar archivos enteros — rápido y exacto.
- **Los permisos también importan.** Un atacante puede dejar un config `world-writable` o un script `setuid` **sin cambiar un solo byte del contenido**. Guardar el modo del archivo y marcar los cambios de permisos atrapa esa clase de ataque que un FIM de solo contenido dejaría pasar.
- **Baseline firmado (la mejora clave).** Un FIM vale lo que vale su línea de base — si un atacante edita `baseline.json` para que coincida con sus archivos manipulados, verías "sin cambios". Con `-k`, la base se firma con **HMAC-SHA256**; al cargarla se recalcula la firma y **se rechaza una base alterada** sin la clave. La verificación usa comparación en tiempo constante.
- **Detección = comparación de conjuntos.** Archivos en ambos manifiestos con hash distinto son *modificados*; mismo hash pero distinto modo son cambios de *permisos*; solo-en-nuevo son *nuevos*; solo-en-base son *eliminados*.

## Uso
```bash
# crear una línea de base firmada
python3 file_integrity.py baseline ./mi_dir -o baseline.json -k "clave-secreta"

# más tarde, verificar integridad (chequea también la firma)
python3 file_integrity.py check ./mi_dir -b baseline.json -k "clave-secreta"
python3 file_integrity.py --json check ./mi_dir -b baseline.json   # estructurado

# vigilar un directorio en vivo
python3 file_integrity.py watch ./mi_dir -i 2
```

## Ejemplo de salida
```
MODIFICADOS (1):
  config/app.conf

PERMISOS (1):
  scripts/deploy.sh

NUEVOS (1):
  uploads/shell.php
```

## Para qué sirve en seguridad
Un FIM detecta cambios no autorizados: binarios alterados, webshells subidas, configs manipuladas o un permiso relajado en silencio. Firmar la base cierra el bypass obvio — atacar al propio detector.

## Conceptos aplicados
Hashing criptográfico, firma HMAC (`hmac`), permisos de archivos (`os.stat`), lectura/escritura JSON, recorrido de directorios, polling y comparación de conjuntos.

## Tests
```bash
pytest
```
