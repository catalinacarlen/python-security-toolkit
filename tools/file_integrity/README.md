# File Integrity Checker

Computes the SHA-256 hash of every file in a directory, saves a baseline, and detects **modified, new or deleted** files on later runs. A basic File Integrity Monitoring (FIM) tool.

## What it does
First it builds a *baseline* (a manifest mapping each file to its hash). Later, it re-hashes the directory and compares against the baseline, classifying every difference.

## How it works (and why)
The core is the **cryptographic hash**. SHA-256 turns any file into a 64-character fingerprint with two key properties: it is **deterministic** (the same bytes always give the same hash) and **collision-resistant** (changing even one byte produces a completely different hash). So comparing hashes is a reliable proxy for comparing entire files — fast and exact.

Detection is just **set comparison** between two manifests: files in both but with different hashes are *modified*; files only in the new scan are *new*; files only in the baseline are *deleted*. This is exactly how tools like Tripwire or AIDE detect tampering at scale.

## Usage
```bash
python3 file_integrity.py baseline ./my_directory -o baseline.json
# ... later, to check for changes ...
python3 file_integrity.py check ./my_directory -b baseline.json
```

## Example output
```
MODIFICADOS (1):
  config/app.conf

NUEVOS (1):
  uploads/shell.php
```

## Security relevance
A FIM detects unauthorized changes: malware that alters binaries, webshells uploaded to a server, or tampered configuration files.

## Concepts applied
Functions, dictionaries, file read/write (JSON), directory traversal and decision structures.

## Tests
```bash
pytest
```

---
---

# File Integrity Checker (ES)

Calcula el hash SHA-256 de los archivos de un directorio, guarda una línea de base y detecta archivos **modificados, nuevos o eliminados** en ejecuciones posteriores. Es un control de integridad de archivos (FIM) básico.

## Qué hace
Primero construye una *línea de base* (un manifiesto que asocia cada archivo con su hash). Después vuelve a hashear el directorio y lo compara contra la base, clasificando cada diferencia.

## Cómo funciona (y por qué)
El núcleo es el **hash criptográfico**. SHA-256 convierte cualquier archivo en una huella de 64 caracteres con dos propiedades clave: es **determinista** (los mismos bytes dan siempre el mismo hash) y **resistente a colisiones** (cambiar aunque sea un byte produce un hash completamente distinto). Por eso comparar hashes equivale a comparar archivos enteros — rápido y exacto.

La detección es simplemente una **comparación de conjuntos** entre dos manifiestos: los archivos que están en ambos pero con hash distinto están *modificados*; los que solo están en el nuevo escaneo son *nuevos*; los que solo están en la base fueron *eliminados*. Así detectan manipulaciones, a gran escala, herramientas como Tripwire o AIDE.

## Uso
```bash
python3 file_integrity.py baseline ./mi_directorio -o baseline.json
# ... más tarde, para comprobar cambios ...
python3 file_integrity.py check ./mi_directorio -b baseline.json
```

## Ejemplo de salida
```
MODIFICADOS (1):
  config/app.conf

NUEVOS (1):
  uploads/shell.php
```

## Para qué sirve en seguridad
Un FIM detecta cambios no autorizados: malware que altera binarios, webshells subidas a un servidor o configuraciones manipuladas.

## Conceptos aplicados
Funciones, diccionarios, lectura/escritura de archivos (JSON), recorrido de directorios y estructuras de decisión.

## Tests
```bash
pytest
```
