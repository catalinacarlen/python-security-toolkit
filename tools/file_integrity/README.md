# File Integrity Checker

File integrity monitoring (FIM) tool. It records a baseline of file hashes and permissions for a directory, and on later runs reports files that were modified, had their permissions changed, were added or were deleted. The baseline can be signed to detect tampering.

## Features

- SHA-256 hashing of every file in a directory tree.
- Permission tracking: changes to file mode are reported even when content is unchanged.
- Optional HMAC-signed baseline; loading a tampered baseline fails verification.
- Real-time `watch` mode via polling.
- Plain-text or JSON output for the `check` command.

## Usage

```bash
pstk fim baseline ./directory -o baseline.json -k "secret-key"   # via the unified CLI
python3 file_integrity.py baseline ./directory -o baseline.json -k "secret-key"   # standalone
```

```bash
pstk fim check ./directory -b baseline.json -k "secret-key"
pstk fim --json check ./directory -b baseline.json
pstk fim watch ./directory -i 2
```

## Commands

| Command | Description |
|---------|-------------|
| `baseline <dir>` | Create a baseline (`-o` output path, `-k` signing key) |
| `check <dir>` | Compare current state against a baseline (`-b` baseline, `-k` key) |
| `watch <dir>` | Monitor a directory in real time (`-i` interval in seconds) |

Change categories reported by `check`: modified, permission, new, deleted.

## Output

```
MODIFICADOS (1):
  config/app.conf

PERMISOS (1):
  scripts/deploy.sh

NUEVOS (1):
  uploads/shell.php
```

## Security considerations

When the baseline is signed with `-k`, any modification to the baseline file is detected on load, which prevents an attacker from editing the baseline to conceal changes. Signature comparison is performed in constant time.

## Testing

```bash
pytest
```

---
---

# File Integrity Checker (ES)

Herramienta de monitoreo de integridad de archivos (FIM). Registra una línea de base de hashes y permisos de un directorio y, en ejecuciones posteriores, reporta los archivos modificados, con permisos cambiados, nuevos o eliminados. La línea de base puede firmarse para detectar manipulación.

## Características

- Hashing SHA-256 de todos los archivos de un árbol de directorios.
- Control de permisos: los cambios de modo se reportan aunque el contenido no cambie.
- Línea de base firmada con HMAC opcional; cargar una base manipulada falla la verificación.
- Modo `watch` en tiempo real por polling.
- Salida en texto plano o JSON para el comando `check`.

## Uso

```bash
pstk fim baseline ./directorio -o baseline.json -k "clave-secreta"   # mediante el CLI unificado
python3 file_integrity.py baseline ./directorio -o baseline.json -k "clave-secreta"   # independiente
```

```bash
pstk fim check ./directorio -b baseline.json -k "clave-secreta"
pstk fim --json check ./directorio -b baseline.json
pstk fim watch ./directorio -i 2
```

## Comandos

| Comando | Descripción |
|---------|-------------|
| `baseline <dir>` | Crea una línea de base (`-o` ruta de salida, `-k` clave de firma) |
| `check <dir>` | Compara el estado actual contra una base (`-b` base, `-k` clave) |
| `watch <dir>` | Monitorea un directorio en tiempo real (`-i` intervalo en segundos) |

Categorías de cambio reportadas por `check`: modificados, permisos, nuevos, eliminados.

## Salida

```
MODIFICADOS (1):
  config/app.conf

PERMISOS (1):
  scripts/deploy.sh

NUEVOS (1):
  uploads/shell.php
```

## Consideraciones de seguridad

Cuando la base se firma con `-k`, cualquier modificación del archivo de base se detecta al cargarlo, lo que impide que un atacante edite la base para ocultar cambios. La comparación de la firma se realiza en tiempo constante.

## Tests

```bash
pytest
```
