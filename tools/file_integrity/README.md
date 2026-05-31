# File Integrity Checker

Calcula el hash SHA-256 de los archivos de un directorio, guarda una línea de base y detecta archivos **modificados, nuevos o eliminados** en ejecuciones posteriores. Es un control de integridad de archivos (FIM) básico.

## Para qué sirve en seguridad
Un FIM detecta cambios no autorizados: malware que altera binarios, webshells subidas a un servidor o configuraciones manipuladas. Herramientas como Tripwire o AIDE hacen esto a escala.

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

## Conceptos aplicados
Funciones, diccionarios, lectura/escritura de archivos (JSON), recorrido de directorios y estructuras de decisión.

## Tests
```bash
pytest
```
