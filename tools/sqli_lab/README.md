# SQL Injection Lab

Laboratorio **local y controlado** (SQLite en memoria) que compara una consulta de login **vulnerable** (concatenando strings) contra una **segura** (parametrizada), y demuestra cómo un payload de inyección burla a la primera pero no a la segunda.

## Para qué sirve en seguridad
SQL Injection sigue en el **OWASP Top 10**. Entender por qué ocurre y cómo se previene es fundamental para el desarrollo seguro. Este lab lo muestra de forma reproducible.

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
