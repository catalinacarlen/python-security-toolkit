# Password Toolkit

Tres utilidades en una: **evaluador** de fortaleza, **generador** criptográficamente seguro (`secrets`) y **hashing** con `hashlib`.

## Para qué sirve en seguridad
Las contraseñas débiles son una de las principales causas de compromiso. Esta herramienta muestra cómo medir su fortaleza, generar contraseñas robustas y entender el hashing.

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
`SHA-256` sirve para verificar integridad, **no** para guardar contraseñas en producción: para eso se usan algoritmos lentos y con *salt* como **bcrypt, scrypt o Argon2**. El salt evita que dos contraseñas iguales tengan el mismo hash.

## Conceptos aplicados
Strings, funciones, estructuras de decisión, operadores lógicos y módulos (`secrets`, `hashlib`, `string`).

## Tests
```bash
pytest
```
