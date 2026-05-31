# 02 · Estructuras de control

> Material de referencia basado en los apuntes de la materia.

Un **algoritmo** es un conjunto de reglas ordenadas en forma lógica para resolver un problema. Sus características: preciso, definido, finito, con presentación formal, correcto (se verifica con *prueba de escritorio*) y eficiente (cuantos menos recursos use, mejor).

Las instrucciones de un algoritmo se organizan en tres tipos de estructuras.

## 1. Secuenciales

Se ejecutan una después de otra: declarar variables, asignar (`=`), leer (`input`) y mostrar (`print`).

## 2. De decisión (selección)

Permiten ejecutar u omitir acciones según una condición (que debe evaluar a verdadero o falso).

- **Condicional** (`if`): ejecuta acciones solo si la condición es verdadera.
- **Alternativa** (`if/else`): unas acciones si es verdadera, otras si es falsa.

```python
if numero < 0:
    numero = numero * -1   # valor absoluto
print(numero)
```

## 3. De repetición (ciclos)

Ejecutan un bloque varias veces.

- **`while` (mientras):** repite mientras se cumpla una condición. La variable de la condición debe tener un valor antes de entrar **y** modificarse dentro del ciclo, o se produce un *loop infinito*.
- **`for` (para):** usa una variable de control con valor inicial, incremento/decremento y valor final.

```python
for i in range(0, 10):      # 0,1,...,9
    print(i)

i = 0
while i < n and a[i] % 3 != 0:   # búsqueda con corte temprano
    i += 1
```

➡️ El **`log_analyzer`** recorre líneas con ciclos y decide con `if`; el **`file_integrity`** recorre directorios; el **`port_scanner`** itera sobre un rango de puertos.
