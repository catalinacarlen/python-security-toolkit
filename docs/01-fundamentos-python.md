# 01 · Fundamentos de Python

> Material de referencia basado en los apuntes de la materia, presentado como documentación técnica del toolkit.

Python es un lenguaje **interpretado** (ejecuta las instrucciones a medida que las lee) y de **alto nivel**, creado a fines de los años 80 por Guido van Rossum. Su sintaxis es cercana al lenguaje natural, lo que lo hace ideal para empezar a programar y, además, lo convierte en el lenguaje estándar para automatización y herramientas de seguridad.

## Variables y tipos

Una variable es una posición de memoria donde se almacena un valor. Tipos básicos:

- `int` — entero (`num = 15`)
- `float` — real (`real = 0.2703`, admite notación científica `0.1e-3`)
- `str` — cadena de caracteres
- `bool` — booleano

Reglas de nombres: de 1 a 32 letras y/o dígitos, admite guion bajo, no puede empezar con número, y **distingue mayúsculas de minúsculas** (`contc` ≠ `contC`). No se pueden usar las palabras reservadas del lenguaje. La asignación se hace con `=`.

## Operadores

| Aritméticos | Relacionales | Lógicos |
|---|---|---|
| `+ - * /` | `> >= < <=` | `not` |
| `**` (exponente) | `==` (igual) | `and` |
| `//` (división entera) | `!=` (distinto) | `or` |
| `%` (módulo) | | |

Asignación abreviada: `x += 10` equivale a `x = x + 10` (la variable debe estar inicializada antes).

## Entrada / salida

- **`print()`** muestra por pantalla. Acepta varios argumentos separados por coma y caracteres de escape: `\n` (línea nueva), `\t` (tabulador), `\\`, `\"`.
- **`input()`** lee del teclado. Para datos numéricos hay que convertir: `a = int(input("Ingrese un número"))`. Si se omite el tipo, Python lo trata como string.

## Comentarios

- Una línea: `#` (con un espacio después).
- Varias líneas: entre `"""..."""`.

Documentar el código mejora la legibilidad — todas las herramientas de este repo usan **docstrings** (comentarios entre `"""`) para explicar qué hace cada función.

➡️ Estos fundamentos aparecen en **todas** las herramientas del toolkit.
