# 03 · Funciones

> Material de referencia basado en los apuntes de la materia.

Una función es un "mini programa dentro de un programa": agrupa varias sentencias bajo un solo nombre, permite dividir un proyecto grande en módulos pequeños y se puede **reutilizar** en este y en otros programas. Encapsula un cálculo para usarlo después sin preocuparse por su implementación.

## Definición

```python
def nombre(param1, param2):
    cuerpo de la función
    return expresion
```

- **Parámetros formales:** los nombres que recibe la función. Puede no tener ninguno.
- **Cuerpo:** las líneas indentadas. Una línea pertenece al cuerpo mientras esté indentada.
- **`return`:** devuelve un valor al programa principal. Si no devuelve nada, puede omitirse.

## Llamada

La función debe ser **llamada** para ejecutarse. Si devuelve un valor, en la llamada se asigna a una variable:

```python
def factorial(n):
    h = 1
    for i in range(1, n + 1):
        h = h * i
    return h

f = factorial(5)   # f vale 120
```

## Ámbito (scope)

Las variables declaradas dentro de una función son **locales**: no se ven en el programa principal y pierden su valor al salir, salvo que se devuelvan con `return`. Una función **no puede** alterar directamente una variable del programa principal, solo su copia temporal.

Los parámetros en la definición y en la llamada deben ir en el **mismo orden**, pero sus nombres pueden no coincidir.

➡️ Todo el toolkit está construido con funciones puras y testeables: `scan_port()`, `evaluar_fortaleza()`, `hash_archivo()`, `login_seguro()`, etc. Esa separación es justamente lo que permite escribir **tests automáticos**.
