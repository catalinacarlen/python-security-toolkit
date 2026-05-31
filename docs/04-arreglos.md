# 04 · Arreglos (listas)

> Material de referencia basado en los apuntes de la materia.

Un **arreglo** es un grupo de posiciones de memoria relacionadas entre sí: mismo nombre, mismo tipo. En Python se implementan con **listas**.

```python
a = [1, 3, 5, 3, 4, 6]   # posiciones 0..5
x = a[2] * 4             # accede al tercer elemento (índice 2)
```

El primer elemento es la posición **0**; el de orden *i* es `a[i-1]`. El número entre corchetes (subíndice) debe ser un entero.

## Operaciones

| Operación | Cómo |
|---|---|
| Cargar | `a.append(valor)` dentro de un `for` |
| Recorrer | `for i in range(0, n): ... a[i]` |
| Mostrar | recorrer e imprimir cada `a[i]` |
| Buscar | `while` con doble condición (corta al encontrar) |
| Intercambiar | con variable auxiliar (`aux`) |
| Ordenar | `a.sort()` (creciente), `a.reverse()` (invertir) |

### Búsqueda con corte temprano

Para buscar conviene un `while`, no un `for`, porque permite **cortar al encontrar** sin recorrer todo el arreglo. La condición es doble: seguir mientras no se encuentre **y** mientras no se termine el arreglo.

```python
i = 0
while i < n and a[i] % 3 != 0:
    i += 1
if i == n:
    print("No hay múltiplos de 3")
else:
    print(f"Primer múltiplo de 3 en la posición {i}")
```

### Intercambio con auxiliar

```python
aux = a[pos2]
a[pos2] = a[pos1]
a[pos1] = aux
```

## Métodos útiles de listas

`insert(pos, valor)`, `sort()`, `reverse()`, `remove(valor)`, `pop(pos)`.

➡️ El **`port_scanner`** arma y ordena una lista de puertos abiertos; el **`log_analyzer`** ordena las IPs sospechosas de mayor a menor.
