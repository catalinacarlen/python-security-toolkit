# 05 · Pensar un algoritmo

> Material de referencia basado en los apuntes de la materia.

Antes de escribir código conviene **diseñar el algoritmo**: entender el problema, identificar los datos de entrada, el proceso y la salida esperada.

## Metodología

1. **Comprender el problema:** qué se pide exactamente.
2. **Identificar entradas y salidas:** qué datos llegan y qué resultado se espera.
3. **Diseñar el proceso:** la secuencia de pasos (con decisiones y ciclos si hacen falta).
4. **Verificar (prueba de escritorio):** seguir el algoritmo a mano con datos de ejemplo para confirmar que da el resultado correcto.
5. **Evaluar eficiencia:** cuantos menos recursos (memoria, tiempo) use, mejor.

## Patrones clásicos

- **Contador:** variable que se incrementa de a uno (`cont += 1`). Ej.: contar intentos fallidos por IP.
- **Acumulador:** variable que suma valores (`suma += num`).
- **Máximos y mínimos:** se asume el primer elemento como máximo/mínimo y se recorre comparando.

```python
maximo = a[0]
for i in range(1, n):
    if a[i] > maximo:
        maximo = a[i]
```

## De la prueba de escritorio a los tests automáticos

La materia enseña a verificar un algoritmo con la **prueba de escritorio**: ejecutarlo a mano con datos conocidos y comprobar el resultado. Este toolkit lleva esa idea un paso más allá: cada herramienta tiene **tests automáticos** (`pytest`) que son exactamente eso — datos de entrada conocidos y el resultado esperado — pero ejecutados por la máquina en cada cambio. Es la versión profesional de la prueba de escritorio.

➡️ El patrón **contador** es el núcleo del `log_analyzer`; la verificación sistemática es lo que hacen los archivos `test_*.py` de cada herramienta.
