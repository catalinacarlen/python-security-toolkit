# Log Analyzer

Analiza un `auth.log` de Linux, cuenta los intentos fallidos de login por IP y marca las que superan un umbral: el patrón típico de un ataque de **fuerza bruta** por SSH.

## Para qué sirve en seguridad
La detección de fuerza bruta sobre logs es una tarea diaria en un SOC y la base de las reglas de un SIEM. Esta herramienta automatiza ese análisis.

## Uso
```bash
python3 log_analyzer.py sample_auth.log            # umbral por defecto: 5
python3 log_analyzer.py /var/log/auth.log -u 10
```

## Ejemplo de salida
```
IPs sospechosas (>= 5 intentos fallidos):

  192.168.0.5      6 intentos
```

## Cómo defenderse
Limitar intentos con `fail2ban`, usar claves SSH en vez de contraseñas, y cambiar el puerto por defecto reduce el ruido.

## Conceptos aplicados
Expresiones regulares, lectura de archivos, diccionarios, ciclos y ordenamiento.

## Tests
```bash
pytest
```
