# Port Scanner

Escáner de puertos TCP con `socket` y barrido concurrente mediante `ThreadPoolExecutor`.

## Para qué sirve en seguridad
Identificar qué servicios expone un host es el primer paso de cualquier auditoría o reconocimiento (la fase *Identificar* del NIST CSF). Un puerto abierto inesperado puede ser una puerta de entrada.

## Uso
```bash
python3 port_scanner.py 127.0.0.1            # puertos 1-1024
python3 port_scanner.py scanme.nmap.org -s 20 -e 100 -t 1.0
```

## Ejemplo de salida
```
Escaneando 127.0.0.1 (puertos 1-1024)...

Puertos abiertos (2):
     22/tcp  SSH
    443/tcp  HTTPS
```

## Conceptos aplicados
Funciones, ciclos, listas, estructuras de decisión, manejo de excepciones y sockets.

## Aviso ético
Usar **solo** sobre sistemas propios o con autorización escrita. Escanear infraestructura ajena sin permiso puede ser ilegal.

## Tests
```bash
pytest
```
