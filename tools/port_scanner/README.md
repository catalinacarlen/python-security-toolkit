# Port Scanner

TCP port scanner using `socket`, with concurrent scanning via `ThreadPoolExecutor`.

## What it does
Given a host and a range of ports, it reports which TCP ports are **open** (accepting connections) and the service usually associated with each.

## How it works (and why)
TCP connections start with a **three-way handshake** (SYN → SYN-ACK → ACK). The scanner tries to open a real connection to each port with `connect_ex()`: if it returns `0`, the handshake completed, which means **the port is open and a service is listening** behind it. If the port is closed or filtered, the connection fails or times out.

Scanning is **I/O-bound** — most of the time is spent *waiting* for network replies, not using the CPU. That's why a thread pool helps: while one socket waits for an answer, others can be checked in parallel, making the full scan much faster without complex code.

## Usage
```bash
python3 port_scanner.py 127.0.0.1            # ports 1-1024
python3 port_scanner.py scanme.nmap.org -s 20 -e 100 -t 1.0
```

## Example output
```
Scanning 127.0.0.1 (ports 1-1024)...

Open ports (2):
     22/tcp  SSH
    443/tcp  HTTPS
```

## Security relevance
Knowing which services a host exposes is the first step of any audit or reconnaissance (the *Identify* function of the NIST CSF). An unexpected open port can be an entry point.

## Concepts applied
Functions, loops, lists, decision structures, exception handling and sockets.

## Ethical notice
Use **only** on systems you own or have written authorization to test. Scanning third-party infrastructure without permission may be illegal.

## Tests
```bash
pytest
```

---
---

# Port Scanner (ES)

Escáner de puertos TCP con `socket` y barrido concurrente mediante `ThreadPoolExecutor`.

## Qué hace
Dado un host y un rango de puertos, informa qué puertos TCP están **abiertos** (aceptan conexiones) y el servicio que suele asociarse a cada uno.

## Cómo funciona (y por qué)
Las conexiones TCP comienzan con un **saludo de tres vías** (SYN → SYN-ACK → ACK). El escáner intenta abrir una conexión real a cada puerto con `connect_ex()`: si devuelve `0`, el saludo se completó, lo que significa que **el puerto está abierto y hay un servicio escuchando** detrás. Si el puerto está cerrado o filtrado, la conexión falla o expira.

El escaneo está **limitado por E/S**: la mayor parte del tiempo se *espera* la respuesta de red, no se usa la CPU. Por eso ayuda un pool de hilos: mientras un socket espera respuesta, se pueden comprobar otros en paralelo, acelerando el barrido sin complejizar el código.

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

## Para qué sirve en seguridad
Identificar qué servicios expone un host es el primer paso de cualquier auditoría o reconocimiento (la fase *Identificar* del NIST CSF). Un puerto abierto inesperado puede ser una puerta de entrada.

## Conceptos aplicados
Funciones, ciclos, listas, estructuras de decisión, manejo de excepciones y sockets.

## Aviso ético
Usar **solo** sobre sistemas propios o con autorización escrita. Escanear infraestructura ajena sin permiso puede ser ilegal.

## Tests
```bash
pytest
```
