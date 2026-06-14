# Port Scanner

Concurrent TCP port scanner with **banner grabbing** and **service fingerprinting**. It doesn't just say "port 22 is open" — it reads what the service announces and tells you what's *actually* running, with rate/concurrency control and JSON output.

## What it does
Given a host and a port range, it reports open ports, grabs each service's banner, infers the real service from that banner (falling back to the well-known port name), and can emit everything as JSON.

## How it works (and why)
- **Open detection.** TCP starts with a three-way handshake (SYN → SYN-ACK → ACK). `connect_ex()` returns `0` only when the handshake completes, i.e. a service is listening.
- **Banner grabbing.** Many services greet you the moment you connect (SSH, FTP, SMTP). The scanner reads that greeting; for silent ones like HTTP it sends a tiny `HEAD` request and reads the reply. The banner is what reveals *versions* — and versions are what map to known CVEs.
- **Fingerprinting over port numbers.** The port number is only a convention; anyone can run SSH on 40000. So the service is inferred from the **banner signature first** (`SSH-2.0…`, `220 …FTP`, `HTTP/1.1…`) and only falls back to the port-name table when there's no banner. That's the difference between guessing and identifying.
- **Rate and concurrency.** Scanning is I/O-bound (mostly waiting on the network), so a thread pool (`-W`) speeds it up massively. A `-d` delay throttles banner grabs to stay quiet and avoid tripping defenses.

## Usage
```bash
python3 port_scanner.py 127.0.0.1                  # ports 1-1024, with banners
python3 port_scanner.py scanme.nmap.org -s 20 -e 100 -t 1.0
python3 port_scanner.py 10.0.0.5 -W 200 -d 0.1     # 200 workers, 0.1s throttle
python3 port_scanner.py 10.0.0.5 --no-banner       # fast: open/closed only
python3 port_scanner.py 10.0.0.5 --json            # structured output
```

## Example output
```
Puertos abiertos en 127.0.0.1 (2):

     22/tcp  SSH      ── SSH-2.0-OpenSSH_9.6
    443/tcp  HTTPS
```

## Security relevance
Mapping exposed services is the first step of any audit or recon (the *Identify* function of NIST CSF). The banner often leaks the software **version**, which is what turns "a port is open" into "this exact version has a known vulnerability".

## Concepts applied
Sockets, banner grabbing, regular expressions, thread pools (`ThreadPoolExecutor`), rate limiting and JSON output.

## Ethical notice
Use **only** on systems you own or have written authorization to test. Scanning third-party infrastructure without permission may be illegal.

## Tests
```bash
pytest
```

---
---

# Port Scanner (ES)

Escáner de puertos TCP concurrente con **banner grabbing** y **fingerprinting de servicio**. No se queda en "el puerto 22 está abierto": lee lo que el servicio anuncia y te dice qué corre *de verdad*, con control de rate/concurrencia y salida JSON.

## Qué hace
Dado un host y un rango de puertos, informa los puertos abiertos, captura el banner de cada servicio, infiere el servicio real a partir de ese banner (y cae al nombre del puerto conocido si no hay banner), y puede emitir todo como JSON.

## Cómo funciona (y por qué)
- **Detección de abierto.** TCP arranca con un saludo de tres vías (SYN → SYN-ACK → ACK). `connect_ex()` devuelve `0` solo cuando el saludo se completa, es decir, hay un servicio escuchando.
- **Banner grabbing.** Muchos servicios te saludan apenas te conectás (SSH, FTP, SMTP). El escáner lee ese saludo; para los mudos como HTTP envía un pequeño `HEAD` y lee la respuesta. El banner es lo que revela *versiones* — y las versiones son las que se mapean a CVEs conocidas.
- **Fingerprinting por encima del número de puerto.** El número de puerto es solo una convención; cualquiera puede correr SSH en el 40000. Por eso el servicio se infiere **primero por la firma del banner** (`SSH-2.0…`, `220 …FTP`, `HTTP/1.1…`) y solo cae a la tabla de puertos cuando no hay banner. Esa es la diferencia entre adivinar e identificar.
- **Rate y concurrencia.** El escaneo está limitado por E/S (casi todo es esperar la red), así que un pool de hilos (`-W`) lo acelera muchísimo. Un retardo `-d` modera los banners para ser más sigiloso y no disparar defensas.

## Uso
```bash
python3 port_scanner.py 127.0.0.1                  # puertos 1-1024, con banners
python3 port_scanner.py scanme.nmap.org -s 20 -e 100 -t 1.0
python3 port_scanner.py 10.0.0.5 -W 200 -d 0.1     # 200 hilos, 0.1s de retardo
python3 port_scanner.py 10.0.0.5 --no-banner       # rápido: solo abierto/cerrado
python3 port_scanner.py 10.0.0.5 --json            # salida estructurada
```

## Ejemplo de salida
```
Puertos abiertos en 127.0.0.1 (2):

     22/tcp  SSH      ── SSH-2.0-OpenSSH_9.6
    443/tcp  HTTPS
```

## Para qué sirve en seguridad
Mapear los servicios expuestos es el primer paso de cualquier auditoría o reconocimiento (la fase *Identificar* del NIST CSF). El banner suele filtrar la **versión** del software, que es lo que convierte "hay un puerto abierto" en "esta versión exacta tiene una vulnerabilidad conocida".

## Conceptos aplicados
Sockets, banner grabbing, expresiones regulares, pools de hilos (`ThreadPoolExecutor`), limitación de rate y salida JSON.

## Aviso ético
Usar **solo** sobre sistemas propios o con autorización escrita. Escanear infraestructura ajena sin permiso puede ser ilegal.

## Tests
```bash
pytest
```
