# Port Scanner

Concurrent TCP port scanner with banner grabbing and service fingerprinting. For each open port it attempts to read the service banner and identifies the service from that banner, with fallback to the well-known port mapping.

## Features

- Concurrent scanning of a configurable port range via a thread pool.
- Banner grabbing on open ports, including an HTTP probe for services that do not greet on connect.
- Service identification from the banner signature, independent of the port number.
- Configurable concurrency and inter-banner delay (rate limiting).
- Plain-text or JSON output.

## Usage

```bash
pstk scan 127.0.0.1                                # via the unified CLI
python3 port_scanner.py 127.0.0.1                  # as a standalone script
```

```bash
pstk scan scanme.nmap.org -s 20 -e 100 -t 1.0
pstk scan 10.0.0.5 -W 200 -d 0.1                   # 200 workers, 0.1s delay
pstk scan 10.0.0.5 --no-banner                     # open/closed only
pstk scan 10.0.0.5 --json
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `host` | Target host or IP | — |
| `-s`, `--start` | First port | 1 |
| `-e`, `--end` | Last port | 1024 |
| `-t`, `--timeout` | Per-port timeout (seconds) | 0.5 |
| `-W`, `--workers` | Concurrent threads | 100 |
| `-d`, `--delay` | Delay between banner grabs (seconds) | 0.0 |
| `--no-banner` | Skip banner grabbing | off |
| `--json` | JSON output | off |

## Output

```
Puertos abiertos en 127.0.0.1 (2):

     22/tcp  SSH      ── SSH-2.0-OpenSSH_9.6
    443/tcp  HTTPS
```

## Security considerations

A service banner frequently exposes the software version, which can be correlated with known vulnerabilities. Scan only systems you own or are explicitly authorized to test; scanning third-party infrastructure without permission may be unlawful.

## Testing

```bash
pytest
```

---
---

# Port Scanner (ES)

Escáner de puertos TCP concurrente con banner grabbing y fingerprinting de servicio. Por cada puerto abierto intenta leer el banner del servicio e identifica el servicio a partir de ese banner, con respaldo en el mapeo de puertos conocidos.

## Características

- Escaneo concurrente de un rango de puertos configurable mediante un pool de hilos.
- Banner grabbing en puertos abiertos, incluido un sondeo HTTP para servicios que no saludan al conectar.
- Identificación del servicio por la firma del banner, independiente del número de puerto.
- Concurrencia y retardo entre banners configurables (limitación de rate).
- Salida en texto plano o JSON.

## Uso

```bash
pstk scan 127.0.0.1                                # mediante el CLI unificado
python3 port_scanner.py 127.0.0.1                  # como script independiente
```

```bash
pstk scan scanme.nmap.org -s 20 -e 100 -t 1.0
pstk scan 10.0.0.5 -W 200 -d 0.1                   # 200 hilos, 0.1s de retardo
pstk scan 10.0.0.5 --no-banner                     # solo abierto/cerrado
pstk scan 10.0.0.5 --json
```

## Opciones

| Opción | Descripción | Por defecto |
|--------|-------------|-------------|
| `host` | Host o IP objetivo | — |
| `-s`, `--start` | Puerto inicial | 1 |
| `-e`, `--end` | Puerto final | 1024 |
| `-t`, `--timeout` | Timeout por puerto (segundos) | 0.5 |
| `-W`, `--workers` | Hilos concurrentes | 100 |
| `-d`, `--delay` | Retardo entre banners (segundos) | 0.0 |
| `--no-banner` | Omitir banner grabbing | off |
| `--json` | Salida JSON | off |

## Salida

```
Puertos abiertos en 127.0.0.1 (2):

     22/tcp  SSH      ── SSH-2.0-OpenSSH_9.6
    443/tcp  HTTPS
```

## Consideraciones de seguridad

El banner de un servicio suele exponer la versión del software, que puede correlacionarse con vulnerabilidades conocidas. Escanee únicamente sistemas propios o sobre los que tenga autorización explícita; escanear infraestructura de terceros sin permiso puede ser ilegal.

## Tests

```bash
pytest
```
