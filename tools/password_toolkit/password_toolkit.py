"""Kit de contraseñas: fortaleza por entropía, generación segura, hashing y breach-check.

Capacidades:
- Fortaleza por **entropía (bits)** combinando el límite por pool de caracteres con
  una estimación estructural basada en un **diccionario** de tokens débiles
  (contraseñas, nombres y palabras comunes), con normalización leet y detección de
  años. El diccionario es ampliable con una wordlist externa (PSTK_WORDLIST).
- Estimación del **tiempo de crackeo** a una tasa de adivinanzas configurable.
- **Generador criptográficamente seguro** con el módulo `secrets`.
- **Verificación contra filtraciones** vía Have I Been Pwned usando el modelo de
  *k-anonymity*: nunca se envía la contraseña ni su hash completo, solo los 5
  primeros caracteres del SHA-1. Funciona con `urllib` (stdlib) y degrada con
  elegancia si no hay red.
- **Hashing**: SHA-256 (integridad) y PBKDF2-HMAC-SHA256 con salt (almacenamiento
  de contraseñas hecho como corresponde).

Manejo de la contraseña: si no se pasa por argumento, se solicita sin eco con
`getpass`. La contraseña no se escribe en disco ni en logs; solo se usa en memoria.

Solo librería estándar. Para uso en entornos autorizados.
"""

from __future__ import annotations

import argparse
import getpass
import gzip
import hashlib
import json
import math
import os
import re
import secrets
import string
from functools import lru_cache
from pathlib import Path
from urllib import error, request

NIVELES = {0: "Muy débil", 1: "Débil", 2: "Aceptable", 3: "Fuerte", 4: "Muy fuerte"}

# Tokens base notoriamente débiles: contraseñas comunes, nombres y palabras de uso
# frecuente (ES/EN). Se comparan en forma normalizada (minúsculas, sin leet). No es
# exhaustiva; el chequeo definitivo es contra HIBP (ver verificar_filtrada).
DEBILES = {
    # contraseñas y patrones de teclado
    "password", "passw0rd", "qwerty", "qwertyuiop", "asdfgh", "zxcvbn", "1q2w3e",
    "admin", "administrator", "root", "login", "welcome", "secret", "letmein",
    "abc", "abcd", "test", "guest", "changeme", "default", "master", "access",
    # afecto / palabras frecuentes
    "iloveyou", "teamo", "love", "amor", "princesa", "princess", "hola", "hello",
    "sunshine", "shadow", "monkey", "dragon", "ninja", "superman", "batman",
    # deportes / cultura popular
    "football", "futbol", "boca", "river", "barcelona", "madrid", "messi", "maradona",
    "pokemon", "starwars",
    # nombres comunes (ES/EN)
    "juan", "maria", "jose", "santiago", "santi", "sofia", "lucia", "mateo", "martina",
    "valentina", "agustin", "camila", "carlos", "laura", "pedro", "pablo", "diego",
    "john", "michael", "jessica", "ashley", "daniel", "david", "sarah", "michelle",
    # estaciones y meses (ES/EN)
    "verano", "invierno", "otono", "primavera", "summer", "winter", "spring", "autumn",
    "enero", "marzo", "agosto", "diciembre", "january", "march", "august", "december",
}

# Sustituciones "leet" más comunes, para no dejar pasar P4ssw0rd, Pr1nc3sa, etc.
_LEET = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t",
                       "@": "a", "$": "s", "8": "b"})

# Secuencias usadas para penalizar (teclado y alfabeto/numérica).
_SECUENCIAS = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm"]


def _tamano_alfabeto(password: str) -> int:
    """Estima el tamaño del espacio de caracteres (pool) que usa la contraseña."""
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    if any(c == " " for c in password):
        pool += 1
    # Caracteres fuera de ASCII imprimible (acentos, etc.): aporte conservador.
    if any(ord(c) > 127 for c in password):
        pool += 100
    return pool


def _normalizar(texto: str) -> str:
    """Pasa a minúsculas y revierte sustituciones leet para comparar contra el diccionario."""
    return texto.lower().translate(_LEET)


_DIR_DATOS = Path(__file__).resolve().parent / "data"


def _leer_wordlist(ruta: Path) -> set[str]:
    """Lee una wordlist (.txt o .gz), una entrada por línea, normalizada."""
    abrir = gzip.open if str(ruta).endswith(".gz") else open
    try:
        with abrir(ruta, "rt", encoding="utf-8", errors="ignore") as archivo:
            return {
                _normalizar(linea.strip())
                for linea in archivo
                if linea.strip() and not linea.startswith("#")
            }
    except OSError:
        return set()


@lru_cache(maxsize=1)
def _diccionario() -> frozenset:
    """Diccionario de tokens débiles, cargado una sola vez (carga perezosa).

    Combina la lista base embebida (DEBILES), el archivo curado `data/common_passwords.txt`
    si existe, y una wordlist externa indicada por la variable de entorno PSTK_WORDLIST
    (útil para apuntar a un diccionario grande como rockyou). Acepta .txt o .gz.
    """
    palabras = set(DEBILES)
    por_defecto = _DIR_DATOS / "common_passwords.txt"
    if por_defecto.exists():
        palabras |= _leer_wordlist(por_defecto)
    externa = os.environ.get("PSTK_WORDLIST")
    if externa:
        palabras |= _leer_wordlist(Path(externa))
    return frozenset(p for p in palabras if len(p) >= 3)


def _palabras_embebidas(normalizado: str, largo_min: int = 4) -> list[tuple[int, int]]:
    """Devuelve rangos [inicio, fin) de palabras del diccionario embebidas, sin solaparse.

    Estrategia voraz: prioriza las coincidencias más largas. Como la contraseña es corta,
    el barrido de subcadenas contra el set es barato.
    """
    dic = _diccionario()
    n = len(normalizado)
    encontradas: list[tuple[int, int, int]] = []
    for i in range(n):
        for j in range(n, i + largo_min - 1, -1):
            if normalizado[i:j] in dic:
                encontradas.append((j - i, i, j))
                break
    encontradas.sort(reverse=True)
    rangos: list[tuple[int, int]] = []
    ocupado = [False] * n
    for _largo, i, j in encontradas:
        if not any(ocupado[i:j]):
            for k in range(i, j):
                ocupado[k] = True
            rangos.append((i, j))
    return rangos


def _tiene_secuencia(password: str, largo: int = 4) -> bool:
    """True si contiene una secuencia ascendente/descendente de `largo` o más."""
    p = _normalizar(password)
    for seq in _SECUENCIAS:
        for i in range(len(seq) - largo + 1):
            fragmento = seq[i:i + largo]
            if fragmento in p or fragmento[::-1] in p:
                return True
    return False


def _entropia_estructural(password: str) -> float | None:
    """Estima la entropía si la contraseña contiene palabras de diccionario.

    Detecta palabras/nombres del diccionario embebidas en la contraseña (con
    normalización leet) y modela cada una como un patrón humano de ~14 bits, en lugar
    de su entropía aleatoria. El resto de los caracteres (letras sueltas, dígitos,
    símbolos) aporta su propia entropía. Devuelve la estimación, o None si no hay
    ninguna palabra reconocida.
    """
    normalizado = _normalizar(password)
    rangos = _palabras_embebidas(normalizado)
    if not rangos:
        return None

    cubierto = [False] * len(password)
    bits = 0.0
    for inicio, fin in rangos:
        bits += 14.0                              # palabra de un diccionario común
        for k in range(inicio, fin):
            cubierto[k] = True
        if any(password[k].isupper() for k in range(inicio, fin)):
            bits += 1.0                           # variación de mayúsculas: ~1 bit

    resto = "".join(c for k, c in enumerate(password) if not cubierto[k])
    for run in re.findall(r"\d+", resto):         # dígitos: suelen ser años/fechas
        bits += min(len(run) * math.log2(10), 10.0)
    bits += sum(math.log2(26) for c in resto if c.isalpha())      # letras sueltas
    bits += sum(2.0 for c in resto if c in string.punctuation)    # símbolos
    bits += sum(1.0 for c in resto if c == " ")
    return bits


def _penalizacion_generica(password: str) -> float:
    """Bits a restar por debilidades estructurales no cubiertas por el patrón."""
    castigo = 0.0
    repeticiones = re.findall(r"((.)\2{2,})", password)   # corridas de 3+ iguales
    if repeticiones:                                      # penaliza según la corrida más larga
        castigo += max(len(r[0]) for r in repeticiones) * 3
    if _tiene_secuencia(password):                        # secuencias de teclado/alfabeto
        castigo += 12
    if re.fullmatch(r"\d+", password):                    # solo dígitos
        castigo += 10
    if re.search(r"(?:18|19|20)\d\d", password):          # un año embebido
        castigo += 7
    return castigo


def entropia_bits(password: str) -> float:
    """Entropía estimada en bits.

    Combina dos estimaciones y toma la más pesimista: (1) un límite superior por
    "pool de caracteres" (len * log2(alfabeto)); (2) una estimación estructural para
    patrones humanos reconocibles (palabra común + año + símbolos). Sobre ese mínimo
    se aplican penalizaciones genéricas (repeticiones, secuencias, años).

    El resultado es una cota de resistencia a fuerza bruta; no modela todos los
    ataques por diccionario, por lo que conviene complementarlo con verificar_filtrada.
    """
    if not password:
        return 0.0
    pool = _tamano_alfabeto(password)
    bruta = len(password) * math.log2(pool) if pool else 0.0
    estructural = _entropia_estructural(password)
    estimacion = bruta if estructural is None else min(bruta, estructural)
    return max(0.0, estimacion - _penalizacion_generica(password))


def tiempo_crackeo(bits: float, adivinanzas_por_segundo: float = 1e10) -> str:
    """Traduce bits de entropía a un tiempo medio de crackeo legible.

    Por defecto asume 10^10 intentos/seg (GPU moderna contra un hash rápido).
    """
    combinaciones = 2 ** bits
    segundos = (combinaciones / 2) / adivinanzas_por_segundo
    if segundos < 1:
        return "instantáneo"
    unidades = [
        ("siglos", 60 * 60 * 24 * 365 * 100),
        ("años", 60 * 60 * 24 * 365),
        ("días", 60 * 60 * 24),
        ("horas", 60 * 60),
        ("minutos", 60),
        ("segundos", 1),
    ]
    for nombre, factor in unidades:
        if segundos >= factor:
            cantidad = segundos / factor
            if nombre == "siglos" and cantidad > 1000:
                return "miles de siglos"
            return f"{cantidad:.0f} {nombre}"
    return "instantáneo"


def evaluar_fortaleza(password: str) -> tuple[int, str]:
    """Devuelve (puntaje 0-4, etiqueta) derivado de la entropía en bits.

    Umbrales prácticos: <28 muy débil, <36 débil, <60 aceptable, <128 fuerte,
    >=128 muy fuerte.
    """
    bits = entropia_bits(password)
    if bits < 28:
        puntaje = 0
    elif bits < 36:
        puntaje = 1
    elif bits < 60:
        puntaje = 2
    elif bits < 128:
        puntaje = 3
    else:
        puntaje = 4
    return puntaje, NIVELES[puntaje]


def generar_password(longitud: int = 16) -> str:
    """Genera una contraseña aleatoria segura con `secrets`.

    Garantiza al menos un carácter de cada clase (minúscula, mayúscula, dígito,
    símbolo) para que el resultado sea siempre robusto.
    """
    if longitud < 4:
        raise ValueError("La longitud mínima es 4 para incluir todas las clases.")
    clases = [string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation]
    caracteres = [secrets.choice(clase) for clase in clases]
    alfabeto = "".join(clases)
    caracteres += [secrets.choice(alfabeto) for _ in range(longitud - len(caracteres))]
    secrets.SystemRandom().shuffle(caracteres)
    return "".join(caracteres)


def hashear(password: str, salt: str | None = None) -> str:
    """SHA-256 hexadecimal con salt opcional.

    Útil para verificar integridad, NO para almacenar contraseñas (es rápido).
    Para almacenamiento usar derivar() (PBKDF2).
    """
    dato = (salt or "") + password
    return hashlib.sha256(dato.encode("utf-8")).hexdigest()


def derivar(password: str, salt: bytes | None = None, iteraciones: int = 200_000) -> str:
    """Deriva la contraseña con PBKDF2-HMAC-SHA256 (lento + salt).

    Así se guardan contraseñas de verdad: un algoritmo deliberadamente lento y un
    salt aleatorio por usuario. Devuelve un string autocontenido
    "pbkdf2_sha256$iteraciones$salt_hex$hash_hex" verificable con verificar_derivado().
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iteraciones)
    return f"pbkdf2_sha256${iteraciones}${salt.hex()}${dk.hex()}"


def verificar_derivado(password: str, codificado: str) -> bool:
    """Verifica una contraseña contra un valor producido por derivar()."""
    try:
        algoritmo, iteraciones, salt_hex, hash_hex = codificado.split("$")
    except ValueError:
        return False
    if algoritmo != "pbkdf2_sha256":
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iteraciones))
    return secrets.compare_digest(dk.hex(), hash_hex)  # comparación en tiempo constante


def verificar_filtrada(password: str, timeout: float = 5.0) -> int | None:
    """Cuenta cuántas veces apareció la contraseña en filtraciones, vía HIBP.

    Usa *k-anonymity*: se calcula el SHA-1 de la contraseña y SOLO se envían los
    primeros 5 caracteres del hash al endpoint de rangos. La API responde con
    todos los sufijos que comparten ese prefijo; la coincidencia se resuelve
    localmente. La contraseña nunca sale del equipo.

    Devuelve la cantidad de apariciones (0 si no aparece) o None si no se pudo
    consultar (sin red, timeout, etc.).
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefijo, sufijo = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefijo}"
    try:
        req = request.Request(url, headers={"User-Agent": "python-security-toolkit"})
        with request.urlopen(req, timeout=timeout) as resp:
            cuerpo = resp.read().decode("utf-8")
    except (error.URLError, TimeoutError, OSError):
        return None
    for linea in cuerpo.splitlines():
        suf, _, conteo = linea.partition(":")
        if suf.strip() == sufijo:
            return int(conteo.strip())
    return 0


def auditar(password: str, offline: bool = False) -> dict:
    """Reúne todas las señales en un solo reporte (ideal para salida --json)."""
    bits = entropia_bits(password)
    puntaje, etiqueta = evaluar_fortaleza(password)
    filtrada = None if offline else verificar_filtrada(password)
    return {
        "longitud": len(password),
        "entropia_bits": round(bits, 1),
        "fortaleza": etiqueta,
        "puntaje": puntaje,
        "tiempo_crackeo_estimado": tiempo_crackeo(bits),
        "apariciones_en_filtraciones": filtrada,
        "comprometida": (filtrada or 0) > 0 if filtrada is not None else None,
    }


_AYUDA_PWD = ("Contraseña. Si se omite, se solicita de forma segura (sin eco). "
              "Pasarla como argumento es inseguro: queda en el historial del shell.")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Kit de contraseñas: auditar, evaluar, generar, hashear.")
    parser.add_argument("--json", action="store_true", help="Salida en formato JSON")
    parser.add_argument("--wordlist", default=None,
                        help="Wordlist externa (.txt o .gz) para ampliar el diccionario de débiles")
    sub = parser.add_subparsers(dest="accion", required=True)

    p_aud = sub.add_parser("auditar", help="Reporte completo: entropía, crack-time y filtraciones (HIBP)")
    p_aud.add_argument("password", nargs="?", help=_AYUDA_PWD)
    p_aud.add_argument("--offline", action="store_true", help="No consultar HIBP (sin red)")

    p_eval = sub.add_parser("evaluar", help="Evalúa la fortaleza por entropía")
    p_eval.add_argument("password", nargs="?", help=_AYUDA_PWD)

    p_gen = sub.add_parser("generar", help="Genera una contraseña segura")
    p_gen.add_argument("-l", "--longitud", type=int, default=16)

    p_hash = sub.add_parser("hashear", help="Calcula el hash (sha256 o pbkdf2)")
    p_hash.add_argument("password", nargs="?", help=_AYUDA_PWD)
    p_hash.add_argument("--salt", default=None)
    p_hash.add_argument("--algoritmo", choices=["sha256", "pbkdf2"], default="sha256")

    p_pwned = sub.add_parser("filtrada", help="Verifica la contraseña contra HIBP (k-anonymity)")
    p_pwned.add_argument("password", nargs="?", help=_AYUDA_PWD)
    return parser.parse_args()


def _resolver_password(valor: str | None) -> str:
    """Devuelve la contraseña dada por argumento o, si falta, la pide sin eco."""
    if valor is not None:
        return valor
    return getpass.getpass("Contraseña: ")


def _imprimir(datos: dict, como_json: bool) -> None:
    if como_json:
        print(json.dumps(datos, ensure_ascii=False, indent=2))
    else:
        for clave, valor in datos.items():
            print(f"{clave:>28}: {valor}")


def main() -> None:
    args = _parse_args()
    if args.wordlist:                              # apuntar a un diccionario externo
        os.environ["PSTK_WORDLIST"] = args.wordlist
        _diccionario.cache_clear()
    if args.accion == "auditar":
        _imprimir(auditar(_resolver_password(args.password), offline=args.offline), args.json)
    elif args.accion == "evaluar":
        password = _resolver_password(args.password)
        puntaje, etiqueta = evaluar_fortaleza(password)
        bits = entropia_bits(password)
        if args.json:
            _imprimir({"fortaleza": etiqueta, "puntaje": puntaje, "entropia_bits": round(bits, 1),
                       "tiempo_crackeo_estimado": tiempo_crackeo(bits)}, True)
        else:
            print(f"Fortaleza: {etiqueta} ({puntaje}/4) — {bits:.1f} bits — crackeo: {tiempo_crackeo(bits)}")
    elif args.accion == "generar":
        pwd = generar_password(args.longitud)
        _imprimir({"password": pwd}, True) if args.json else print(pwd)
    elif args.accion == "hashear":
        password = _resolver_password(args.password)
        valor = derivar(password) if args.algoritmo == "pbkdf2" else hashear(password, args.salt)
        _imprimir({"algoritmo": args.algoritmo, "hash": valor}, True) if args.json else print(valor)
    elif args.accion == "filtrada":
        n = verificar_filtrada(_resolver_password(args.password))
        if n is None:
            datos: dict[str, object] = {"estado": "no verificable (sin red)"}
        elif n == 0:
            datos = {"estado": "no aparece en filtraciones conocidas", "apariciones": 0}
        else:
            datos = {"estado": "COMPROMETIDA", "apariciones": n}
        if args.json:
            _imprimir(datos, True)
        else:
            extra = f" ({datos['apariciones']} apariciones)" if datos.get("apariciones") else ""
            print(f"{datos['estado']}{extra}")


if __name__ == "__main__":
    main()
