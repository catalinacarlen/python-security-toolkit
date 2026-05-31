"""Kit de contraseñas: evalúa fortaleza, genera contraseñas seguras y hashea.

- Evaluador de fortaleza por longitud y variedad de caracteres.
- Generador criptográficamente seguro con el módulo `secrets`.
- Hashing con SHA-256 (con nota sobre el salting).

Conceptos de la materia aplicados: strings, funciones, estructuras de decisión
y operadores lógicos.
"""

from __future__ import annotations

import argparse
import hashlib
import secrets
import string

NIVELES = {0: "Muy débil", 1: "Débil", 2: "Aceptable", 3: "Fuerte", 4: "Muy fuerte"}


def evaluar_fortaleza(password: str) -> tuple[int, str]:
    """Devuelve (puntaje 0-4, etiqueta) según longitud y tipos de caracteres."""
    puntaje = 0
    if len(password) >= 8:
        puntaje += 1
    if len(password) >= 12:
        puntaje += 1
    tiene_minuscula = any(c.islower() for c in password)
    tiene_mayuscula = any(c.isupper() for c in password)
    tiene_digito = any(c.isdigit() for c in password)
    tiene_simbolo = any(c in string.punctuation for c in password)
    variedad = sum([tiene_minuscula, tiene_mayuscula, tiene_digito, tiene_simbolo])
    if variedad >= 3:
        puntaje += 1
    if variedad == 4:
        puntaje += 1
    puntaje = min(puntaje, 4)
    return puntaje, NIVELES[puntaje]


def generar_password(longitud: int = 16) -> str:
    """Genera una contraseña aleatoria segura con `secrets`.

    Garantiza al menos un carácter de cada clase (minúscula, mayúscula, dígito,
    símbolo) para que el resultado sea siempre robusto.
    """
    if longitud < 4:
        raise ValueError("La longitud mínima es 4 para incluir todas las clases.")
    clases = [string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation]
    # Un carácter obligatorio de cada clase...
    caracteres = [secrets.choice(clase) for clase in clases]
    # ...y el resto desde el alfabeto completo.
    alfabeto = "".join(clases)
    caracteres += [secrets.choice(alfabeto) for _ in range(longitud - len(caracteres))]
    secrets.SystemRandom().shuffle(caracteres)
    return "".join(caracteres)


def hashear(password: str, salt: str | None = None) -> str:
    """Devuelve el hash SHA-256 en hexadecimal, con salt opcional.

    Nota de seguridad: SHA-256 sirve para verificar integridad, pero para
    almacenar contraseñas en producción conviene un algoritmo lento y con salt
    como bcrypt, scrypt o Argon2. El salt evita que dos contraseñas iguales
    produzcan el mismo hash.
    """
    dato = (salt or "") + password
    return hashlib.sha256(dato.encode("utf-8")).hexdigest()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Kit de contraseñas: evaluar, generar y hashear.")
    sub = parser.add_subparsers(dest="accion", required=True)

    p_eval = sub.add_parser("evaluar", help="Evalúa la fortaleza de una contraseña")
    p_eval.add_argument("password")

    p_gen = sub.add_parser("generar", help="Genera una contraseña segura")
    p_gen.add_argument("-l", "--longitud", type=int, default=16)

    p_hash = sub.add_parser("hashear", help="Calcula el hash SHA-256")
    p_hash.add_argument("password")
    p_hash.add_argument("--salt", default=None)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if args.accion == "evaluar":
        puntaje, etiqueta = evaluar_fortaleza(args.password)
        print(f"Fortaleza: {etiqueta} ({puntaje}/4)")
    elif args.accion == "generar":
        print(generar_password(args.longitud))
    elif args.accion == "hashear":
        print(hashear(args.password, args.salt))


if __name__ == "__main__":
    main()
