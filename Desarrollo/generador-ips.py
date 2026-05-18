#!/usr/bin/env python3

import random
import sys


def generar_ip():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print(f"Uso: {sys.argv[0]} <n> [nombre_fichero]")
        sys.exit(1)

    try:
        n = int(sys.argv[1])
        if n <= 0:
            raise ValueError
    except ValueError:
        print("El parámetro n debe ser un entero positivo.")
        sys.exit(1)

    # Nombre por defecto si no se especifica
    nombre_fichero = sys.argv[2] if len(sys.argv) == 3 else "banned"

    with open(nombre_fichero, "w") as f:
        for _ in range(n):
            f.write(generar_ip() + "\n")

    print(f"Se han generado {n} direcciones IP en '{nombre_fichero}'")


if __name__ == "__main__":
    main()
