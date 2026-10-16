#!/usr/bin/env python3
import socket

P = 251
G = 6
IP_BOB = "172.28.0.10"
PUERTO = 5000


def aplicar_xor(datos_bytes, llave_k):
    """Aplica XOR byte a byte entre el texto claro y la llave K."""

    # =====================================================================
    # XOR byte a byte
    # =====================================================================
    resultado = []
    for byte in datos_bytes:
        resultado.append(byte ^ llave_k)  # K < 256, cabe en un byte

    return bytes(resultado)


def pedir_secreto(texto):
    # pide un entero entre 2 y 250 hasta que sea valido
    while True:
        try:
            numero = int(input(texto))
            if 2 <= numero <= 250:
                return numero
            print("Tiene que estar entre 2 y 250")
        except ValueError:
            print("Eso no es un numero entero")


def main():

    # =====================================================================
    # Clave privada (a)
    # Clave pública (A)
    # =====================================================================
    a = pedir_secreto("Introduce tu número secreto (a): ")
    A = pow(G, a, P)  # A = G^a mod P
    print(f"[Local] Clave privada a = {a} (no sale del contenedor)")
    print(f"[Local] Clave pública A = {G}^{a} mod {P} = {A}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"\n[*] Conectando con el contenedor de Bob ({IP_BOB}:{PUERTO})...")
        s.connect((IP_BOB, PUERTO))

        # Envía clave pública A y recibe clave pública B
        s.sendall(f"{A}".encode())
        B = int(s.recv(1024).decode().strip())
        print(f"[Red Pública] Enviada clave pública A = {A} | Recibida clave pública B = {B}")

        # =====================================================================
        # Clave compartida (K)
        # Pide mensaje para cifrarlo con XOR usando K
        # =====================================================================
        K = pow(B, a, P)  # K = B^a mod P
        print(f"[Local] Clave compartida K = {B}^{a} mod {P} = {K}")

        mensaje = input("\nEscribe el mensaje para Bob: ")
        mensaje_bytes = mensaje.encode("utf-8")
        bytes_cifrados = aplicar_xor(mensaje_bytes, K)

        # Envía mensaje a Bob
        print(f"\n[Enviando por la red en Hex]: {bytes_cifrados.hex(' ').upper()}")
        s.sendall(bytes_cifrados)
        print("[+] ¡Mensaje cifrado enviado con éxito!")


if __name__ == "__main__":
    main()
