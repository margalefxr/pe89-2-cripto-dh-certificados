#!/usr/bin/env python3
import socket

P = 251
G = 6
PUERTO = 5000

def aplicar_xor(datos_bytes, llave_k):
    """Aplica XOR byte a byte entre el mensaje y la llave K de Diffie-Hellman."""

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
    b = pedir_secreto("Introduce tu número secreto (b): ")

    # =====================================================================
    # Clave pública (B)
    # =====================================================================
    B = pow(G, b, P)  # B = G^b mod P
    print(f"[Local] Clave privada b = {b} (no sale del contenedor)")
    print(f"[Local] Clave pública B = {G}^{b} mod {P} = {B}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", PUERTO))
        s.listen(1)
        print(f"\n[*] Esperando conexión de Alice en el puerto {PUERTO}...")

        conn, addr = s.accept()
        with conn:
            print(f"[*] Conexión establecida desde {addr[0]}")

            # Recibe clave pública A de Alice y envia B
            A = int(conn.recv(1024).decode().strip())
            print(f"[Red Pública] Recibida clave pública de Alice: A = {A}")
            conn.sendall(f"{B}".encode())
            print(f"[Red Pública] Enviada la clave pública de Bob: B = {B}")

            # =====================================================================
            # Clave compartida (K)
            # =====================================================================
            K = pow(A, b, P)  # K = A^b mod P
            print(f"[Local] Clave compartida K = {A}^{b} mod {P} = {K}")

            # Recibe el mensaje cifrado y aplicar XOR con K
            mensaje_cifrado = conn.recv(4096)
            print(f"\n[Tráfico Cifrado en Red (Hex)]: {mensaje_cifrado.hex(' ').upper()}")

            # =====================================================================
            # XOR con K
            # =====================================================================
            mensaje_bytes = aplicar_xor(mensaje_cifrado, K)
            mensaje = mensaje_bytes.decode("utf-8")
            print(f"[+] Mensaje descifrado: {mensaje}")

if __name__ == "__main__":
    main()
