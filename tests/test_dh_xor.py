import os
import sys
import unittest

# los scripts estan en lab-dh-xor/scripts
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "lab-dh-xor", "scripts"))

import alice_cliente
import bob_servidor

P = 251
G = 6


class TestDHXor(unittest.TestCase):

    def test_misma_clave_compartida(self):
        a = 97
        b = 203
        A = pow(G, a, P)
        B = pow(G, b, P)
        self.assertEqual(pow(B, a, P), pow(A, b, P))

    def test_todas_las_combinaciones(self):
        # todos los a y b del rango dan la misma K en los dos lados
        for a in range(2, 251):
            for b in range(2, 251):
                k_alice = pow(pow(G, b, P), a, P)
                k_bob = pow(pow(G, a, P), b, P)
                self.assertEqual(k_alice, k_bob)
                self.assertTrue(1 <= k_alice <= 250)  # cabe en un byte

    def test_xor_ida_y_vuelta(self):
        mensaje = "Hola Bob, aquí Alice".encode("utf-8")
        cifrado = alice_cliente.aplicar_xor(mensaje, 42)
        self.assertNotEqual(cifrado, mensaje)
        self.assertEqual(bob_servidor.aplicar_xor(cifrado, 42), mensaje)

    def test_xor_byte_a_byte(self):
        self.assertEqual(alice_cliente.aplicar_xor(b"\x00\xff", 15), b"\x0f\xf0")


if __name__ == "__main__":
    unittest.main()
