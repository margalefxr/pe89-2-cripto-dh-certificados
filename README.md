# PE 89.2 — Técnicas criptográficas, Diffie–Hellman + XOR y certificados digitales

**Autor:** Xavier Margalef Riestra · **Módulo:** MF0489 Semana 2 · **Fecha:** 16/10/2026

Selección de técnicas criptográficas, intercambio Diffie–Hellman entre dos contenedores (Alice y Bob) con cifrado XOR usando K, y análisis y verificación de un certificado X.509 con OpenSSL.

## Índice

- [Resumen](#resumen)
- [RA1 — Técnicas de cifrado](#ra1--técnicas-de-cifrado) · [1.1](#11-selección-de-técnicas) · [1.2](#12-configuraciones) · [1.3](#13-hash-cifrado-y-certificados)
- [RA2 — Diffie–Hellman y XOR](#ra2--diffiehellman-y-xor) · [2.1](#21-entorno-docker) · [2.2](#22-diffiehellman) · [2.3](#23-xor) · [2.4](#24-comprobación)
- [RA3 — Certificado digital](#ra3--certificado-digital) · [3.1](#31-campos) · [3.2](#32-interpretación) · [3.3](#33-verificación)
- [Decisiones](#decisiones) · [Normativa](#normativa) · [Ejecución](#ejecución)

## Resumen

| | |
|---|---|
| **Objetivo** | Elegir técnicas según la necesidad, implantar DH + XOR entre dos contenedores y analizar un certificado X.509 |
| **Resultado** | Completado. Alice y Bob obtienen K = 96 y Bob recupera el mensaje exacto. `openssl verify` → `OK`. 4/4 tests OK |
| **Entorno** | macOS + OrbStack, `python:3.11-slim`, OpenSSL 3.6.3. Sesiones grabadas en [`logs/`](logs/) |
| **Observación** | Con P = 251 la clave privada se saca por fuerza bruta en 249 intentos. Además el rango del enunciado permite a = 250, que da A = 1 y K = 1 con cualquier b ([2.4](#24-comprobación)) |

| Criterio | Pts | Sección | Evidencia |
|---|---|---|---|
| Selección de técnicas | 1,5 | [1.1](#11-selección-de-técnicas) | 6/6 necesidades justificadas |
| Análisis de configuraciones | 1 | [1.2](#12-configuraciones) | Config. B + problemas de A y C |
| Hash, cifrado y certificados | 0,5 | [1.3](#13-hash-cifrado-y-certificados) | Tabla hash vs cifrado + certificado en TLS |
| Entorno Docker | 0,75 | [2.1](#21-entorno-docker) | `docker-compose.yml` + `docker compose ps` |
| Diffie–Hellman | 1,5 | [2.2](#22-diffiehellman) | `pow()` en ambos scripts, K iguales |
| XOR | 1 | [2.3](#23-xor) | `aplicar_xor()`, `test_xor_ida_y_vuelta` |
| Comprobación | 0,75 | [2.4](#24-comprobación) | Tabla de valores + K no viaja + XOR didáctico |
| Campos del certificado | 1,5 | [3.1](#31-campos) | Ficha de 15 campos |
| Interpretación | 0,75 | [3.2](#32-interpretación) | 5 respuestas |
| Verificación | 0,75 | [3.3](#33-verificación) | Comando + salida + lectura |
| **TOTAL** | **10** | | |

| Actividad | Pregunta | Respuesta corta | Sección |
|---|---|---|---|
| Técnicas | ¿Qué configuración seleccionarías? | B (RSA-2048, SHA-256, TLS 1.3) | [1.2](#12-configuraciones) |
| Técnicas | ¿Por qué rechazarías las otras dos? | A: RSA-1024, SHA-1, TLS 1.0. C: MD5, HTTP, clave en el mensaje | [1.2](#12-configuraciones) |
| Técnicas | ¿Diferencia entre cifrar y hacer hash? | Cifrar es reversible con clave, el hash no | [1.3](#13-hash-cifrado-y-certificados) |
| Técnicas | ¿Qué aporta un certificado en TLS? | Autenticación del servidor y protección contra MITM | [1.3](#13-hash-cifrado-y-certificados) |
| DH + XOR | Valores a, A, b, B, K, mensajes | a = 97, A = 107, b = 203, B = 56, K = 96 | [2.4](#24-comprobación) |
| Certificado | ¿Servidor o CA? | Servidor (`CA:FALSE`, EKU serverAuth) | [3.2](#32-interpretación) |
| Certificado | ¿Qué lo relaciona con el servidor? | SAN y CN | [3.2](#32-interpretación) |
| Certificado | ¿Qué se puede distribuir? | El certificado entero | [3.2](#32-interpretación) |
| Certificado | ¿Contiene la clave privada? | No | [3.2](#32-interpretación) |
| Certificado | ¿Riesgo si roban la privada? | Suplantación y MITM hasta revocar | [3.2](#32-interpretación) |
| Certificado | Verificación contra la CA | `OK` | [3.3](#33-verificación) |

## RA1 — Técnicas de cifrado

### 1.1 Selección de técnicas

| Necesidad | Técnica seleccionada | Justificación |
|---|---|---|
| Proteger un gran volumen de información cuando emisor y receptor ya comparten una clave secreta | **Cifrado simétrico** | Confidencialidad. Rápido (AES-GCM, ChaCha20-Poly1305) y la clave ya existe |
| Proteger un secreto destinado a un receptor sin haber acordado previamente una clave compartida | **Cifrado asimétrico** | Confidencialidad. Cifro con la pública del receptor y solo su privada descifra. En la práctica cifra una clave de sesión (esquema híbrido) |
| Detectar si un archivo ha sido modificado | **Función hash** | Integridad. Un bit distinto cambia todo el SHA-256. Si el atacante puede cambiar también el hash hace falta HMAC o firma |
| Comprobar la identidad de un servidor web | **Certificado digital** | Autenticación. La CA firma que esa clave pública es de ese dominio |
| Acordar una clave compartida a través de una red insegura | **Intercambio de claves Diffie–Hellman** | Intercambio de claves. Solo viajan valores públicos, K no pasa por la red. No autentica (MITM), por eso en TLS va con certificado |
| Demostrar que un documento ha sido firmado por una determinada entidad y detectar modificaciones posteriores | **Firma digital** | Autenticación, integridad y no repudio. Se firma el hash con la privada y se verifica con la pública |

### 1.2 Configuraciones

**¿Qué configuración seleccionarías para proteger una comunicación actual?** La **B**. Es la única con longitudes y algoritmos vigentes.

**¿Por qué rechazarías las otras dos?** A usa algoritmos rotos o deprecados y C no cifra nada de verdad.

| Config. | Elemento | Problema | |
|---|---|---|---|
| A | RSA 1024 | ~80 bits de seguridad. RSA-768 ya se factorizó en 2009. NIST SP 800-131A no lo permite desde 2013 | ❌ |
| A | SHA-1 | Colisiones prácticas (SHAttered, 2017) | ❌ |
| A | TLS 1.0 | Deprecado (RFC 8996). CBC vulnerable (BEAST), sin AEAD | ❌ |
| C | MD5 | Colisiones triviales. Con una se falsificó un certificado de Microsoft (Flame, 2012) | ❌ |
| C | HTTP sin TLS | Todo en claro, sin integridad ni autenticación del servidor. MITM directo | ❌ |
| C | Clave en el mensaje | Quien captura el tráfico tiene el cifrado y la clave | ❌ |
| B | RSA 2048 | 112 bits, válido según NIST SP 800-57 hasta 2030 | ✅ |
| B | SHA-256 | Sin colisiones conocidas | ✅ |
| B | TLS 1.3 | Solo AEAD, ECDHE obligatorio (forward secrecy), sin algoritmos legacy | ✅ |

Más adelante RSA-2048 tendrá que migrar a post-cuántico (CNSA 2.0, ML-KEM). En OpsMatrix Lab el Nginx solo acepta TLS 1.3.

### 1.3 Hash, cifrado y certificados

**Diferencia entre cifrar un mensaje y calcular su hash**

| | Cifrado | Hash |
|---|---|---|
| Propiedad | Confidencialidad | Integridad |
| Reversible | Sí, con la clave | No |
| Clave | Sí | No (salvo HMAC) |
| Salida | Tamaño según el mensaje | Fija (SHA-256 = 32 bytes) |

**¿Qué propiedades de seguridad puede aportar un certificado digital dentro de una comunicación TLS?**

| Propiedad | Cómo |
|---|---|
| Autenticación del servidor | La CA firma el vínculo clave pública ↔ nombre (SAN) |
| Protección contra MITM | El servidor firma el handshake (`CertificateVerify`) con su privada. Sin ella nadie se mete en medio del ECDHE |
| Integridad del certificado | Cualquier cambio rompe la firma de la CA |

El certificado no cifra el tráfico. La clave de sesión sale de ECDHE.

## RA2 — Diffie–Hellman y XOR

```
lab-dh-xor/
├── docker-compose.yml
└── scripts/
    ├── bob_servidor.py
    └── alice_cliente.py
```

### 2.1 Entorno Docker

| Parámetro | Bob | Alice |
|---|---|---|
| Imagen | `python:3.11-slim` | `python:3.11-slim` |
| Hostname / container | `bob` | `alice` |
| Directorio / volumen | `/app` · `./scripts:/app` | `/app` · `./scripts:/app` |
| Red / subred | `red-cripto` · `172.28.0.0/16` | `red-cripto` · `172.28.0.0/16` |
| IPv4 | `172.28.0.10` | `172.28.0.20` |
| `tty` / `stdin_open` | `true` | `true` |

Con `tty` y `stdin_open` el `python3` por defecto de la imagen queda esperando entrada y el contenedor no se para.

[`logs/entorno.log`](logs/entorno.log):

```
NAME      IMAGE              COMMAND     SERVICE   CREATED         STATUS         PORTS
alice     python:3.11-slim   "python3"   alice     2 minutes ago   Up 2 minutes   
bob       python:3.11-slim   "python3"   bob       2 minutes ago   Up 2 minutes   

internal=true subnet=172.28.0.0/16
/bob hostname=bob ip=172.28.0.10 image=python:3.11-slim
/alice hostname=alice ip=172.28.0.20 image=python:3.11-slim
```

### 2.2 Diffie–Hellman

| Parámetro | Valor |
|---|---|
| P | 251 (primo) |
| G | 6 (raíz primitiva de 251, orden 250) |
| PUERTO | 5000 |
| a, b | 2–250, validado en `pedir_secreto()` |

```python
B = pow(G, b, P)  # B = G^b mod P      (bob_servidor.py)
K = pow(A, b, P)  # K = A^b mod P

A = pow(G, a, P)  # A = G^a mod P      (alice_cliente.py)
K = pow(B, a, P)  # K = B^a mod P
```

Los únicos `sendall` de los scripts mandan A, B y el mensaje cifrado. a y b no salen de su contenedor. `test_todas_las_combinaciones` comprueba que las dos K coinciden en los 249 × 249 pares.

### 2.3 XOR

La misma función en los dos scripts. XOR es su propia inversa, `(m ^ K) ^ K = m`.

```python
    resultado = []
    for byte in datos_bytes:
        resultado.append(byte ^ llave_k)  # K < 256, cabe en un byte

    return bytes(resultado)
```

Alice cifra `mensaje.encode("utf-8")` y Bob hace `.decode("utf-8")` al descifrar.

### 2.4 Comprobación

| Elemento | Valor |
|---|---|
| Clave privada de Alice, a | 97 |
| Clave pública de Alice, A | 107 |
| Clave privada de Bob, b | 203 |
| Clave pública de Bob, B | 56 |
| Clave compartida calculada por Alice | 96 |
| Clave compartida calculada por Bob | 96 |
| Mensaje original | `Hola Bob, aquí Alice. Prueba PE 89.2` |
| Mensaje cifrado en hexadecimal | `28 0F 0C 01 40 22 0F 02 4C 40 01 11 15 A3 CD 40 21 0C 09 03 05 4E 40 30 12 15 05 02 01 40 30 25 40 58 59 4E 52` |
| Mensaje recuperado por Bob | `Hola Bob, aquí Alice. Prueba PE 89.2` |

<details>
<summary>Salida completa de Bob y Alice (<a href="logs/bob.log">bob.log</a>, <a href="logs/alice.log">alice.log</a>)</summary>

```
===== BOB =====
Introduce tu número secreto (b): 203
[Local] Clave privada b = 203 (no sale del contenedor)
[Local] Clave pública B = 6^203 mod 251 = 56

[*] Esperando conexión de Alice en el puerto 5000...
[*] Conexión establecida desde 172.28.0.20
[Red Pública] Recibida clave pública de Alice: A = 107
[Red Pública] Enviada la clave pública de Bob: B = 56
[Local] Clave compartida K = 107^203 mod 251 = 96

[Tráfico Cifrado en Red (Hex)]: 28 0F 0C 01 40 22 0F 02 4C 40 01 11 15 A3 CD 40 21 0C 09 03 05 4E 40 30 12 15 05 02 01 40 30 25 40 58 59 4E 52
[+] Mensaje descifrado: Hola Bob, aquí Alice. Prueba PE 89.2

===== ALICE =====
Introduce tu número secreto (a): 97
[Local] Clave privada a = 97 (no sale del contenedor)
[Local] Clave pública A = 6^97 mod 251 = 107

[*] Conectando con el contenedor de Bob (172.28.0.10:5000)...
[Red Pública] Enviada clave pública A = 107 | Recibida clave pública B = 56
[Local] Clave compartida K = 56^97 mod 251 = 96

Escribe el mensaje para Bob: Hola Bob, aquí Alice. Prueba PE 89.2

[Enviando por la red en Hex]: 28 0F 0C 01 40 22 0F 02 4C 40 01 11 15 A3 CD 40 21 0C 09 03 05 4E 40 30 12 15 05 02 01 40 30 25 40 58 59 4E 52
[+] ¡Mensaje cifrado enviado con éxito!
```
</details>

**¿K se transmite?** No. Por la red solo pasan A = 107 y B = 56. Alice calcula 56^97 mod 251 y Bob 107^203 mod 251. Los dos dan 96 porque (G^b)^a = (G^a)^b mod P.

**¿Sirve este XOR en producción?** No, es didáctico.

| Comprobación | Resultado | Por qué | Implicación en un entorno real |
|---|---|---|---|
| K de Alice = K de Bob | 96 = 96 | (G^b)^a = (G^a)^b mod P | DH funciona, las dos partes tienen la misma clave sin enviarla |
| Mensaje recuperado | Idéntico, con la `í` incluida | (m ^ K) ^ K = m y UTF-8 en los dos lados | El cifrado es reversible, pero solo da confidencialidad |
| Fuerza bruta con A y B | `a encontrada: 97 -> K = 96` en ≤ 249 intentos | P = 251 cabe en 8 bits | Hace falta P ≥ 2048 bits o X25519. En el PE 89.1 usé el grupo 14 de RFC 3526 y `secrets` |
| a = 250 (lo permite el enunciado) | A = 1 y K = 1 con cualquier b. Con a = 125, A = 250 y K solo puede ser 1 o 250 | El orden de 6 es 250, así que 6^250 = 1 y 6^125 = −1 mod 251 | Hay que validar la pública recibida (2 ≤ A ≤ P − 2), como `validar_publica()` del PE 89.1 |
| Probar las 256 K | Solo K = 96 da texto legible | K es un byte | La clave de sesión debe ser de 128-256 bits |
| Espacios (`0x20`) en el hex | Todos salen como `40` | Misma K para cada byte | Hace falta un keystream distinto por byte, como ChaCha20 en el PE 89.1 |
| MITM | No se detecta | Sin autenticación ni MAC | Hace falta un certificado que firme el handshake (RA3) y AEAD (ChaCha20-Poly1305, AES-GCM) |

```bash
python3 -c "
P, G, A, B = 251, 6, 107, 56
for a in range(2, 251):
    if pow(G, a, P) == A:
        print('a encontrada:', a, '-> K =', pow(B, a, P))
"
```

## RA3 — Certificado digital

Ficheros del enunciado en [`certificados/`](certificados/).

### 3.1 Campos

```bash
openssl x509 -in certificados/certificado_servidor_PE89_2.crt -noout -text
openssl x509 -in certificados/certificado_servidor_PE89_2.crt -noout -fingerprint -sha256
```

| Elemento | Valor encontrado |
|---|---|
| Sujeto del certificado | `C = ES, O = CETI Formacion, OU = PE 89.2, CN = servidor.pe89.local` |
| Nombre común (CN) | `servidor.pe89.local` |
| Organización | `CETI Formacion` |
| Emisor | `C = ES, O = CETI Formacion, OU = Laboratorio de Criptografia, CN = CETI Lab Root CA 2026` |
| Número de serie | `2300585473` (`0x89202601`) |
| Fecha de inicio | `Oct 16 06:21:14 2026 GMT` |
| Fecha de caducidad | `Oct 16 06:21:14 2027 GMT` |
| Algoritmo de clave pública | `rsaEncryption` |
| Tamaño de la clave pública | 2048 bits (exponente 65537) |
| Algoritmo de firma | `sha256WithRSAEncryption` |
| Huella digital SHA-256 | `C2:6C:98:F6:63:81:45:0C:04:9A:BA:29:72:B7:FB:CD:24:DB:54:31:27:95:E5:CB:BC:F0:06:82:56:1E:D7:14` |
| Subject Alternative Name (SAN) | `DNS:servidor.pe89.local, DNS:www.servidor.pe89.local, IP Address:172.28.0.30` |
| Key Usage | `critical` · Digital Signature, Key Encipherment |
| Extended Key Usage | TLS Web Server Authentication |
| ¿Puede actuar como CA? | No. `Basic Constraints: critical, CA:FALSE` |

### 3.2 Interpretación

**¿Es un certificado de servidor o de autoridad de certificación? ¿Qué campos permiten determinarlo?** Es de servidor.

| Campo | Servidor | CA del laboratorio |
|---|---|---|
| Basic Constraints | `CA:FALSE` | `CA:TRUE, pathlen:0` |
| Key Usage | Digital Signature, Key Encipherment | Certificate Sign, CRL Sign |
| Extended Key Usage | TLS Web Server Authentication | — |
| Emisor = Sujeto | No | Sí (raíz autofirmada) |

**¿Qué información del certificado permite relacionarlo con la identidad del servidor?** El SAN (`servidor.pe89.local`, `www.servidor.pe89.local`, `172.28.0.30`) y el CN. Los clientes TLS validan contra el SAN. El CN ya no se usa para eso (RFC 9525).

**¿Qué parte del certificado puede distribuirse públicamente?** El certificado entero. Lleva identidad, clave pública y firma de la CA, nada secreto.

**¿Contiene el certificado la clave privada asociada?** No. Solo tiene módulo y exponente públicos, y `grep -c PRIVATE` sobre el `.crt` da `0`.

**¿Qué riesgo existiría si la clave privada fuera publicada o robada?** Cualquiera puede suplantar a `servidor.pe89.local` con un certificado válido y hacer MITM sin alertas hasta que se revoque o caduque (16/10/2027). En TLS 1.2 con intercambio RSA también podría descifrar el tráfico capturado. En TLS 1.3 no, por la forward secrecy. Se revoca (CRL/OCSP), se genera una clave nueva y se reemite el certificado.

### 3.3 Verificación

```
$ openssl verify -CAfile certificados/CA_laboratorio_PE89_2.crt certificados/certificado_servidor_PE89_2.crt
certificados/certificado_servidor_PE89_2.crt: OK
```

En el Mac (OpenSSL 3.6.3) da el mismo `OK` ([`logs/pruebas.log`](logs/pruebas.log)). La verificación es correcta. La firma del certificado cuadra con la clave pública de la CA, la cadena llega a la raíz que le paso en `-CAfile` y está dentro de fechas. Por defecto no comprueba el nombre del servidor.

| Prueba extra | Salida | Lectura |
|---|---|---|
| `-purpose sslserver -verify_hostname servidor.pe89.local` | `OK` | Válido como servidor TLS para ese nombre |
| `-verify_hostname google.com` | `error 62 ... hostname mismatch` | El SAN no coincide |
| Sin `-CAfile` | `error 20 ... unable to get local issuer certificate` | La CA del lab no está en el almacén del sistema |

## Decisiones

| Decisión | Elegido (A) | Descartado (B) | Motivo |
|---|---|---|---|
| Red | `internal: true` | Red bridge normal | El enunciado pide red aislada. Alice y Bob se ven pero no salen a Internet, igual que MariaDB en OpsMatrix Lab |
| Nombre de red | `name: red-cripto` | Nombre por defecto | Sin `name`, Compose la llama `lab-dh-xor_red-cripto` |
| Potencia modular | `pow(G, b, P)` | `G ** b % P` | No calcula el número gigante intermedio |
| Entrada de a y b | `pedir_secreto()` con `while`/`try` | `int(input())` del código base | Valida el rango 2–250 y que sea entero |
| Codificación | UTF-8 | ASCII | Soporta tildes. La `í` ocupa 2 bytes y se recupera bien |
| Rango de a y b | 2–250, el del enunciado | Excluir 125 y 250 | Lo respeto y documento el valor débil. Excluirlos cambiaría el enunciado |
| Imagen | `python:3.11-slim` por tag | Fijada por digest `@sha256:...` | El tag es lo que pide el enunciado. En producción fijaría el digest para que la imagen no cambie sin control (supply chain) |
| Dependencias | Ninguna | `requirements.txt` | Solo uso la librería estándar (`socket`) |

## Normativa

| Referencia | Relación |
|---|---|
| ISO/IEC 27001:2022 A.8.24 · A.5.21 | Uso de criptografía (B frente a A y C) · cadena de suministro (imagen Docker de terceros) |
| ENS (RD 311/2022) mp.com.2 / mp.com.3 | Confidencialidad e integridad de las comunicaciones. CCN-STIC-807 descarta MD5, SHA-1 y RSA-1024 |
| NIST SP 800-131A / 800-57 | RSA < 2048 y SHA-1 en firma no permitidos. RSA-2048 válido hasta 2030 |
| eIDAS (UE 910/2014, mod. 2024/1183) | Firma electrónica y certificados cualificados en la UE |
| RGPD art. 32 | Cifrado como medida técnica. La config. C con datos personales no lo cumpliría |

## Ejecución

```bash
cd lab-dh-xor
docker compose up -d
docker compose ps

# grabando la sesión en logs/ (macOS)
script -q ../logs/bob.log docker exec -it bob python bob_servidor.py      # terminal 1
script -q ../logs/alice.log docker exec -it alice python alice_cliente.py   # terminal 2

docker compose down

# tests, desde la raíz del repo (salida en logs/pruebas.log)
python3 -m unittest discover -s tests -v

# certificado
openssl x509 -in certificados/certificado_servidor_PE89_2.crt -noout -text
openssl verify -CAfile certificados/CA_laboratorio_PE89_2.crt certificados/certificado_servidor_PE89_2.crt
```

```
pe89-2-cripto-dh-certificados/
├── README.md            ← este informe
├── WORKLOG.md           ← pasos, tests, decisiones, cambios y dificultades
├── certificados/        ← .crt del enunciado
├── lab-dh-xor/          ← docker-compose.yml + scripts de Alice y Bob
├── logs/                ← sesiones reales (entorno, Bob, Alice, tests y OpenSSL)
└── tests/test_dh_xor.py ← 4 tests
```

Dificultades en [`WORKLOG.md`](WORKLOG.md).
