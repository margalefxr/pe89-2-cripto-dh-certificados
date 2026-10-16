# WORKLOG — PE 89.2

Entorno final: macOS + OrbStack, `python:3.11-slim`, Python 3.12 y OpenSSL 3.6.3 en el host. Evidencias en [`logs/`](logs/).

## Pasos

| # | Paso | Resultado |
|---|---|---|
| 1 | Leer introducción, rúbrica, actividades y entrega | 10 criterios, 10 pts |
| 2 | Tabla de técnicas y análisis de configuraciones | 6/6, config. B |
| 3 | Comprobar P y G | 6 es raíz primitiva de 251 (orden 250) |
| 4 | `docker-compose.yml` + `docker compose config` | Sintaxis válida |
| 5 | Completar `bob_servidor.py` y `alice_cliente.py` | DH con `pow()` + `aplicar_xor()` |
| 6 | `docker compose up -d` y revisar red, IPs, hostnames e imagen | [`entorno.log`](logs/entorno.log) |
| 7 | Bob (b = 203) y Alice (a = 97), sesiones grabadas con `script` | [`bob.log`](logs/bob.log), [`alice.log`](logs/alice.log). K = 96 en los dos |
| 8 | Tests + `openssl x509` + `openssl verify` | [`pruebas.log`](logs/pruebas.log). 4/4 OK, `OK` |
| 9 | Fuerza bruta con A y B | a = 97, K = 96 |
| 10 | Revisión del README contra la rúbrica | Ver [Cambios](#cambios) |

## Tests

| Test | Qué comprueba | Resultado |
|---|---|---|
| `test_misma_clave_compartida` | Con a = 97 y b = 203 las dos K coinciden | ✅ |
| `test_todas_las_combinaciones` | Las dos K coinciden en los 249 × 249 pares y K cabe en un byte | ✅ |
| `test_xor_ida_y_vuelta` | Cifrar y descifrar devuelve el mensaje con tildes | ✅ |
| `test_xor_byte_a_byte` | `0x00 ^ 15 = 0x0F` y `0xFF ^ 15 = 0xF0` | ✅ |

## Decisiones de proceso (por qué A y no B)

| Decisión | Elegido (A) | Descartado (B) | Motivo |
|---|---|---|---|
| Valores de prueba | a = 97, b = 203 | 2, 3 o valores pequeños | Valores lejos de los extremos, dan A, B y K no triviales |
| Mensaje | Con tilde (`aquí`) | Solo ASCII | Demuestra que el UTF-8 multibyte se recupera bien |
| Evidencia | `script` → `logs/*.log` | Capturas de pantalla | Texto real, se puede buscar y comparar con el README |
| Tests | 4 con `unittest` | `pytest` | Librería estándar, sin dependencias |
| Documentación | README + WORKLOG + `logs/` | Carpeta `docs/` con anexos | Lo mínimo para cubrir la rúbrica |

## Cambios

| Versión | Cambio | Motivo |
|---|---|---|
| v1 | Primera versión completa | — |
| v2 | Quitado `depends_on` del compose | No lo pide el enunciado |
| v2 | Tabla de Decisiones con A/B | Justificar lo descartado |
| v2 | RFC 6125 → RFC 9525 | 6125 está obsoleto |
| v2 | Texto recortado, log plegado | Leer rápido |
| v3 | Salidas del README sustituidas por las de `logs/` | Evidencia real con `python:3.11-slim` |
| v3 | Tabla de resultados con por qué e implicaciones | Conectar la prueba con un entorno real |

## Dificultades

| Dificultad | Solución |
|---|---|
| El código base hace `int(input())` sin validar y el enunciado limita a y b a 2–250 | `pedir_secreto()` con `while`/`try` |
| El botón **+** de OrbStack daba `pull access denied for test` | No hace falta crear contenedores a mano. `docker compose up -d` crea los dos |
| Los logs de `script` en macOS terminan las líneas con `\r\n` | Convertidos a `\n` con `tr -d '\r'` para que se lean bien en GitHub |
| `openssl verify` sin `-CAfile` da error 20 | La CA del lab no está en el almacén del sistema, hay que pasarla |
