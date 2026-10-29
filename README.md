# cortex9-attenuable-mcp

[![CI](https://github.com/federiconbaez/cortex9-attenuable-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/federiconbaez/cortex9-attenuable-mcp/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

Tokens de capacidad atenuables para `tools/call` de MCP: Biscuit con chequeos Datalog sobre la herramienta y los argumentos canonicalizados, ligados a una clave DPoP (RFC 9449), con delegación agente → subagente firmada por el poseedor actual. Es una capa de autorización delante del transporte Streamable HTTP de [`mcp-server-rs`](https://github.com/federiconbaez/mcp-server-rs).

*Attenuable capability tokens for MCP `tools/call`. English version below.*

---

## Español

### El problema

Cuando un agente delega en un subagente, hoy le pasa su token OAuth entero o nada. Los scopes son gruesos: no hay forma de decir "solo `tools/call` de `repo.push` sobre `acme/site`, ramas `feature/*`, por 10 minutos, y sin re-delegar" sin volver al servidor de autorización. La especificación de autorización de MCP (revisión 2025-11-25) se apoya en OAuth 2.1 con `Authorization: Bearer`; DPoP liga un token a una clave pero no lo atenúa; Biscuit atenúa offline pero no sabe nada de MCP.

### Qué hace

- **Token raíz** (Biscuit, Ed25519): `right(<tool>)` por herramienta, chequeo de audiencia, vencimiento opcional. El `context` del bloque de autoridad nombra al poseedor: `attn:holder=<jkt>`, el thumbprint RFC 7638 de su clave DPoP.
- **Atenuación offline** (cualquiera que tenga el token, sin hablar con nadie): bloques que solo agregan chequeos.
  - herramientas permitidas (`tool($t)`),
  - argumento igual a un valor (`arg("/repo", "acme/site")`), prefijo de string, mundo cerrado de argumentos (`reject if arg_path($p), !{...}.contains($p)`),
  - solo `tools/call`, vencimiento, bloqueo a una clave (`dpop_jkt`), máximo de cambios de poseedor.
- **Delegación con cambio de clave**: un bloque cuyo `context` es `attn:holder=<nuevo>` solo vale si es un *third-party block* de Biscuit cuya firma externa verifica con la clave del poseedor **actual**. Quien copia el token puede restringirlo, pero no moverlo a su clave.
- **Verificación por request** (`Verifier::verify`):
  1. `Authorization: DPoP <token>` exactamente una vez (Bearer se rechaza, RFC 9449 §7.2) y un único header `DPoP`;
  2. prueba DPoP: `typ=dpop+jwt`, `alg=EdDSA`, `jwk` OKP/Ed25519 sin `d`, firma con `verify_strict`, `htm`, `htu` normalizado contra la URL configurada (no contra `Host`), ventana de `iat` (60 s hacia atrás, 5 s hacia adelante), `ath`;
  3. **extensión no estándar** `rbh` = base64url(SHA-256(body)): en MCP el body *es* la operación, así que una prueba capturada no sirve con otro body (RFC 9449 §11.7 permite claims extra);
  4. firma de la cadena Biscuit contra la clave raíz y cadena de poseedores; la clave de la prueba tiene que ser la del último poseedor;
  5. `jti` de un solo uso (caché en memoria que falla cerrado si se llena);
  6. parseo **estricto** del body: claves duplicadas en cualquier nivel → 400 (serde_json se queda con la última, otros parsers con la primera); batches → 400;
  7. hechos `method`, `tool`, `arg_path`, `arg`, `arg_num`, `dpop_jkt`, `holder_changes`, `audience`, `time` y políticas `allow if method($m), {públicos}.contains($m)`, `allow if method("tools/call"), tool($t), right($t)`, `deny if true`.
- El body autorizado es exactamente el que se despacha a `HttpState::handle` de `mcp-server-rs` (sin re-serializar).
- CLI `attn`: `keygen`, `jkt`, `pub`, `mint`, `attenuate`, `delegate`, `proof`, `inspect`, `serve`, `suite`, `bench`.

### Medición contra el criterio de aceptación

Criterio (idea #43): *100 % de rechazo de uso fuera de lo atenuado (otra tool/arg, re-delegación, replay sin clave) y verificación p99 < 200 µs.*

**(a) Suite de confused-deputy / escalada** — `cargo run --release --bin attn -- suite`

| | Resultado |
|---|---|
| Ataques rechazados **y** que no llegaron a la herramienta | **34/34** (100 %) |
| Controles positivos ejecutados (para que "rechazar todo" no pase) | **6/6** |

Clases: otra herramienta (5: otra tool, mayúsculas, método no público, batch mezclado), otro argumento (8: otro valor, prefijo, argumento extra, contrabando anidado `/opts/repo`, clave duplicada, tipo cambiado a array, argumento faltante, tercer nivel más estricto), re-delegación / cambio de poseedor (6: re-delegar un token bloqueado, segundo salto con `max_holder_changes=1`, bloque común que se declara poseedor, cambio firmado por una clave ajena, `right("calc")` agregado en un bloque posterior, el delegador usando el token ya delegado), replay / clave (11: token robado con clave propia, downgrade a Bearer, replay exacto, prueba capturada con otro body, `ath` de otro token, otro `htu`, otro `htm`, `iat` viejo, `iat` futuro, `alg=none`, dos headers DPoP), validez del token (4: vencido, otra raíz, byte alterado, otra audiencia). Cada caso es un request HTTP completo a través de la capa hasta `mcp-server-rs`, con una herramienta de demo `repo.push` que registra cada ejecución; un ataque cuenta como rechazado solo si el status no es 200 **y** el registro no creció.

**(b) Costo por request** — `cargo run --release --bin attn -- bench --iters 20000 --warmup 2000`

Tiempo de `Verifier::verify` (DPoP + Biscuit + cadena de poseedores + Datalog), 20 000 requests, pruebas pre-generadas (el costo del cliente no se cuenta). VM de desarrollo: Intel Xeon virtualizado, 8 vCPU, **compartida con otros builds** (load average 5-10 durante la corrida), así que estos números son ruidosos:

| Token | Bloques | Bytes (binario / base64) | p50 frío | **p99 frío** | p50 token en caché | **p99 token en caché** |
|---|---|---|---|---|---|---|
| raíz | 1 | 346 / 464 | 125.9 µs | 181.1 µs | 63.0 µs | 102.2 µs |
| delegado (1 nivel) | 2 | 1158 / 1544 | 253.5 µs | 384.1 µs | 92.8 µs | 134.1 µs |
| 2 niveles | 3 | 1428 / 1904 | no medido | no medido | no medido | no medido |
| **3 niveles** | 4 | **1627 / 2172** | 342.9 µs | **534.0 µs** | 103.3 µs | **148.0 µs** |

Prueba DPoP: 513 bytes. "Frío" = cada request vuelve a verificar toda la cadena de firmas de Biscuit. "En caché" = el mismo string de token ya fue verificado (caché por SHA-256 del string exacto, 1024 entradas); igual corren en cada request la firma DPoP, el `jti` y **todos** los chequeos Datalog (el test `token_cache_does_not_skip_time_or_holder_checks` lo comprueba con un token vencido y con la clave de un atacante).

Veredicto honesto:
- (a) **cumple**: 34/34 rechazados, 6/6 controles.
- (b) **cumple solo con el token en caché** (p99 148 µs con 3 niveles en la VM de desarrollo; ver CI abajo). **No cumple en frío**: con 3 niveles el p99 es ~534 µs, porque Biscuit verifica 4 firmas de bloque + 1 firma externa y la prueba DPoP agrega otra (`cargo run --release --example breakdown`: parseo + cadena de firmas ≈ 210 µs p50, prueba DPoP ≈ 46 µs p50). El primer uso de cada token paga ese costo.
- Tamaño con 3 niveles: 1627 bytes (2172 en base64, lo que viaja en el header). El bloque de delegación es el más grande (~810 bytes) porque un third-party block trae su propia tabla de símbolos, la clave pública y la firma externa.

Los resultados de los jobs de CI (`suite` y `bench` en `ubuntu-latest`) están en la sección siguiente.

### Resultados en CI

Primera corrida en `main` ([run 40809314290](https://github.com/federiconbaez/cortex9-attenuable-mcp/actions/runs/40809314290)), runner `ubuntu-latest` x86_64 con AMD EPYC 7763 (4 vCPU):

| Job | Resultado |
|---|---|
| `fmt · clippy · test` | verde: `cargo fmt --check`, `clippy -D warnings`, 22 tests |
| `attack suite (criterion a)` | verde: **34/34** ataques rechazados, **6/6** controles ejecutados |
| `verification latency (criterion b, reported)` | verde (reporta, no es compuerta) |

| Token | p50 frío | **p99 frío** | p50 en caché | **p99 en caché** |
|---|---|---|---|---|
| raíz (1 bloque) | 165.1 µs | 211.8 µs | 89.7 µs | 123.4 µs |
| delegado (2 bloques) | 304.5 µs | 357.0 µs | 117.4 µs | 155.5 µs |
| 3 niveles (4 bloques) | 429.2 µs | **484.2 µs** | 133.7 µs | **175.0 µs** |

Tamaños idénticos a los de la VM de desarrollo (346 / 1158 / 1428 / 1627 bytes). En el runner se repite el veredicto: el p99 < 200 µs se cumple con el token en caché (175.0 µs con 3 niveles) y **no** en frío (484.2 µs con 3 niveles; tampoco con el token raíz, 211.8 µs). Solo se midió en runners x86_64.

### Qué está probado y qué no

Probado (tests en `cargo test`, 22 en total):
- vectores del RFC 8037 (apéndice A.3: thumbprint; A.4: firma EdDSA reproducida);
- checks de la prueba DPoP uno por uno, normalización de `htu`, caché de `jti`;
- parseo estricto (claves duplicadas, también escritas con escapes `\u0072epo`), aplanado a JSON Pointer (RFC 6901), límites (256 hojas, profundidad 16, 4096 bytes por string);
- cadena de poseedores (delegaciones firmadas, cambios sin firma o con firma ajena, contextos malformados);
- que los parámetros Datalog no son inyectables (un nombre de tool con comillas y sintaxis Datalog no agrega derechos);
- la suite completa (a) y un test sobre un socket TCP real con `tiny_http` + `mcp-server-rs`;
- la CLI de punta a punta (keygen, mint, delegate, inspect, proof).

No probado / fuera de alcance:
- **No es interoperable con clientes MCP existentes**: la spec usa `Authorization: Bearer` y estos tokens son Biscuit + DPoP + `rbh`; hace falta un cliente que hable esto. SEP-1932 (perfil DPoP para MCP) está abierto y sin mergear, y las SEPs de firma HTTP para clientes (SEP-1415 y su revival #2753) están cerradas.
- Sin servidor de autorización, sin revocación (ni distribuida ni local), sin `DPoP-Nonce` (RFC 9449 §8/§9): la prueba puede pre-generarse dentro de la ventana de 60 s.
- Solo EdDSA/Ed25519 para DPoP (no ES256).
- La caché de `jti` es por proceso: con varias réplicas detrás de un balanceador, un replay a otra réplica no se detecta (RFC 9449 §11.1 lo menciona).
- Solo métodos `POST`; `GET` (SSE) y `DELETE` devuelven 405 en esta capa. Sin batches.
- La canonicalización no normaliza Unicode (NFC) ni números: `1.0` y `1` son hojas distintas (`arg_num` vs `arg`). Los chequeos comparan exactamente lo que se despacha, que es lo que importa para seguridad, pero un atenuador tiene que escribir los valores tal como los manda el cliente.
- Los números de latencia son de una VM compartida y de runners de GitHub; no son un benchmark controlado.

### Uso rápido

```sh
cargo build --release
B=./target/release/attn
$B keygen --out root.key.json            # imprime el jkt (no se usa)
A=$($B keygen --out a.key.json)          # orquestador
S=$($B keygen --out b.key.json)          # subagente
$B pub --key root.key.json > root.pub
$B mint --root root.key.json --holder "$A" --audience mcp://demo \
   --tool repo.push --tool echo --ttl 3600 > a.tok
$B delegate --root-pub root.pub --token @a.tok --holder-key a.key.json --to "$S" \
   --tool repo.push --arg /repo=acme/site --arg-prefix /branch=feature/ \
   --only-args /repo,/branch --lock "$S" --ttl 600 > b.tok
$B inspect --root-pub root.pub --token @b.tok
$B serve --root-pub root.pub --audience mcp://demo --url http://127.0.0.1:8808/mcp
# cliente: $B proof --key b.key.json --token @b.tok --url http://127.0.0.1:8808/mcp --body body.json
```

### Fuentes (leídas)

- RFC 9449, OAuth 2.0 DPoP: https://www.rfc-editor.org/rfc/rfc9449 (§4.2, §4.3, §6.1, §7.1, §7.2, §11.1, §11.7).
- Especificación de Biscuit: https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md (scopes, `check all`/`reject if`, third-party blocks, firmas v1).
- RFC 8037 (OKP/Ed25519 en JOSE), apéndices A.1–A.4: https://www.rfc-editor.org/rfc/rfc8037
- RFC 7638 (JWK Thumbprint), §3.2: https://www.rfc-editor.org/rfc/rfc7638
- RFC 6901 (JSON Pointer), §3: https://www.rfc-editor.org/rfc/rfc6901
- Autorización MCP, revisión 2025-11-25: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- SEP-1415 (cerrada) y #2753 (cerrada): https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1415 , https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2753 ; SEP-1932 (abierta): https://github.com/modelcontextprotocol/modelcontextprotocol/pull/1932

---

## English

### Problem

When an agent delegates to a subagent it hands over its whole OAuth token or nothing. Scopes are coarse: you cannot say "only `tools/call` of `repo.push` on `acme/site`, `feature/*` branches, for 10 minutes, not re-delegable" without going back to the authorization server. MCP authorization (2025-11-25) is OAuth 2.1 with `Authorization: Bearer`; DPoP binds a token to a key but does not attenuate it; Biscuit attenuates offline but knows nothing about MCP.

### What it does

- **Root token** (Biscuit, Ed25519): `right(<tool>)`, an audience check, optional expiry. The authority block `context` names the holder, `attn:holder=<jkt>` (RFC 7638 thumbprint of its DPoP key).
- **Offline attenuation** by anyone holding the token: blocks that only add checks (allowed tools, argument equals value, string prefix, closed-world argument set, `tools/call` only, expiry, lock to one DPoP key, maximum holder changes).
- **Key-changing delegation**: a block whose context is `attn:holder=<new>` is honoured only if it is a Biscuit third-party block whose external signature verifies with the *current* holder's key. Someone who copies the token can restrict it but cannot move it to their key.
- **Per-request verification**: one `Authorization: DPoP` and one `DPoP` header (Bearer refused); DPoP proof checks (`typ`, `alg=EdDSA`, public-only OKP `jwk`, strict signature, `htm`, normalized `htu` against the configured URL, `iat` window, `ath`); a **non-standard** `rbh` claim (SHA-256 of the body) so a captured proof cannot carry another operation; Biscuit signature chain and holder chain, with the proof key required to be the last holder; single-use `jti`; strict body parsing (duplicate keys anywhere and batches are refused); Datalog over `method`, `tool`, `arg_path`, `arg`, `arg_num`, `dpop_jkt`, `holder_changes`, `audience`, `time`.
- The authorized body is the exact body dispatched to `mcp-server-rs`'s `HttpState::handle`.

### Measurement against the acceptance criterion

Criterion (idea #43): *100% rejection of out-of-attenuation use (other tool/arg, re-delegation, replay without the key) and verification p99 < 200 µs.*

- **(a)** `attn suite`: **34/34 attacks refused and never executed, 6/6 positive controls executed.** Each case is a full HTTP request through the layer into `mcp-server-rs`; an attack only counts as refused if the status is not 200 *and* the demo tool's call log did not grow.
- **(b)** `attn bench --iters 20000 --warmup 2000` on the shared dev VM (8 vCPU Xeon, load average 5–10 from other builds): with a 3-level token (4 blocks, 1627 bytes, 2172 in base64; DPoP proof 513 bytes) p99 is **534 µs cold** (full Biscuit signature chain every request) and **148 µs with the token cached** (cache keyed by SHA-256 of the exact token string; DPoP signature, `jti` and all Datalog checks still run per request). Root token: 181 µs cold / 102 µs cached. **The < 200 µs target is met only on the cached path, not cold.** The cold cost is dominated by Biscuit's signature chain (≈210 µs p50 for 4 blocks + 1 external signature, `cargo run --release --example breakdown`).

CI results are in the next section.

### CI results

First run on `main` ([run 40809314290](https://github.com/federiconbaez/cortex9-attenuable-mcp/actions/runs/40809314290)), `ubuntu-latest` x86_64 runner, AMD EPYC 7763 (4 vCPU): all three jobs green. `attack suite`: **34/34** attacks refused, **6/6** controls executed. `bench` (reported, not a gate), 3-level token: p99 **484.2 µs cold**, **175.0 µs cached**; root token 211.8 µs cold / 123.4 µs cached; delegated 357.0 µs cold / 155.5 µs cached. Same verdict as on the dev VM: the < 200 µs p99 target holds on the cached path only. Only x86_64 runners were measured.

### Tested / not tested

Tested by `cargo test` (22 tests): RFC 8037 A.3/A.4 vectors, each DPoP check, `htu` normalization, `jti` cache, strict parsing and JSON Pointer flattening with limits, holder chain, Datalog parameter injection, the full suite, a real TCP socket test, and the CLI end to end.

Not covered: interoperability with stock MCP clients (they send Bearer; SEP-1932 for a DPoP profile is still open; SEP-1415 and #2753 are closed), an authorization server, revocation, `DPoP-Nonce`, ES256, a shared `jti` store across replicas, `GET`/`DELETE`/batches, Unicode or numeric normalization of arguments. Latency numbers come from a shared VM and GitHub runners, not a controlled benchmark.

### Sources (read)

See the list in the Spanish section: RFC 9449, the Biscuit specification, RFC 8037, RFC 7638, RFC 6901, MCP authorization 2025-11-25, SEP-1415, #2753 and SEP-1932.

## License

Apache-2.0
