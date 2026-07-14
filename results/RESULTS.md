# Results — The DoS attack surface of post-quantum TLS on Java servers (exploratory host)

Server-side per-handshake cryptographic work for classical, PQC, and hybrid TLS 1.3 configurations,
measured uniformly on the JVM to quantify the denial-of-service amplification an attacker gains.

**Headline: PQC does not uniformly widen the TLS server DoS surface. Key exchange (ML-KEM) is
DoS-neutral-to-favorable, and ML-DSA authentication is a modest ~2–3× factor over ECDSA — and cheaper
than RSA. The DoS risk is concentrated entirely in SLH-DSA authentication, which is a ~190× CPU/capacity
amplifier and a ~600× memory amplifier, making it unsuitable for per-handshake interactive server
authentication under DoS exposure.** The pre-registered hypothesis that ML-DSA would multiply server
cost 10–100× (H3) is refuted; the honest result is sharper — the danger is SLH-DSA, not PQC in general.

## Environment

- JDK OpenJDK 21.0.11 (Homebrew); macOS 27.0, arm64 (Apple Silicon), 8 logical processors; **unpinned**.
- BouncyCastle `bcprov-jdk18on` 1.84 (ML-KEM/ML-DSA/SLH-DSA/X25519) + JDK JCE (ECDSA/RSA); JMH 1.37.
- Exploratory host; authoritative runs belong on a pinned Linux/x86 host. Raw JMH JSON: `rq-all.json`;
  capacity output: `capacity.txt`.
- Signing over a rotating pool of 128 transcripts, because ML-DSA signing time is message-dependent
  (rejection sampling); this averages that variance for a representative per-handshake cost.

## Component cost — server per-operation CPU and allocation

| Server operation | CPU (µs/op) | Allocation (bytes/op) |
|---|---|---|
| **Key exchange** | | |
| x25519 (keygen + agreement) | 77.34 | 2,876 |
| ml-kem-768 (encapsulate) | **31.57** | 23,304 |
| hybrid x25519+ml-kem-768 | 109.55 | 27,481 |
| **Authentication (transcript signature)** | | |
| ecdsa-p256 | 123.10 | 14,036 |
| rsa-2048 | 895.93 | 45,246 |
| ml-dsa-65 | 379.74 | 306,153 |
| slh-dsa-sha2-128f | **38,618** | **8,640,640** |

Two facts drive everything: (1) key exchange is cheap for all schemes — ML-KEM encapsulation (32 µs) is
actually *faster* than X25519 (77 µs); (2) authentication cost spans **three orders of magnitude**, from
123 µs (ECDSA) to 38.6 ms (SLH-DSA). Note ML-DSA (380 µs) is well under RSA-2048 (896 µs), and SLH-DSA
allocates **8.6 MB per signature** (615× ECDSA) from its hash-tree construction.

## RQ1/RQ4 — full-handshake server cost and amplification

Amplification is relative to the classical baseline `x25519 + ecdsa-p256`.

| Full handshake (kex + auth) | CPU (µs) | CPU amp | Allocation (bytes) | Mem amp |
|---|---|---|---|---|
| x25519 + ecdsa-p256 (classical) | 200.8 | 1.0× | 17,194 | 1.0× |
| x25519 + rsa-2048 | 974.7 | 4.9× | 48,403 | 2.8× |
| ml-kem-768 + ml-dsa-65 (PQC) | 518.2 | 2.6× | 314,235 | 18× |
| **ml-kem-768 + slh-dsa-sha2-128f (PQC worst)** | **38,696** | **192.7×** | **8,663,810** | **504×** |
| hybrid + ml-dsa-65 | 466.6 | 2.3× | 317,609 | 18× |

The PQC configuration with ML-DSA (2.6× CPU) sits between classical ECDSA and classical RSA — it is
*cheaper than an RSA-certificate server*. Only the SLH-DSA configuration is an outlier, and by a huge
margin on both CPU (193×) and memory (504×).

## RQ3 — sustained capacity (full handshakes/second)

| Configuration | 1 thread | 8 threads |
|---|---|---|
| x25519 + ecdsa-p256 (classical) | 4,983 | 25,437 |
| x25519 + rsa-2048 | 1,027 | 5,301 |
| ml-kem-768 + ml-dsa-65 (PQC) | 1,891 | 9,432 |
| **ml-kem-768 + slh-dsa-sha2-128f** | **26** | **144** |
| hybrid + ml-dsa-65 | 1,634 | 8,251 |

A server presenting **SLH-DSA certificates sustains only ~26 handshakes/second/core** — a ~190× drop
from classical — so an attacker needs a trivial ~26 requests/second to saturate a core. By contrast the
PQC ML-DSA server (1,891/s) outperforms the classical **RSA** server (1,027/s): migrating an
RSA-certificate server to ML-DSA *improves* DoS resistance.

## RQ4 — attacker-vs-server asymmetry

The attacker's request is a (precomputable, replayable) ClientHello whose key-share is 32 B (X25519),
1184 B (ML-KEM), or 1216 B (hybrid); the attacker spends ~no CPU. Per request, the server is forced to
spend up to 38.6 ms and allocate 8.6 MB under SLH-DSA — the definition of a potent amplifier. ML-KEM's
larger key-share modestly *raises* the attacker's bandwidth cost (a mild, incidental mitigation), while
its server CPU is lower than X25519 — so key exchange never favors the attacker.

## RQ5 / hypotheses

| Hypothesis | Outcome |
|---|---|
| H1 (cost dominated by auth, not KEX) | **Confirmed** — KEX ≤ 110 µs; auth spans 123 µs–38.6 ms. |
| H2 (ML-KEM KEX does not widen surface) | **Confirmed** — ML-KEM (32 µs) is faster than X25519 (77 µs). |
| H3 (ML-DSA 10–100× ECDSA; SLH-DSA 1000×+) | **Split: refuted for ML-DSA** (~3×, < RSA); **SLH-DSA is ~314× on the sign op, 193× full-handshake.** |
| H4 (PQC allocates far more per handshake) | **Confirmed** — SLH-DSA 8.6 MB/handshake; ML-DSA 0.31 MB; classical ≤ 48 KB. |
| H5 (SLH-DSA the worst amplifier by a wide margin) | **Confirmed** — 193× CPU / 504× memory / 190× capacity. |

## Significance and guidance

- **PQC is not a blanket DoS liability for TLS servers.** ML-KEM key exchange and ML-DSA authentication
  keep the server within a small factor of classical, and ML-DSA is *safer than RSA* on this axis.
- **SLH-DSA per-handshake server authentication is a severe DoS amplifier** and should be avoided for
  interactive, DoS-exposed TLS. SLH-DSA belongs to offline/infrequent signing (firmware, code signing),
  not the hot path. Where hash-based server auth is nonetheless required, aggressive rate-limiting,
  proof-of-work/client puzzles, session resumption, and TLS-layer caching of the CertificateVerify are
  necessary mitigations.
- The measured 8.6 MB allocation per SLH-DSA handshake is an independent memory/GC-pressure vector: a
  connection flood exhausts heap and induces GC pauses long before CPU alone would saturate.

## Caveats and next

- Exploratory unpinned host; authoritative magnitudes on a pinned Linux/x86 host. Relative orderings are
  expected to be robust.
- Model-based: we measure the server-side cryptographic work of a handshake, excluding socket/network
  cost (configuration-independent). A `bctls` end-to-end handshake would confirm the model in situ.
- ML-DSA signing time is message-dependent (rejection sampling); averaged here over a 128-transcript
  pool. Single implementation stack (BouncyCastle 1.84 / JDK JCE), one parameter set per family.
