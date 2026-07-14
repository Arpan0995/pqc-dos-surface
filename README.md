# pqc-dos-surface

**Does post-quantum cryptography widen the denial-of-service attack surface of Java TLS servers?**

A DoS amplifier exists when an attacker forces a server to spend far more than the attacker spends. A
TLS 1.3 full handshake makes the server do per-connection cryptographic work — a key exchange plus a
signature over the transcript for server authentication — in response to a ClientHello the attacker can
precompute and replay. This project measures, uniformly on the JVM, how much **server** CPU and memory
each classical, PQC, and hybrid configuration forces per unit of **attacker** effort, and thus whether
migrating to PQC — and which schemes — widens the DoS surface.

The central hypothesis: the surface is dominated by **server-side signature generation**, not key
exchange. ML-KEM encapsulation is cheap, but ML-DSA and especially **SLH-DSA** signing is expensive, so
a server presenting SLH-DSA certificates may be a severe amplifier.

## Status

Model + benchmarks implemented; first results in. Pre-registered design in
[`docs/EXPERIMENT-DESIGN.md`](docs/EXPERIMENT-DESIGN.md); full results in
[`results/RESULTS.md`](results/RESULTS.md).

**Headline (exploratory macOS/arm64 host):** PQC does **not** uniformly widen the TLS server DoS
surface. ML-KEM key exchange is DoS-neutral-to-favorable (32 µs, faster than X25519's 77 µs), and
ML-DSA authentication is a modest ~2–3× factor over ECDSA — and *cheaper than RSA*. The DoS risk is
concentrated in **SLH-DSA authentication**: ~39 ms and **8.6 MB allocated per handshake**, collapsing
server capacity to **~26 handshakes/sec/core (vs ~4,983 classical)** — a ~190× amplifier. SLH-DSA
should not be used for per-handshake interactive server auth under DoS exposure.

## Configurations

Server handshake work = one key-exchange operation (server role) + one authentication signature.

- **Key exchange:** `x25519`, `ml-kem-768`, `hybrid-x25519-mlkem768`
- **Authentication:** `ecdsa-p256`, `rsa-2048`, `ml-dsa-65`, `slh-dsa-sha2-128f`

## Toolchain

Java 21 (pinned OpenJDK 21); BouncyCastle `bcprov-jdk18on` 1.84 (ML-KEM/ML-DSA/SLH-DSA/X25519) + JDK JCE
(ECDSA/RSA); JMH 1.37; Maven multi-module. Apple-Silicon runs are exploratory; authoritative runs on a
pinned Linux/x86-64 host.

## Layout

```
docs/EXPERIMENT-DESIGN.md   Pre-registered design (read this first)
handshake/                  Server-side handshake work model (KEX + auth)
benchmarks/                 JMH CPU/allocation benchmarks + concurrent capacity harness
results/                    Raw JMH data + summaries (reproducible)
```

## License

Apache-2.0 (see `LICENSE`).
