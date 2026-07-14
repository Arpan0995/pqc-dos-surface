# Experimental Design — The DoS Attack Surface of Post-Quantum TLS on Java Servers

**Working title:** *Cheap to Ask, Expensive to Answer: Quantifying the Denial-of-Service Amplification
of Post-Quantum Authentication in Java TLS Servers*

**Author:** Arpan Sharma
**Status:** Design draft v0.1 — pre-registration of research questions, hypotheses, and method. No
results yet.
**Repository:** `pqc-dos-surface` (standalone).

---

## 1. Motivation and gap

A denial-of-service (DoS) amplifier exists whenever an attacker can force a server to spend far more
resources answering a request than the attacker spent making it. TLS 1.3 handshakes are a classic
target: a client sends a small ClientHello and the server must perform per-handshake cryptographic
work. The migration to post-quantum cryptography (PQC) changes the arithmetic of that exchange, because
PQC keys, ciphertexts, and — above all — signatures are larger and, for some schemes, far more
expensive to compute than their classical counterparts.

Existing PQC benchmarks report primitive speed in isolation; PQC-TLS studies mostly report median
handshake latency on clean links. **What is unmeasured is the adversarial framing**: how much *server*
CPU and memory a PQC handshake forces per unit of *attacker* effort, and therefore whether adopting PQC
widens the DoS attack surface of a Java TLS server — the platform that fronts a large share of
enterprise and government services. This project measures that amplification directly.

## 2. The key insight (what makes this a security result, not a benchmark)

In a TLS 1.3 full handshake the server performs two classes of cryptographic work per connection:

1. **Key exchange (server side).** For an (EC)DHE group the server generates an ephemeral key pair and
   computes one agreement; for a KEM group (ML-KEM) the server performs one encapsulation against the
   client-supplied public key. Both are cheap.
2. **Server authentication.** The server signs the handshake transcript with its long-term certificate
   private key (the TLS 1.3 CertificateVerify message) **on every full handshake**.

The attacker's cost to trigger this is near zero: a ClientHello can be precomputed and replayed. The
server's cost is dominated by the **signature generation**, which is exactly where PQC diverges most
from classical crypto: ML-DSA signing is milliseconds and SLH-DSA signing is tens of milliseconds,
versus microseconds for ECDSA. The hypothesis this project tests is therefore that **PQC's DoS surface
on servers is driven by signature-based authentication, not by key exchange** — and that a server
configured with SLH-DSA certificates is a potent amplifier.

## 3. Threat model

An attacker who can open TCP connections and send (possibly replayed) ClientHello messages, at a rate
bounded by their bandwidth, aiming to exhaust the server's CPU or memory so that legitimate handshakes
are delayed or dropped. We model an attacker who forces **full** handshakes (the expensive path); TLS
session resumption / PSK, connection rate-limiting, and client puzzles are mitigations discussed but
not assumed. We measure the server-side cryptographic work per handshake; network and socket overheads
are configuration-independent and excluded so the comparison isolates the crypto attack surface.

## 4. Configurations under test

Server-side handshake work = one key-exchange operation + one authentication signature. We vary each.

**Key exchange (server role):**

| Config | Server work | Client key-share size (attacker bytes) |
|---|---|---|
| `x25519` | ephemeral keygen + agreement | 32 B |
| `ml-kem-768` | encapsulate to client public key | 1184 B |
| `hybrid-x25519-mlkem768` | both | 1216 B |

**Server authentication (transcript signature):**

| Config | Signature op | Signature size |
|---|---|---|
| `ecdsa-p256` | ECDSA sign | ~64–72 B |
| `rsa-2048` | RSA sign | 256 B |
| `ml-dsa-65` | ML-DSA sign | ~3309 B |
| `slh-dsa-sha2-128f` | SLH-DSA sign | ~17088 B |

Representative full handshakes: classical (`x25519 + ecdsa-p256`), PQC (`ml-kem-768 + ml-dsa-65`),
PQC-worst (`ml-kem-768 + slh-dsa-128f`), hybrid (`hybrid + ml-dsa-65`).

## 5. Research questions

- **RQ1 (CPU per handshake).** What is the server-side CPU time per handshake for each key-exchange and
  authentication configuration, and how does PQC compare to classical?
- **RQ2 (memory per handshake).** How many bytes does the server allocate per handshake for each
  configuration (JMH GC profiler), and how large are the per-connection objects an attacker forces the
  server to hold?
- **RQ3 (capacity / throughput).** How many handshakes per second can one server core sustain per
  configuration, single- and multi-threaded — i.e., how easily is it saturated?
- **RQ4 (amplification factor).** The headline metric: server CPU-time (and allocation) forced per unit
  of attacker effort (per ClientHello / per attacker byte), per configuration, relative to the
  classical baseline.
- **RQ5 (worst case and mitigation headroom).** Which configuration is the strongest amplifier, and by
  how much does it exceed the classical baseline?

## 6. Hypotheses (pre-registered)

- **H1.** Server per-handshake CPU is dominated by authentication, not key exchange: KEX differences
  (X25519 vs ML-KEM vs hybrid) are small, while auth differences span orders of magnitude.
- **H2.** ML-KEM key exchange does **not** meaningfully widen the DoS surface (encapsulation is cheap),
  consistent with ML-KEM being competitive on server work.
- **H3.** ML-DSA authentication multiplies server per-handshake CPU by ~10–100× over ECDSA; SLH-DSA
  (sha2-128f) multiplies it by ~1000×+, making it a severe amplifier.
- **H4.** Memory allocation per handshake is far larger for PQC (SLH-DSA's ~17 KB signature dominates),
  so a connection flood exhausts heap faster under PQC authentication.
- **H5.** The amplification factor (server work per attacker byte) is worst for SLH-DSA authentication
  by a wide margin, because a tiny replayed ClientHello forces tens of milliseconds of server signing.

A hypothesis proven false is as valuable as one confirmed; the contribution is the measured surface.

## 7. Methodology

- **Server-side work model.** A faithful model of the server's per-handshake cryptography for each
  configuration (KEX server role + transcript signature), using BouncyCastle 1.84 (ML-KEM, ML-DSA,
  SLH-DSA, X25519 lightweight API) and the JDK JCE (ECDSA, RSA). Network/socket handling is excluded as
  configuration-independent; the transcript is a fixed-size hash input.
- **CPU per handshake (RQ1, RQ4).** JMH `AverageTime` for the full server handshake work and for KEX
  and auth components separately, so amplification can be attributed.
- **Memory per handshake (RQ2, RQ4).** JMH GC profiler (`-prof gc`) reporting normalized allocation
  (bytes/op) per configuration.
- **Capacity (RQ3).** A concurrent capacity harness executing server handshake work across a thread
  pool as fast as possible, reporting sustained handshakes/second (1 and N threads) and peak heap under
  a fixed backlog of concurrent handshakes (the "connection flood" memory picture).
- **Correctness gate.** Each configuration must perform a *valid* server operation (agreement/encaps
  succeeds; signature verifies under the server's public key) before its cost is reported — so we are
  measuring real work, not a mis-wired no-op.

## 8. Metrics and reporting

Per configuration: server CPU µs/handshake (KEX, auth, total); allocation bytes/handshake; sustained
handshakes/s (1 and 8 threads); amplification factor vs the classical `x25519 + ecdsa-p256` baseline;
attacker bytes per handshake and the resulting server-work-per-attacker-byte ratio. Raw JMH JSON and a
results summary are committed.

## 9. Threats to validity

- **Exploratory host.** Apple-Silicon (arm64), unpinned; treated as exploratory, authoritative runs on
  a pinned Linux/x86-64 host. Recorded in every artifact.
- **Model vs full stack.** We measure server-side crypto work, not a full socket TLS handshake; this is
  a deliberate scoping (socket/network cost is configuration-independent). A `bctls`-based end-to-end
  handshake is a natural extension to confirm the model in situ.
- **Library specificity.** Tied to BouncyCastle 1.84 and the JDK JCE; pinned and recorded.
- **Signing-key caching.** Server signing keys are expanded once (as a real server would), so signing
  cost excludes key setup — the realistic per-handshake cost.

## 10. Reproducibility

Pinned OpenJDK 21, BouncyCastle 1.84, JMH 1.37, deterministic seeds. Every artifact embeds the JDK,
JVM flags, and host details; benchmarks run from a single shaded JAR; raw data committed.

## 11. Deliverables and target venues

- **Artifact:** an open-source, uniform Java model of TLS 1.3 server handshake work across classical,
  PQC, and hybrid configurations, with CPU/memory/capacity/amplification instrumentation.
- **Paper:** the first quantification of the PQC handshake DoS amplification surface on the JVM, with an
  explicit attacker-vs-server cost ratio and a concrete worst case (SLH-DSA authentication).
  - Venues: ACSAC, DIMVA, IEEE EuroS&P workshops; a security (not benchmarking) framing.

## 12. Non-goals

- Not a working DoS exploit against a live service; we quantify the amplification surface.
- Not a full socket/TLS record-layer implementation (model-based server-work measurement).
- Not client-side cost (the attacker's side), except as the "attacker effort" denominator.
- Not mitigations engineering (rate limits, puzzles, resumption) beyond discussion.

---

*Pre-registration: research questions, configurations, and hypotheses are fixed before data collection
so that a result contrary to a hypothesis carries the same weight as a confirming one.*
