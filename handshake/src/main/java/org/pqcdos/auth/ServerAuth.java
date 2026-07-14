package org.pqcdos.auth;

/**
 * Models the <em>server authentication</em> step of a TLS 1.3 handshake: the server signs the handshake
 * transcript with its long-term certificate private key (the CertificateVerify message) on every full
 * handshake. This is hypothesized to be the dominant per-handshake cost and therefore the primary DoS
 * amplification factor — which is exactly where PQC diverges most from classical signatures.
 */
public interface ServerAuth {

    /** Stable configuration identifier used in results. */
    String name();

    /** Approximate signature size in bytes (the object the server produces and buffers per handshake). */
    int signatureBytes();

    /** The server's per-handshake signing work over the transcript. */
    byte[] sign(byte[] transcript);

    /** Verify a signature under the server's public key (used by the correctness gate, not measured). */
    boolean verify(byte[] transcript, byte[] signature);
}
