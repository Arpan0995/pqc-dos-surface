package org.pqcdos;

import org.pqcdos.auth.ServerAuth;
import org.pqcdos.kex.KeyExchangeServer;
import org.pqcdos.util.DeterministicSecureRandom;

/**
 * The server-side cryptographic work of one TLS 1.3 full handshake: one key exchange (server role) plus
 * one transcript signature for server authentication. This is what an attacker forces the server to do
 * per (precomputable, replayable) ClientHello. The class exposes the whole handshake and each half
 * separately so the benchmarks can attribute cost between key exchange and authentication.
 */
public final class ServerHandshake {

    /** TLS 1.3 CertificateVerify signs a fixed-size transcript hash input; 64 bytes is representative. */
    private static final int TRANSCRIPT_BYTES = 64;

    /**
     * A pool of distinct transcripts, rotated per handshake. This is important because ML-DSA signing
     * time is message-dependent (rejection sampling), so signing one fixed transcript repeatedly gives
     * a single, unrepresentative sample; rotating over a pool averages over that variance and models a
     * real server signing a different transcript on every handshake. Size is a power of two for a cheap
     * masked cursor.
     */
    private static final int TRANSCRIPT_POOL = 128;

    private final KeyExchangeServer kex;
    private final ServerAuth auth;
    private final byte[] clientShare;
    private final byte[][] transcripts;
    private int cursor;

    public ServerHandshake(KeyExchangeServer kex, ServerAuth auth) {
        this.kex = kex;
        this.auth = auth;
        this.clientShare = kex.clientKeyShare();
        this.transcripts = new byte[TRANSCRIPT_POOL][TRANSCRIPT_BYTES];
        DeterministicSecureRandom rng = new DeterministicSecureRandom(99);
        for (byte[] t : transcripts) {
            rng.nextBytes(t);
        }
    }

    private byte[] nextTranscript() {
        return transcripts[cursor++ & (TRANSCRIPT_POOL - 1)];
    }

    public String kexName() {
        return kex.name();
    }

    public String authName() {
        return auth.name();
    }

    public String label() {
        return kex.name() + " + " + auth.name();
    }

    /** Bytes the attacker must send to trigger this handshake (the key-share; ClientHello framing aside). */
    public int attackerBytes() {
        return kex.clientShareBytes();
    }

    public int signatureBytes() {
        return auth.signatureBytes();
    }

    /** Full server per-handshake work: key exchange then authentication signature. */
    public long perform() {
        byte[] sharedSecret = kex.serverKeyExchange(clientShare);
        byte[] signature = auth.sign(nextTranscript());
        return (long) sharedSecret.length + signature.length;
    }

    /** Just the server key-exchange work (for cost attribution). */
    public byte[] performKeyExchange() {
        return kex.serverKeyExchange(clientShare);
    }

    /** Just the server authentication signature (for cost attribution). */
    public byte[] performAuth() {
        return auth.sign(nextTranscript());
    }
}
