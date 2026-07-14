package org.pqcdos;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pqcdos.auth.ServerAuth;
import org.pqcdos.kex.KeyExchangeServer;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Correctness gate: every component performs a valid operation before its cost is reported, so the
 * benchmarks measure real server work rather than a mis-wired no-op.
 */
class HandshakeCorrectnessTest {

    static List<String> kexNames() {
        return Configs.kexNames();
    }

    static List<String> authNames() {
        return Configs.authNames();
    }

    static List<Configs.Config> configs() {
        return Configs.representativeConfigs();
    }

    @ParameterizedTest
    @MethodSource("kexNames")
    void keyExchangeProducesANonEmptySharedSecret(String name) {
        KeyExchangeServer kex = Configs.kex(name);
        byte[] share = kex.clientKeyShare();
        assertEquals(kex.clientShareBytes(), share.length, name + ": client-share size");
        byte[] secret = kex.serverKeyExchange(share);
        assertNotNull(secret);
        assertTrue(secret.length >= 32, name + ": shared secret should be >= 32 bytes, was " + secret.length);
    }

    @ParameterizedTest
    @MethodSource("authNames")
    void authSignsAndVerifies(String name) {
        ServerAuth auth = Configs.auth(name);
        byte[] transcript = "TLS 1.3 CertificateVerify transcript hash (test vector)".getBytes();
        byte[] sig = auth.sign(transcript);
        assertNotNull(sig);
        assertTrue(auth.verify(transcript, sig), name + ": signature must verify");

        byte[] tampered = transcript.clone();
        tampered[0] ^= 0x01;
        assertFalse(auth.verify(tampered, sig), name + ": signature must not verify for a different transcript");
    }

    @ParameterizedTest
    @MethodSource("configs")
    void fullHandshakePerformsWithoutError(Configs.Config config) {
        ServerHandshake hs = Configs.handshake(config);
        long result = hs.perform();
        assertTrue(result > 0, config.id() + ": handshake should return a positive size marker");
        assertTrue(hs.attackerBytes() > 0);
    }

    @Test
    void slhDsaAuthProducesTheLargestSignature() {
        // Sanity check on the ordering that drives the memory-amplification result.
        int ecdsa = Configs.auth(Configs.AUTH_ECDSA).signatureBytes();
        int mldsa = Configs.auth(Configs.AUTH_MLDSA).signatureBytes();
        int slhdsa = Configs.auth(Configs.AUTH_SLHDSA).signatureBytes();
        assertTrue(ecdsa < mldsa && mldsa < slhdsa,
                "signature sizes should order ECDSA < ML-DSA < SLH-DSA");
    }
}
