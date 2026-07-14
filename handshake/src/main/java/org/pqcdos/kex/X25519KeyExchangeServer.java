package org.pqcdos.kex;

import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.pqcdos.util.DeterministicSecureRandom;

import java.security.SecureRandom;

/**
 * Classical X25519 (EC)DHE, server role: the server generates an ephemeral key pair and computes one
 * agreement against the client's ephemeral public key. Client key-share is a raw 32-byte public key.
 */
public final class X25519KeyExchangeServer implements KeyExchangeServer {

    private final SecureRandom rng = new DeterministicSecureRandom(11);
    private final byte[] clientPublic;

    public X25519KeyExchangeServer() {
        X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
        gen.init(new X25519KeyGenerationParameters(rng));
        this.clientPublic = ((X25519PublicKeyParameters) gen.generateKeyPair().getPublic()).getEncoded();
    }

    @Override
    public String name() {
        return "x25519";
    }

    @Override
    public int clientShareBytes() {
        return 32;
    }

    @Override
    public byte[] clientKeyShare() {
        return clientPublic.clone();
    }

    @Override
    public byte[] serverKeyExchange(byte[] clientShare) {
        X25519PublicKeyParameters clientPub = new X25519PublicKeyParameters(clientShare, 0);
        X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
        gen.init(new X25519KeyGenerationParameters(rng));
        X25519PrivateKeyParameters serverPriv = (X25519PrivateKeyParameters) gen.generateKeyPair().getPrivate();

        byte[] sharedSecret = new byte[32];
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(serverPriv);
        agreement.calculateAgreement(clientPub, sharedSecret, 0);
        return sharedSecret;
    }
}
