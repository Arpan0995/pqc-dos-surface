package org.pqcdos.kex;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.pqcdos.util.DeterministicSecureRandom;

import java.security.SecureRandom;

/**
 * ML-KEM-768 key exchange, server role: the server encapsulates against the client's ML-KEM public key
 * (sent in the ClientHello key-share) and derives the shared secret. Client key-share is the 1184-byte
 * ML-KEM public key. Encapsulation is cheap, so this tests whether PQC key exchange widens the DoS
 * surface (hypothesis: it does not).
 */
public final class MlKem768KeyExchangeServer implements KeyExchangeServer {

    private final SecureRandom rng = new DeterministicSecureRandom(12);
    private final byte[] clientPublic;

    public MlKem768KeyExchangeServer() {
        MLKEMKeyPairGenerator kpg = new MLKEMKeyPairGenerator();
        kpg.init(new MLKEMKeyGenerationParameters(rng, MLKEMParameters.ml_kem_768));
        this.clientPublic = ((MLKEMPublicKeyParameters) kpg.generateKeyPair().getPublic()).getEncoded();
    }

    @Override
    public String name() {
        return "ml-kem-768";
    }

    @Override
    public int clientShareBytes() {
        return clientPublic.length;
    }

    @Override
    public byte[] clientKeyShare() {
        return clientPublic.clone();
    }

    @Override
    public byte[] serverKeyExchange(byte[] clientShare) {
        MLKEMPublicKeyParameters clientPub =
                new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, clientShare);
        SecretWithEncapsulation swe = new MLKEMGenerator(rng).generateEncapsulated(clientPub);
        return swe.getSecret();
    }
}
