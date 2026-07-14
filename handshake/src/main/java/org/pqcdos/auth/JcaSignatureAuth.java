package org.pqcdos.auth;

import org.pqcdos.util.DeterministicSecureRandom;
import org.pqcdos.util.DosException;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

/**
 * Classical JCA signature server authentication (ECDSA-P256 and RSA-2048). The signing key is generated
 * and loaded once; each {@link #sign} performs one signature over the transcript, as a real server does
 * per handshake. Signature objects are reused per instance (single-threaded per handshake worker).
 */
public final class JcaSignatureAuth implements ServerAuth {

    private final String id;
    private final int signatureBytes;
    private final PublicKey publicKey;
    private final Signature signer;
    private final String sigAlgorithm;

    private JcaSignatureAuth(String id, int signatureBytes, String keyAlgorithm,
                             AlgorithmParameterSpec keySpec, int rsaKeySize, String sigAlgorithm, long seed) {
        try {
            this.id = id;
            this.signatureBytes = signatureBytes;
            this.sigAlgorithm = sigAlgorithm;
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm);
            if (keySpec != null) {
                kpg.initialize(keySpec, new DeterministicSecureRandom(seed));
            } else {
                kpg.initialize(rsaKeySize, new DeterministicSecureRandom(seed));
            }
            KeyPair kp = kpg.generateKeyPair();
            this.publicKey = kp.getPublic();
            this.signer = Signature.getInstance(sigAlgorithm);
            this.signer.initSign(kp.getPrivate());
        } catch (GeneralSecurityException e) {
            throw new DosException("JCA auth setup failed for " + id, e);
        }
    }

    public static JcaSignatureAuth ecdsaP256() {
        return new JcaSignatureAuth("ecdsa-p256", 72, "EC",
                new ECGenParameterSpec("secp256r1"), 0, "SHA256withECDSA", 21);
    }

    public static JcaSignatureAuth rsa2048() {
        return new JcaSignatureAuth("rsa-2048", 256, "RSA", null, 2048, "SHA256withRSA", 22);
    }

    @Override
    public String name() {
        return id;
    }

    @Override
    public int signatureBytes() {
        return signatureBytes;
    }

    @Override
    public byte[] sign(byte[] transcript) {
        try {
            signer.update(transcript);
            return signer.sign(); // leaves the Signature reinitialized for the next handshake
        } catch (GeneralSecurityException e) {
            throw new DosException("signing failed for " + id, e);
        }
    }

    @Override
    public boolean verify(byte[] transcript, byte[] signature) {
        try {
            Signature v = Signature.getInstance(sigAlgorithm);
            v.initVerify(publicKey);
            v.update(transcript);
            return v.verify(signature);
        } catch (GeneralSecurityException e) {
            throw new DosException("verify failed for " + id, e);
        }
    }
}
