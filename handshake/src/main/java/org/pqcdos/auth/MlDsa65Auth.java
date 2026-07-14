package org.pqcdos.auth;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.pqcdos.util.DeterministicSecureRandom;
import org.pqcdos.util.DosException;

/**
 * ML-DSA-65 (FIPS 204) server authentication. The signing key is expanded once; each handshake resets
 * the pre-initialized signer and signs the transcript (deterministic signing). ML-DSA signatures are
 * ~3.3 KB and signing is milliseconds — far heavier than ECDSA, which is the DoS point.
 */
public final class MlDsa65Auth implements ServerAuth {

    private final MLDSAPublicKeyParameters publicKey;
    private final MLDSASigner signer;

    public MlDsa65Auth() {
        MLDSAKeyPairGenerator kpg = new MLDSAKeyPairGenerator();
        kpg.init(new MLDSAKeyGenerationParameters(new DeterministicSecureRandom(23), MLDSAParameters.ml_dsa_65));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        this.publicKey = (MLDSAPublicKeyParameters) kp.getPublic();
        this.signer = new MLDSASigner();
        this.signer.init(true, (MLDSAPrivateKeyParameters) kp.getPrivate());
    }

    @Override
    public String name() {
        return "ml-dsa-65";
    }

    @Override
    public int signatureBytes() {
        return 3309;
    }

    @Override
    public byte[] sign(byte[] transcript) {
        signer.reset();
        signer.update(transcript, 0, transcript.length);
        try {
            return signer.generateSignature();
        } catch (CryptoException e) {
            throw new DosException("ML-DSA signing failed", e);
        }
    }

    @Override
    public boolean verify(byte[] transcript, byte[] signature) {
        MLDSASigner v = new MLDSASigner();
        v.init(false, publicKey);
        v.update(transcript, 0, transcript.length);
        return v.verifySignature(signature);
    }
}
