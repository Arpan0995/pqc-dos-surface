package org.pqcdos.auth;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner;
import org.pqcdos.util.DeterministicSecureRandom;

/**
 * SLH-DSA (FIPS 205, sha2-128f) server authentication — the hypothesized worst-case DoS amplifier.
 * SLH-DSA signatures are ~17 KB and signing is tens of milliseconds (thousands of hash calls), so a
 * server that signs with SLH-DSA per handshake forces enormous work for a trivial attacker request.
 * The fast (f) variant is used; the small (s) variants sign even more slowly.
 */
public final class SlhDsa128fAuth implements ServerAuth {

    private final SLHDSAPublicKeyParameters publicKey;
    private final SLHDSASigner signer;

    public SlhDsa128fAuth() {
        SLHDSAKeyPairGenerator kpg = new SLHDSAKeyPairGenerator();
        kpg.init(new SLHDSAKeyGenerationParameters(new DeterministicSecureRandom(24), SLHDSAParameters.sha2_128f));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        this.publicKey = (SLHDSAPublicKeyParameters) kp.getPublic();
        this.signer = new SLHDSASigner();
        this.signer.init(true, (SLHDSAPrivateKeyParameters) kp.getPrivate());
    }

    @Override
    public String name() {
        return "slh-dsa-sha2-128f";
    }

    @Override
    public int signatureBytes() {
        return 17088;
    }

    @Override
    public byte[] sign(byte[] transcript) {
        return signer.generateSignature(transcript);
    }

    @Override
    public boolean verify(byte[] transcript, byte[] signature) {
        SLHDSASigner v = new SLHDSASigner();
        v.init(false, publicKey);
        return v.verifySignature(transcript, signature);
    }
}
