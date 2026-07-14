package org.pqcdos.util;

import java.security.SecureRandom;
import java.util.random.RandomGenerator;
import java.util.random.RandomGeneratorFactory;

/**
 * A {@link SecureRandom} whose output is fully determined by a seed, so key material is reproducible
 * across runs. For experiment reproducibility only; not cryptographically secure.
 */
public final class DeterministicSecureRandom extends SecureRandom {

    private final RandomGenerator rng;

    public DeterministicSecureRandom(long seed) {
        super();
        this.rng = RandomGeneratorFactory.of("L64X128MixRandom").create(seed);
    }

    @Override
    public void nextBytes(byte[] bytes) {
        int i = 0;
        while (i < bytes.length) {
            long r = rng.nextLong();
            for (int b = 0; b < 8 && i < bytes.length; b++, i++) {
                bytes[i] = (byte) (r & 0xFF);
                r >>>= 8;
            }
        }
    }

    @Override
    public byte[] generateSeed(int numBytes) {
        byte[] out = new byte[numBytes];
        nextBytes(out);
        return out;
    }
}
