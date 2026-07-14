package org.pqcdos.bench;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.pqcdos.Configs;
import org.pqcdos.auth.ServerAuth;
import org.pqcdos.util.DeterministicSecureRandom;

import java.util.concurrent.TimeUnit;

/**
 * RQ1/RQ4 (authentication component): server-side transcript signing time per scheme — the hypothesized
 * dominant per-handshake cost. Run with {@code -prof gc} to also capture allocation (RQ2).
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 6, time = 1)
@Fork(1)
public class AuthBenchmark {

    @Param({"ecdsa-p256", "rsa-2048", "ml-dsa-65", "slh-dsa-sha2-128f"})
    public String auth;

    private static final int POOL = 128;

    private ServerAuth serverAuth;
    private byte[][] transcripts;
    private int cursor;

    @Setup
    public void setup() {
        serverAuth = Configs.auth(auth);
        // Rotate over a pool of transcripts: ML-DSA signing time is message-dependent (rejection
        // sampling), so a single fixed transcript is an unrepresentative sample.
        transcripts = new byte[POOL][64];
        DeterministicSecureRandom rng = new DeterministicSecureRandom(7);
        for (byte[] t : transcripts) {
            rng.nextBytes(t);
        }
    }

    @Benchmark
    public byte[] sign() {
        return serverAuth.sign(transcripts[cursor++ & (POOL - 1)]);
    }
}
