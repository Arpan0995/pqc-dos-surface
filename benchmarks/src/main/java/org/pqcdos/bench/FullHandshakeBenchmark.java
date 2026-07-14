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
import org.pqcdos.ServerHandshake;

import java.util.concurrent.TimeUnit;

/**
 * RQ1/RQ4 (full handshake): total server per-handshake work (key exchange + authentication) for the
 * representative configurations. This is the quantity an attacker forces per ClientHello. Run with
 * {@code -prof gc} to capture per-handshake allocation (RQ2).
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 6, time = 1)
@Fork(1)
public class FullHandshakeBenchmark {

    @Param({
            "x25519__ecdsa-p256",
            "x25519__rsa-2048",
            "ml-kem-768__ml-dsa-65",
            "ml-kem-768__slh-dsa-sha2-128f",
            "hybrid-x25519-mlkem768__ml-dsa-65"
    })
    public String config;

    private ServerHandshake handshake;

    @Setup
    public void setup() {
        String[] parts = config.split("__");
        handshake = Configs.handshake(parts[0], parts[1]);
    }

    @Benchmark
    public long fullHandshake() {
        return handshake.perform();
    }
}
