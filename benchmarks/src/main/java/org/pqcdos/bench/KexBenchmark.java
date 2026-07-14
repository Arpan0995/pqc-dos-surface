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
import org.pqcdos.kex.KeyExchangeServer;

import java.util.concurrent.TimeUnit;

/**
 * RQ1/RQ4 (key-exchange component): server-side key-exchange time per scheme. Expected to be small and
 * similar across schemes, demonstrating that key exchange is not the DoS driver. Run with {@code -prof gc}
 * for allocation.
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 6, time = 1)
@Fork(1)
public class KexBenchmark {

    @Param({"x25519", "ml-kem-768", "hybrid-x25519-mlkem768"})
    public String kex;

    private KeyExchangeServer server;
    private byte[] clientShare;

    @Setup
    public void setup() {
        server = Configs.kex(kex);
        clientShare = server.clientKeyShare();
    }

    @Benchmark
    public byte[] serverKeyExchange() {
        return server.serverKeyExchange(clientShare);
    }
}
