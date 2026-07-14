package org.pqcdos.bench;

import org.pqcdos.Configs;
import org.pqcdos.ServerHandshake;

import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicLong;

/**
 * RQ3 --- sustained server capacity: how many full handshakes per second each configuration supports at
 * 1 and 8 threads, i.e. how easily an attacker saturates the server. Each worker thread builds its own
 * {@link ServerHandshake} (the ML-DSA/SLH-DSA signers are stateful and not shared), warms up, then
 * counts handshakes performed within a fixed measurement window.
 *
 * <pre>java -cp benchmarks/target/benchmarks.jar org.pqcdos.bench.CapacityHarness</pre>
 */
public final class CapacityHarness {

    private static final long WARMUP_MS = 2_000;
    private static final long MEASURE_MS = 3_000;
    private static final int[] THREAD_COUNTS = {1, 8};

    private CapacityHarness() {
    }

    public static void main(String[] args) throws InterruptedException {
        System.out.println("Sustained server capacity (full handshakes/second)");
        System.out.printf(Locale.ROOT, "%-42s %14s %14s%n", "configuration (kex + auth)", "1 thread", "8 threads");
        System.out.println("-".repeat(72));

        for (Configs.Config config : Configs.representativeConfigs()) {
            StringBuilder row = new StringBuilder(String.format(Locale.ROOT, "%-42s", config.kex() + " + " + config.auth()));
            for (int threads : THREAD_COUNTS) {
                double hps = measure(config, threads);
                row.append(String.format(Locale.ROOT, " %14s", String.format(Locale.ROOT, "%,.0f", hps)));
            }
            System.out.println(row);
        }
        System.out.println("-".repeat(72));
        System.out.println("Higher = harder to saturate. Lower numbers are cheaper to DoS.");
    }

    private static double measure(Configs.Config config, int threads) throws InterruptedException {
        AtomicLong measuredOps = new AtomicLong();
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch done = new CountDownLatch(threads);

        long now = System.currentTimeMillis();
        long measureStart = now + WARMUP_MS;
        long measureEnd = measureStart + MEASURE_MS;

        for (int t = 0; t < threads; t++) {
            Thread worker = new Thread(() -> {
                ServerHandshake hs = Configs.handshake(config); // per-thread instance
                ready.countDown();
                long local = 0;
                long sink = 0;
                while (true) {
                    long ts = System.currentTimeMillis();
                    if (ts >= measureEnd) {
                        break;
                    }
                    sink += hs.perform();
                    if (ts >= measureStart) {
                        local++;
                    }
                }
                measuredOps.addAndGet(local);
                if (sink == Long.MIN_VALUE) {
                    System.out.print("");
                }
                done.countDown();
            }, "hs-worker-" + t);
            worker.setDaemon(true);
            worker.start();
        }

        ready.await();
        done.await();
        return measuredOps.get() / (MEASURE_MS / 1000.0);
    }
}
