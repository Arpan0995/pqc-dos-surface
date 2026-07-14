package org.pqcdos;

import org.pqcdos.auth.JcaSignatureAuth;
import org.pqcdos.auth.MlDsa65Auth;
import org.pqcdos.auth.ServerAuth;
import org.pqcdos.auth.SlhDsa128fAuth;
import org.pqcdos.kex.HybridKeyExchangeServer;
import org.pqcdos.kex.KeyExchangeServer;
import org.pqcdos.kex.MlKem768KeyExchangeServer;
import org.pqcdos.kex.X25519KeyExchangeServer;

import java.util.List;

/**
 * Builds key-exchange and authentication components by name and assembles representative full
 * handshakes, so tests, benchmarks, and the capacity harness share one source of configurations.
 */
public final class Configs {

    public static final String KEX_X25519 = "x25519";
    public static final String KEX_MLKEM = "ml-kem-768";
    public static final String KEX_HYBRID = "hybrid-x25519-mlkem768";

    public static final String AUTH_ECDSA = "ecdsa-p256";
    public static final String AUTH_RSA = "rsa-2048";
    public static final String AUTH_MLDSA = "ml-dsa-65";
    public static final String AUTH_SLHDSA = "slh-dsa-sha2-128f";

    /** A named full handshake configuration (key exchange + authentication). */
    public record Config(String kex, String auth) {
        public String id() {
            return kex + "__" + auth;
        }
    }

    private Configs() {
    }

    public static List<String> kexNames() {
        return List.of(KEX_X25519, KEX_MLKEM, KEX_HYBRID);
    }

    public static List<String> authNames() {
        return List.of(AUTH_ECDSA, AUTH_RSA, AUTH_MLDSA, AUTH_SLHDSA);
    }

    /** Representative end-to-end handshakes: classical, classical-RSA, PQC, PQC-worst, and hybrid. */
    public static List<Config> representativeConfigs() {
        return List.of(
                new Config(KEX_X25519, AUTH_ECDSA),   // classical baseline
                new Config(KEX_X25519, AUTH_RSA),     // classical with RSA auth
                new Config(KEX_MLKEM, AUTH_MLDSA),    // PQC
                new Config(KEX_MLKEM, AUTH_SLHDSA),   // PQC worst case (SLH-DSA auth)
                new Config(KEX_HYBRID, AUTH_MLDSA));  // hybrid
    }

    public static KeyExchangeServer kex(String name) {
        return switch (name) {
            case KEX_X25519 -> new X25519KeyExchangeServer();
            case KEX_MLKEM -> new MlKem768KeyExchangeServer();
            case KEX_HYBRID -> new HybridKeyExchangeServer();
            default -> throw new IllegalArgumentException("Unknown key exchange: " + name);
        };
    }

    public static ServerAuth auth(String name) {
        return switch (name) {
            case AUTH_ECDSA -> JcaSignatureAuth.ecdsaP256();
            case AUTH_RSA -> JcaSignatureAuth.rsa2048();
            case AUTH_MLDSA -> new MlDsa65Auth();
            case AUTH_SLHDSA -> new SlhDsa128fAuth();
            default -> throw new IllegalArgumentException("Unknown auth: " + name);
        };
    }

    public static ServerHandshake handshake(String kexName, String authName) {
        return new ServerHandshake(kex(kexName), auth(authName));
    }

    public static ServerHandshake handshake(Config config) {
        return handshake(config.kex(), config.auth());
    }
}
