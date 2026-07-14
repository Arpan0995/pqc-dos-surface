package org.pqcdos.kex;

import java.util.Arrays;

/**
 * Hybrid X25519 + ML-KEM-768 key exchange, server role: the server performs both the X25519 agreement
 * and the ML-KEM encapsulation, and concatenates the two shared secrets. Client key-share is the
 * 32-byte X25519 public key followed by the 1184-byte ML-KEM public key.
 */
public final class HybridKeyExchangeServer implements KeyExchangeServer {

    private static final int X25519_SHARE = 32;

    private final X25519KeyExchangeServer x25519 = new X25519KeyExchangeServer();
    private final MlKem768KeyExchangeServer mlkem = new MlKem768KeyExchangeServer();

    @Override
    public String name() {
        return "hybrid-x25519-mlkem768";
    }

    @Override
    public int clientShareBytes() {
        return x25519.clientShareBytes() + mlkem.clientShareBytes();
    }

    @Override
    public byte[] clientKeyShare() {
        return concat(x25519.clientKeyShare(), mlkem.clientKeyShare());
    }

    @Override
    public byte[] serverKeyExchange(byte[] clientShare) {
        byte[] xShare = Arrays.copyOfRange(clientShare, 0, X25519_SHARE);
        byte[] mShare = Arrays.copyOfRange(clientShare, X25519_SHARE, clientShare.length);
        return concat(x25519.serverKeyExchange(xShare), mlkem.serverKeyExchange(mShare));
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
