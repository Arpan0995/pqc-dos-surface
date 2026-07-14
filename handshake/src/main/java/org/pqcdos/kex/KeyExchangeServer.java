package org.pqcdos.kex;

/**
 * Models the <em>server-side</em> key-exchange work of a TLS 1.3 handshake: given the client's
 * key-share from the ClientHello, the server performs one (EC)DHE agreement or one KEM encapsulation
 * and derives the shared secret. This is the cheap half of the server's per-handshake work; the study
 * measures it to show that key exchange is <em>not</em> the dominant DoS factor.
 */
public interface KeyExchangeServer {

    /** Stable configuration identifier used in results. */
    String name();

    /** Size in bytes of the client key-share the attacker must send (part of "attacker effort"). */
    int clientShareBytes();

    /** A valid client key-share to drive the server (the precomputable attacker input). */
    byte[] clientKeyShare();

    /** The server's per-handshake key-exchange work; returns the derived shared secret. */
    byte[] serverKeyExchange(byte[] clientShare);
}
