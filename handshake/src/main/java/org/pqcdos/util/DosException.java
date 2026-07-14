package org.pqcdos.util;

/** Unchecked wrapper for checked crypto exceptions on the handshake-work path. */
public final class DosException extends RuntimeException {
    public DosException(String message, Throwable cause) {
        super(message, cause);
    }
}
