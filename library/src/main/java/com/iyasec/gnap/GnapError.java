// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

/** A failure this client can explain. code is config, discovery, protocol, validation, or signature. */
public class GnapError extends RuntimeException {
    public final String code;
    public final String gnapError;
    public Object context;
    public Continuation continuation;

    public GnapError(String code, String message) {
        this(code, message, null, null, null);
    }

    public GnapError(String code, String message, Throwable cause) {
        this(code, message, cause, null, null);
    }

    public GnapError(String code, String message, Throwable cause, String gnapError, Continuation continuation) {
        super(message, cause);
        this.code = code;
        this.gnapError = gnapError;
        this.continuation = continuation;
    }

    /** A continuation carried on a GNAP error, including too_fast. */
    public static final class Continuation {
        public final String uri;
        public final String accessToken;
        public final Double wait;

        public Continuation(String uri, String accessToken, Double wait) {
            this.uri = uri;
            this.accessToken = accessToken;
            this.wait = wait;
        }
    }
}
