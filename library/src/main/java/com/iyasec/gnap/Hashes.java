// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import java.nio.charset.StandardCharsets;

/** Interaction finish hash, RFC 9635 section 4.2.3. The continuation token never leaves this process. */
public final class Hashes {
    private Hashes() {}

    public static String interactionHash(String clientNonce, String serverNonce, String interactRef, String grantEndpoint) {
        String raw = clientNonce + "\n" + serverNonce + "\n" + interactRef + "\n" + grantEndpoint;
        return Json.b64url(Json.sha256(raw.getBytes(StandardCharsets.UTF_8)));
    }

    public static boolean hashEqual(String left, String right) {
        return Json.timingEqual(left, right);
    }
}
