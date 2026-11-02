// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/** Detached JWS key proof. The signature covers headerB64 + '.' + payload. */
public final class Jwsd {
    private Jwsd() {}

    public static String ath(String token) {
        return Json.b64url(Json.sha256(token.getBytes(StandardCharsets.US_ASCII)));
    }

    public static String detached(Keys.ClientKey key, String method, String url, String body, String token) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "gnap-binding-jwsd");
        header.put("alg", key.alg);
        header.put("kid", key.kid);
        header.put("htm", method.toUpperCase());
        header.put("uri", Urls.href(url));
        header.put("created", System.currentTimeMillis() / 1000L);
        if (token != null && !token.isEmpty()) header.put("ath", ath(token));
        String encoded = Json.b64url(Json.dumps(header).getBytes(StandardCharsets.UTF_8));
        String payload = body == null || body.isEmpty() ? "" : Json.b64url(Json.sha256(body.getBytes(StandardCharsets.UTF_8)));
        byte[] signature = key.sign((encoded + "." + payload).getBytes(StandardCharsets.US_ASCII));
        return encoded + "." + payload + "." + Json.b64url(signature);
    }
}
