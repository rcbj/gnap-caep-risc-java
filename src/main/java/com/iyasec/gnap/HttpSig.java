// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** HTTP message signatures (RFC 9421) with an RFC 9530 Content-Digest. There is no alg parameter. */
public final class HttpSig {
    private HttpSig() {}

    public static String contentDigest(String body) {
        byte[] raw = body.getBytes(StandardCharsets.UTF_8);
        return "sha-256=:" + Json.b64(Json.sha256(raw)) + ":";
    }

    public static Map<String, String> sign(Keys.ClientKey key, String method, String url, Map<String, String> headers, String body) {
        String href = Urls.href(url);
        Map<String, String> lower = new LinkedHashMap<>();
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) lower.put(entry.getKey().toLowerCase(), entry.getValue());
        }
        List<String> components = new ArrayList<>();
        components.add("@method");
        components.add("@target-uri");
        Map<String, String> added = new LinkedHashMap<>();
        if (body != null && !body.isEmpty()) {
            added.put("content-digest", contentDigest(body));
            lower.put("content-digest", added.get("content-digest"));
            components.add("content-digest");
        }
        if (lower.containsKey("authorization")) components.add("authorization");
        long created = System.currentTimeMillis() / 1000L;
        byte[] nonceRaw = new byte[16];
        new SecureRandom().nextBytes(nonceRaw);
        String nonce = Json.b64url(nonceRaw);
        String covered = String.join(" ", components.stream().map(name -> "\"" + name + "\"").toList());
        String params = "(" + covered + ");created=" + created + ";nonce=" + sf(nonce) + ";keyid=" + sf(key.kid) + ";tag=\"gnap\"";
        String base = base(components, method, href, lower, params);
        byte[] signature = key.sign(base.getBytes(StandardCharsets.UTF_8));
        added.put("signature-input", "sig1=" + params);
        added.put("signature", "sig1=:" + Json.b64(signature) + ":");
        return added;
    }

    private static String base(List<String> components, String method, String url, Map<String, String> headers, String serialised) {
        List<String> lines = new ArrayList<>();
        for (String component : components) {
            String value;
            if ("@method".equals(component)) value = method.toUpperCase();
            else if ("@target-uri".equals(component)) value = url;
            else {
                if (!headers.containsKey(component)) throw new IllegalArgumentException("Cannot sign \"" + component + "\": the request has no such header");
                value = headers.get(component).trim();
            }
            if (value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
                throw new IllegalArgumentException("Cannot sign \"" + component + "\": the value contains a line break");
            }
            lines.add("\"" + component + "\": " + value);
        }
        lines.add("\"@signature-params\": " + serialised);
        return String.join("\n", lines);
    }

    private static String sf(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
