// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap.ssf;

import com.iyasec.gnap.GnapError;
import com.iyasec.gnap.Json;
import com.iyasec.gnap.Keys;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Verify a Security Event Token or an ID token. The key is chosen by kid. none and HMAC are refused. */
public final class Jws {
    public static final List<String> ALGS = List.of(
            "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519");
    private static final Map<String, String> KTY = Map.ofEntries(
            Map.entry("RS256", "RSA"), Map.entry("RS384", "RSA"), Map.entry("RS512", "RSA"),
            Map.entry("PS256", "RSA"), Map.entry("PS384", "RSA"), Map.entry("PS512", "RSA"),
            Map.entry("ES256", "EC"), Map.entry("ES384", "EC"), Map.entry("ES512", "EC"),
            Map.entry("EdDSA", "OKP"), Map.entry("Ed25519", "OKP"));

    private Jws() {}

    public static Map<String, Object> verify(String token, List<Map<String, Object>> keys) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            throw new GnapError("signature", "the token is not a compact JWS");
        }
        Map<String, Object> header;
        Map<String, Object> payload;
        try {
            header = Json.map(Json.parse(new String(b64(parts[0], "header"), StandardCharsets.UTF_8)));
            payload = Json.map(Json.parse(new String(b64(parts[1], "payload"), StandardCharsets.UTF_8)));
        } catch (GnapError err) {
            throw err;
        } catch (Exception err) {
            throw new GnapError("signature", "the token's header or payload is not JSON", err);
        }
        if (header == null || payload == null) throw new GnapError("signature", "the token's header or payload is not a JSON object");
        String alg = header.get("alg") == null ? "" : String.valueOf(header.get("alg"));
        String kty = KTY.get(alg);
        if (kty == null) {
            throw new GnapError("signature", "the token is signed with " + (alg.isEmpty() ? "(no alg)" : alg) + ", which this client does not verify (" + String.join(", ", ALGS) + ")");
        }
        if (header.containsKey("crit")) throw new GnapError("signature", "the token's header has a crit member this client does not understand");
        String kid = header.get("kid") instanceof String text ? text : null;
        List<Map<String, Object>> candidates = new java.util.ArrayList<>();
        for (Map<String, Object> key : keys) {
            if (kid != null && !kid.equals(key.get("kid"))) continue;
            if (!kty.equals(key.get("kty"))) continue;
            if (key.get("use") != null && !"sig".equals(key.get("use"))) continue;
            if (key.get("alg") != null && !alg.equals(key.get("alg"))) continue;
            candidates.add(key);
        }
        if (candidates.isEmpty()) {
            String suffix = kid == null ? "" : " with kid " + kid;
            throw new GnapError("signature", "no " + kty + " signing key" + suffix + " was published");
        }
        byte[] data = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        byte[] signature = b64(parts[2], "signature");
        for (Map<String, Object> jwk : candidates) {
            if (Keys.verify(Keys.publicKeyFromJwk(jwk), alg, data, signature)) {
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("header", header);
                out.put("payload", payload);
                return out;
            }
        }
        throw new GnapError("signature", "the token's signature does not verify against the published keys");
    }

    private static byte[] b64(String value, String what) {
        if (value == null || !value.matches("[A-Za-z0-9_-]*")) throw new GnapError("signature", "the JWS " + what + " is not base64url");
        return Json.b64urlDecode(value);
    }
}
