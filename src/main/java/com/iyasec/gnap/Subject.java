// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import com.iyasec.gnap.ssf.Jws;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/** Subject information from a grant response. An id_token is checked here. HMAC and none are refused. */
public final class Subject {
    private Subject() {}

    public static final class Person {
        public final String sub;
        public final Map<String, Object> claims;
        public final boolean assertionVerified;
        public final String iss;
        public final String uid;
        public final String email;
        public final String name;
        public final String preferredUsername;
        public final String sid;

        public Person(String sub, Map<String, Object> claims, boolean assertionVerified, String iss, String uid,
                      String email, String name, String preferredUsername, String sid) {
            this.sub = sub;
            this.claims = claims;
            this.assertionVerified = assertionVerified;
            this.iss = iss;
            this.uid = uid;
            this.email = email;
            this.name = name;
            this.preferredUsername = preferredUsername;
            this.sid = sid;
        }
    }

    public static final class Check {
        public final String idTokenIssuer;
        public final List<String> audiences;
        public final long clockToleranceSec;
        public final Supplier<List<Map<String, Object>>> keys;

        public Check(String idTokenIssuer, List<String> audiences, long clockToleranceSec, Supplier<List<Map<String, Object>>> keys) {
            this.idTokenIssuer = idTokenIssuer;
            this.audiences = audiences;
            this.clockToleranceSec = clockToleranceSec;
            this.keys = keys;
        }
    }

    public static Person personFrom(Object subject, Check check) {
        Map<String, Object> doc = Json.map(subject);
        if (doc == null) return null;
        List<Object> subIds = Json.list(doc.get("sub_ids"));
        if (subIds == null) subIds = List.of();
        Map<String, Object> issSub = null;
        Map<String, Object> opaque = null;
        Map<String, Object> account = null;
        for (Object item : subIds) {
            Map<String, Object> one = Json.map(item);
            if (one == null) continue;
            if (issSub == null && "iss_sub".equals(one.get("format")) && one.get("sub") instanceof String) issSub = one;
            if (opaque == null && "opaque".equals(one.get("format")) && one.get("id") instanceof String) opaque = one;
            if (account == null && "account".equals(one.get("format")) && one.get("uri") instanceof String) account = one;
        }
        List<Object> assertions = Json.list(doc.get("assertions"));
        if (assertions == null) assertions = List.of();
        Map<String, Object> idToken = null;
        for (Object item : assertions) {
            Map<String, Object> one = Json.map(item);
            if (one != null && "id_token".equals(one.get("format")) && one.get("value") instanceof String) {
                idToken = one;
                break;
            }
        }
        Map<String, Object> claims = new LinkedHashMap<>();
        String sub = issSub == null ? null : (String) issSub.get("sub");
        String iss = issSub != null && issSub.get("iss") instanceof String text ? text : null;
        boolean verified = false;
        if (idToken != null) {
            List<Map<String, Object>> keys = check.keys.get();
            Map<String, Object> verifiedJws = Jws.verify((String) idToken.get("value"), keys);
            @SuppressWarnings("unchecked")
            Map<String, Object> payload = (Map<String, Object>) verifiedJws.get("payload");
            if (!check.idTokenIssuer.equals(payload.get("iss"))) {
                throw new GnapError("validation", "the id_token was issued by " + payload.get("iss") + ", not " + check.idTokenIssuer);
            }
            if (!(payload.get("sub") instanceof String tokenSub) || tokenSub.isBlank()) {
                throw new GnapError("validation", "the id_token has no sub");
            }
            if (!(payload.get("exp") instanceof Number)) throw new GnapError("validation", "the id_token has no exp");
            long now = Instant.now().getEpochSecond();
            if (((Number) payload.get("exp")).longValue() + check.clockToleranceSec < now) {
                throw new GnapError("validation", "the id_token has expired");
            }
            if (payload.get("nbf") instanceof Number nbf && nbf.longValue() - check.clockToleranceSec > now) {
                throw new GnapError("validation", "the id_token is not valid yet");
            }
            if (payload.get("iat") instanceof Number iat && iat.longValue() - check.clockToleranceSec > now) {
                throw new GnapError("validation", "the id_token is issued in the future");
            }
            List<String> aud = strings(payload.get("aud"));
            List<String> known = new ArrayList<>();
            if (check.audiences != null) for (String one : check.audiences) if (one != null && !one.isBlank()) known.add(one);
            if (!known.isEmpty() && aud.stream().noneMatch(known::contains)) {
                String shown = aud.isEmpty() ? "(no audience)" : String.join(", ", aud);
                throw new GnapError("validation", "the id_token is for " + shown + ", not " + String.join(" or ", known));
            }
            if (sub != null && !sub.equals(payload.get("sub"))) {
                throw new GnapError("validation", "the id_token is about somebody other than the subject identifier");
            }
            sub = (String) payload.get("sub");
            iss = String.valueOf(payload.get("iss"));
            claims.putAll(payload);
            verified = true;
        }
        if (sub == null && opaque != null) sub = (String) opaque.get("id");
        if (sub == null && account != null) sub = (String) account.get("uri");
        if (sub == null) return null;
        String uid = account == null ? null : uidFromAccount((String) account.get("uri"));
        String email = claims.get("email") instanceof String text ? text : null;
        String name = claims.get("name") instanceof String text ? text : null;
        String preferred = claims.get("preferred_username") instanceof String text ? text : null;
        String sid = null;
        if (claims.get("sid") instanceof String sidText) sid = sidText;
        else if (claims.get("session_id") instanceof String sessionText) sid = sessionText;
        return new Person(sub, claims, verified, iss, uid, email, name, preferred, sid);
    }

    public static String uidFromAccount(String uri) {
        if (uri == null || !uri.startsWith("acct:") || uri.indexOf('@') < 0) return null;
        String user = uri.substring(5, uri.indexOf('@'));
        try {
            return decode(user);
        } catch (Exception err) {
            return user;
        }
    }

    static String decode(String value) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < value.length();) {
            char c = value.charAt(i);
            if (c == '%') {
                if (i + 2 >= value.length()) throw new IllegalArgumentException("bad percent-encoding");
                String hex = value.substring(i + 1, i + 3);
                if (!hex.chars().allMatch(ch -> "0123456789abcdefABCDEF".indexOf(ch) >= 0)) {
                    throw new IllegalArgumentException("bad percent-encoding");
                }
                out.write(Integer.parseInt(hex, 16));
                i += 3;
            } else {
                out.writeBytes(String.valueOf(c).getBytes(StandardCharsets.UTF_8));
                i += 1;
            }
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    private static List<String> strings(Object value) {
        List<String> out = new ArrayList<>();
        if (value instanceof List<?> list) for (Object item : list) out.add(String.valueOf(item));
        else if (value != null) out.add(String.valueOf(value));
        return out;
    }
}
