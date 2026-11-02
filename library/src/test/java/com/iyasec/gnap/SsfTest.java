// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import com.iyasec.gnap.ssf.Events;
import com.iyasec.gnap.ssf.Jws;
import com.iyasec.gnap.ssf.SessionIndex;
import com.iyasec.gnap.ssf.SignalsReceiver;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SsfTest {
    static KeyPair pair;
    static KeyPair other;
    static Map<String, Object> jwk;
    static HttpServer server;
    static String base;
    static final Map<String, String> queue = new LinkedHashMap<>();
    static final List<String> acked = new ArrayList<>();
    static final Map<String, Object> errs = new LinkedHashMap<>();
    static final List<Map<String, Object>> streams = new ArrayList<>();
    static int created;
    static String authorization = "";
    static final List<Map<String, Object>> signed = new ArrayList<>();

    @BeforeAll
    static void up() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        pair = generator.generateKeyPair();
        other = generator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();
        jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("n", Json.b64url(unsigned(publicKey.getModulus())));
        jwk.put("e", Json.b64url(unsigned(publicKey.getPublicExponent())));
        jwk.put("kid", "k1");
        jwk.put("alg", "RS256");
        jwk.put("use", "sig");
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String text = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String path = exchange.getRequestURI().getPath();
            authorization = exchange.getRequestHeaders().getFirst("Authorization");
            if (authorization == null) authorization = "";
            if (!"GNAP app-token".equals(authorization) && !"/.well-known/ssf-configuration".equals(path) && !path.startsWith("/jwks")) {
                send(exchange, 401, Json.dumps(Map.of("error", "invalid_token")));
                return;
            }
            if ("/.well-known/ssf-configuration".equals(path)) {
                send(exchange, 200, Json.dumps(Map.of(
                        "issuer", base, "jwks_uri", base + "/jwks",
                        "configuration_endpoint", base + "/ssf/stream",
                        "verification_endpoint", base + "/ssf/verify",
                        "delivery_methods_supported", List.of("urn:ietf:rfc:8936"))));
                return;
            }
            if ("/jwks".equals(path)) {
                send(exchange, 200, Json.dumps(Map.of("keys", List.of(jwk))));
                return;
            }
            if ("/ssf/stream".equals(path) && "GET".equals(exchange.getRequestMethod())) {
                send(exchange, 200, Json.dumps(streams));
                return;
            }
            if ("/ssf/stream".equals(path) && "POST".equals(exchange.getRequestMethod())) {
                Map<String, Object> body = Json.map(Json.parse(text));
                created += 1;
                Map<String, Object> delivery = Json.map(body.get("delivery"));
                Map<String, Object> stream = new LinkedHashMap<>();
                stream.put("stream_id", "s" + created);
                stream.put("iss", base);
                stream.put("aud", "my-app");
                stream.put("delivery", Map.of("method", delivery.get("method"), "endpoint_url", base + "/ssf/poll/s" + created));
                stream.put("events_requested", body.get("events_requested"));
                stream.put("events_delivered", body.get("events_requested"));
                streams.add(stream);
                send(exchange, 201, Json.dumps(stream));
                return;
            }
            if ("/ssf/verify".equals(path)) {
                exchange.sendResponseHeaders(204, -1);
                exchange.close();
                return;
            }
            if (path.startsWith("/ssf/poll/")) {
                Map<String, Object> body = Json.map(Json.parse(text.isBlank() ? "{}" : text));
                if (body.get("ack") instanceof List<?> list) for (Object jti : list) {
                    acked.add(String.valueOf(jti));
                    queue.remove(String.valueOf(jti));
                }
                if (body.get("setErrs") instanceof Map<?, ?> setErrs) {
                    for (Map.Entry<?, ?> entry : setErrs.entrySet()) {
                        errs.put(String.valueOf(entry.getKey()), entry.getValue());
                        queue.remove(String.valueOf(entry.getKey()));
                    }
                }
                send(exchange, 200, Json.dumps(Map.of("sets", new LinkedHashMap<>(queue), "moreAvailable", false)));
                return;
            }
            send(exchange, 404, Json.dumps(Map.of("error", "not_found")));
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void down() {
        if (server != null) server.stop(0);
    }

    @Test
    void verifiesASetAndRefusesAnotherKey() throws Exception {
        assertEquals(Map.of("a", 1), Jws.verify(jws(Map.of("a", 1), pair, null), List.of(jwk)).get("payload"));
        assertTrue(assertThrows(GnapError.class, () -> Jws.verify(jws(Map.of("a", 1), other, null), List.of(jwk))).getMessage().contains("does not verify"));
        Map<String, Object> nope = Map.of("alg", "RS256", "kid", "nope");
        assertTrue(assertThrows(GnapError.class, () -> Jws.verify(jws(Map.of("a", 1), pair, nope), List.of(jwk))).getMessage().contains("kid nope"));
        assertTrue(assertThrows(GnapError.class, () -> Jws.verify(jws(Map.of("a", 1), pair, Map.of("alg", "none")), List.of(jwk))).getMessage().contains("does not verify"));
    }

    @Test
    void readsSubjectForms() {
        assertEquals("https://schemas.openid.net/secevent/caep/event-type/session-revoked", Events.SESSION_REVOKED);
        assertEquals("https://schemas.openid.net/secevent/risc/event-type/credential-compromise", Events.CREDENTIAL_COMPROMISE);
        assertEquals(Map.of("person", "urn:uuid:a", "idp_session", "S1"), Events.subjectOf(Map.of(
                "format", "complex",
                "user", Map.of("format", "iss_sub", "iss", "https://i", "sub", "urn:uuid:a"),
                "session", Map.of("format", "opaque", "id", "S1")), "https://i"));
        assertEquals(Map.of(), Events.subjectOf(Map.of("format", "iss_sub", "iss", "https://other", "sub", "urn:uuid:a"), "https://i"));
        assertEquals(Map.of("email", "A@x.com"), Events.subjectOf(Map.of("format", "email", "email", "A@x.com"), "https://i"));
    }

    @Test
    void pollsWithTheGnapTokenAndAcknowledges() throws Exception {
        List<List<String>> ended = new ArrayList<>();
        List<SignalsReceiver.Event> seen = new ArrayList<>();
        SignalsReceiver receiver = new SignalsReceiver(base, (ids, event) -> ended.add(ids), null, request -> {
            signed.add(request);
            return Map.of("authorization", "GNAP app-token");
        }, 60_000L);
        receiver.on("*", seen::add);
        receiver.start();
        receiver.stop();
        assertEquals(1, created);
        assertEquals("GNAP app-token", authorization);
        assertEquals("s1", receiver.stream().get("stream_id"));
        Map<String, Object> create = signed.stream().filter(item -> "POST".equals(item.get("method")) && String.valueOf(item.get("url")).endsWith("/ssf/stream")).findFirst().orElseThrow();
        assertTrue(String.valueOf(create.get("body")).contains("\"delivery\""));
        receiver.track(new SessionIndex.Tracked("L-a1", "urn:uuid:alice", "alice@example.com", "IDP-A1", null));
        receiver.track(new SessionIndex.Tracked("L-a2", "urn:uuid:alice", "alice@example.com", "IDP-A2", null));
        receiver.track(new SessionIndex.Tracked("L-b1", "urn:uuid:bob", "bob@example.com", "IDP-B1", null));
        String revoked = deliver(Events.SESSION_REVOKED, Map.of(
                "format", "complex",
                "user", Map.of("format", "iss_sub", "iss", base, "sub", "urn:uuid:alice"),
                "session", Map.of("format", "opaque", "id", "IDP-A1")), null, pair);
        deliver(Events.CREDENTIAL_CHANGE, Map.of("format", "iss_sub", "iss", base, "sub", "urn:uuid:bob"), Map.of("credential_type", "password"), pair);
        receiver.pollOnce();
        assertEquals(List.of(List.of("L-a1")), ended);
        assertEquals(2, seen.size());
        assertTrue(seen.get(0).ended);
        assertEquals(Events.CREDENTIAL_CHANGE, seen.get(1).type);
        assertFalse(seen.get(1).ended);
        Map<String, Object> poll = signed.stream().filter(item -> String.valueOf(item.get("url")).contains("/ssf/poll/")).findFirst().orElseThrow();
        assertEquals("POST", poll.get("method"));
        assertTrue(String.valueOf(poll.get("body")).contains("maxEvents"));
        receiver.pollOnce();
        assertEquals(revoked, acked.get(0));
        String bad = deliver(Events.ACCOUNT_DISABLED, Map.of("format", "email", "email", "alice@example.com"), null, other);
        receiver.pollOnce();
        receiver.pollOnce();
        assertEquals("invalid_key", Json.map(errs.get(bad)).get("err"));
        receiver.verify("abc");
        receiver.stop();
    }

    private static void send(com.sun.net.httpserver.HttpExchange exchange, int status, String body) {
        try {
            byte[] raw = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, raw.length);
            exchange.getResponseBody().write(raw);
            exchange.close();
        } catch (java.io.IOException err) {
            throw new java.io.UncheckedIOException(err);
        }
    }

    private static String deliver(String type, Map<String, Object> subId, Map<String, Object> extra, KeyPair key) throws Exception {
        String jti = UUID.randomUUID().toString();
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("event_timestamp", 1);
        if (extra != null) event.putAll(extra);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", base);
        payload.put("aud", "my-app");
        payload.put("jti", jti);
        payload.put("iat", 1);
        payload.put("sub_id", subId);
        payload.put("events", Map.of(type, event));
        queue.put(jti, jws(payload, key, null));
        return jti;
    }

    private static String jws(Map<String, Object> payload, KeyPair key, Map<String, Object> header) throws Exception {
        Map<String, Object> head = header == null ? new LinkedHashMap<>(Map.of("alg", "RS256", "kid", "k1", "typ", "secevent+jwt")) : new LinkedHashMap<>(header);
        String h = Json.b64url(Json.dumps(head).getBytes(StandardCharsets.UTF_8));
        String p = Json.b64url(Json.dumps(payload).getBytes(StandardCharsets.UTF_8));
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key.getPrivate());
        signature.update((h + "." + p).getBytes(StandardCharsets.US_ASCII));
        return h + "." + p + "." + Json.b64url(signature.sign());
    }

    private static byte[] unsigned(java.math.BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0) {
            byte[] trimmed = new byte[raw.length - 1];
            System.arraycopy(raw, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return raw;
    }
}
