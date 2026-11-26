// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import com.iyasec.pep.Access;
import com.iyasec.pep.Decision;
import com.iyasec.pep.Mode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PepTest {
    private static final String SAME_KEY = "pep.assertionKey is the GNAP client instance key (privateKey); the PEP needs a key of its own";
    /** Permits {@code read}, and nothing else. */
    private static final String READ_ONLY = "<Policy xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" PolicyId=\"orders\" Version=\"1.0\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit\"><Target/><Rule RuleId=\"read\" Effect=\"Permit\"><Target><AnyOf><AllOf><Match MatchId=\"urn:oasis:names:tc:xacml:1.0:function:string-equal\"><AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">read</AttributeValue><AttributeDesignator Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:action\" AttributeId=\"urn:oasis:names:tc:xacml:1.0:action:action-id\" DataType=\"http://www.w3.org/2001/XMLSchema#string\" MustBePresent=\"false\"/></Match></AllOf></AnyOf></Target></Rule></Policy>";

    @Test
    void thePdpUrlIsTheGrantEndpointsRealm() {
        assertEquals("https://sts.example/realm/acme", EmbeddedPep.defaultPdpUrl("https://sts.example/realm/acme/gnap"));
        assertEquals("https://sts.example/realm/acme", EmbeddedPep.defaultPdpUrl("https://sts.example/realm/acme/as/gnap"));
        assertEquals("https://sts.example", EmbeddedPep.defaultPdpUrl("https://sts.example/gnap"));
        assertEquals("https://sts.example:8443/realm/acme", EmbeddedPep.defaultPdpUrl("https://sts.example:8443/realm/acme/gnap/"));
        assertEquals("http://127.0.0.1:9/realm/r", EmbeddedPep.defaultPdpUrl("http://127.0.0.1:9/realm/r/gnap"));
        assertEquals("", EmbeddedPep.defaultPdpUrl("not a url"));
        assertEquals("https://idp.example", Urls.origin("https://idp.example/realm/acme/gnap"));
        assertNotEquals(EmbeddedPep.defaultPdpUrl("https://idp.example/realm/acme/gnap"), Urls.origin("https://idp.example/realm/acme/gnap"));
    }

    @Test
    void subjectIdPrefersAccountThenUsernameThenPreferredThenSub() {
        assertEquals("ada", EmbeddedPep.subjectId(person("pairwise", "ada", "Ada", Map.of("username", "from-token"))));
        assertEquals("from-token", EmbeddedPep.subjectId(person("pairwise", null, "Ada", Map.of("username", "from-token"))));
        assertEquals("Ada", EmbeddedPep.subjectId(person("pairwise", "", "Ada", Map.of("username", ""))));
        assertEquals("Ada", EmbeddedPep.subjectId(person("pairwise", null, "Ada", Map.of())));
        assertEquals("pairwise", EmbeddedPep.subjectId(person("pairwise", null, "", Map.of())));
        assertEquals("", EmbeddedPep.subjectId(person("", null, null, Map.of())));
        Subject.Person withAcr = person("sub", "ada", null, Map.of("acr", "urn:example:loa2", "username", "from-token"));
        com.iyasec.pep.Subject subject = EmbeddedPep.subjectFor(withAcr);
        assertEquals("ada", EmbeddedPep.subjectId(withAcr));
        assertNotNull(subject);
    }

    @Test
    void theAssertionKeyMustNotBeTheClientKey() throws Exception {
        X509Gen.KeyPairPem client = X509Gen.createSelfSigned("app");
        X509Gen.KeyPairPem other = X509Gen.createSelfSigned("pep");
        Path dir = Files.createTempDirectory("gnap-pep");
        Path same = dir.resolve("same.pem");
        Path different = dir.resolve("pep.pem");
        Files.writeString(same, client.privateKeyPem);
        Files.writeString(different, other.privateKeyPem);
        GnapError err = assertThrows(GnapError.class, () -> Config.resolve(section(client.privateKeyPem, same.toString(), "central"), dir));
        assertEquals("config", err.code);
        assertEquals(SAME_KEY, err.getMessage());
        Config.Resolved resolved = Config.resolve(section(client.privateKeyPem, different.toString(), "central"), dir);
        assertNotNull(resolved.pep);
        assertEquals(Mode.CENTRAL, resolved.pep.config().mode);
        assertFalse(EmbeddedPep.wantsEvents(resolved.pep));
        Config.Resolved cached = Config.resolve(cachedSection(client.privateKeyPem, different.toString()), dir);
        assertTrue(EmbeddedPep.wantsEvents(cached.pep));
        Config.Resolved local = Config.resolve(section(client.privateKeyPem, different.toString(), null), dir);
        assertEquals(Mode.LOCAL, local.pep.config().mode);
        assertTrue(EmbeddedPep.wantsEvents(local.pep));
    }

    @Test
    void decideGrantDeniesAnEndedGrantWithoutAsking() {
        Config.Resolved resolved = Config.resolve(Map.of(
                "grantEndpoint", "https://idp.example/gnap",
                "application", "app",
                "privateKey", X509Gen.createSelfSigned("app").privateKeyPem,
                "keyProof", "httpsig"), Path.of("."));
        GnapClient client = GnapClient.create(resolved);
        Access access = Access.of("read", "order", "42");
        Subject.Person person = person("sub", "ada", null, Map.of("acr", "1"));
        GnapClient.Grant open = new GnapClient.Grant();
        open.subject = person;
        open.expiresAt = System.currentTimeMillis() + 120_000L;
        Decision none = client.decideGrant(open, access);
        assertEquals(403, none.httpStatus());
        assertEquals("no pep section is configured", none.why());
        GnapClient.Grant nameless = new GnapClient.Grant();
        nameless.expiresAt = open.expiresAt;
        assertEquals("the grant names no subject", client.decideGrant(nameless, access).why());
        assertEquals(403, client.decideGrant(nameless, access).httpStatus());
        GnapClient.Grant expired = new GnapClient.Grant();
        expired.subject = person;
        expired.expiresAt = 1L;
        assertEquals("the grant's access token has expired", client.decideGrant(expired, access).why());
        GnapClient.Grant revoked = new GnapClient.Grant();
        revoked.subject = person;
        revoked.expiresAt = open.expiresAt;
        revoked.continuation = new GnapClient.Continuation("https://idp.example/continue/1", "token", null);
        client.rememberRevoked(revoked.continuation.uri);
        assertEquals("the grant was revoked", client.decideGrant(revoked, access).why());
        for (int i = 0; i < 10_000; i++) client.rememberRevoked("https://idp.example/continue/" + i);
        client.rememberRevoked("https://idp.example/continue/last");
        GnapClient.Grant oldest = new GnapClient.Grant();
        oldest.subject = person;
        oldest.expiresAt = open.expiresAt;
        oldest.continuation = new GnapClient.Continuation("https://idp.example/continue/0", "token", null);
        assertEquals("no pep section is configured", client.decideGrant(oldest, access).why());
        GnapClient.Grant newest = new GnapClient.Grant();
        newest.subject = person;
        newest.expiresAt = open.expiresAt;
        newest.continuation = new GnapClient.Continuation("https://idp.example/continue/last", "token", null);
        assertEquals("the grant was revoked", client.decideGrant(newest, access).why());
    }

    @Test
    void localModeFailsClosedThenDecidesInProcess() throws Exception {
        AtomicBoolean policiesUp = new AtomicBoolean(false);
        AtomicInteger evaluations = new AtomicInteger();
        AtomicInteger policyPulls = new AtomicInteger();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("object", "subject");
        row.put("property", "acr");
        row.put("attributeId", "urn:example:acr");
        Map<String, Object> catalogue = new LinkedHashMap<>();
        catalogue.put("syncToken", "c1");
        catalogue.put("rows", List.of(row));
        catalogue.put("settings", Map.of("obligationsProfile", false));
        String catalogueJson = Json.dumps(catalogue);
        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("policyId", "orders");
        policy.put("kind", "Policy");
        policy.put("version", "1.0");
        policy.put("isRoot", true);
        policy.put("document", READ_ONLY);
        Map<String, Object> policies = new LinkedHashMap<>();
        policies.put("syncToken", "p1");
        policies.put("policies", List.of(policy));
        String policiesJson = Json.dumps(policies);
        HttpServer server = null;
        ExecutorService pool = null;
        GnapClient client = null;
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            pool = Executors.newCachedThreadPool(runnable -> {
                Thread thread = new Thread(runnable, "pep-stub");
                thread.setDaemon(true);
                return thread;
            });
            server.setExecutor(pool);
            server.createContext("/", exchange -> {
                try {
                    exchange.getRequestBody().readAllBytes();
                    String path = exchange.getRequestURI().getPath();
                    String method = exchange.getRequestMethod();
                    String authorization = exchange.getRequestHeaders().getFirst("Authorization");
                    if (authorization == null) authorization = "";
                    if ("POST".equals(method) && "/oauth2/token".equals(path)) {
                        respond(exchange, 200, "{\"access_token\":\"pep-token\",\"token_type\":\"DPoP\",\"expires_in\":300}");
                        return;
                    }
                    if (!authorization.startsWith("DPoP ")) {
                        respond(exchange, 401, "{\"error\":\"invalid_token\"}");
                        return;
                    }
                    if ("POST".equals(method) && "/xacml/pep/register".equals(path)) {
                        respond(exchange, 201, "{\"registered\":true}");
                        return;
                    }
                    if ("POST".equals(method) && "/xacml/pep/heartbeat".equals(path)) {
                        respond(exchange, 200, "{\"acknowledged\":true,\"current\":true}");
                        return;
                    }
                    if ("GET".equals(method) && "/xacml/pep/authzen-catalogue".equals(path)) {
                        respond(exchange, 200, catalogueJson);
                        return;
                    }
                    if ("/xacml/pep/policies".equals(path)) {
                        policyPulls.incrementAndGet();
                        if (!"GET".equals(method) || !policiesUp.get()) {
                            respond(exchange, 503, "{\"error\":\"server_error\",\"error_description\":\"not now\"}");
                            return;
                        }
                        respond(exchange, 200, policiesJson);
                        return;
                    }
                    if ("POST".equals(method) && "/admin-api/pep-audit".equals(path)) {
                        respond(exchange, 200, "{\"acknowledged\":0}");
                        return;
                    }
                    if ("POST".equals(method) && "/access/v1/evaluation".equals(path)) {
                        evaluations.incrementAndGet();
                        respond(exchange, 200, "{\"decision\":true}");
                        return;
                    }
                    respond(exchange, 404, "{\"error\":\"not_found\"}");
                } finally {
                    exchange.close();
                }
            });
            server.start();
            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            X509Gen.KeyPairPem clientKey = X509Gen.createSelfSigned("app");
            X509Gen.KeyPairPem pepKey = X509Gen.createSelfSigned("pep");
            Path dir = Files.createTempDirectory("gnap-pep");
            Path key = dir.resolve("pep-key.pem").toAbsolutePath().normalize();
            Files.writeString(key, pepKey.privateKeyPem);
            Map<String, Object> pep = new LinkedHashMap<>();
            pep.put("name", "pep-test");
            pep.put("mode", "local");
            pep.put("assertionKey", key.toString());
            pep.put("pdpUrl", base);
            pep.put("pollIntervalMs", 1000);
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("grantEndpoint", "https://idp.example/gnap");
            body.put("application", "app");
            body.put("privateKey", clientKey.privateKeyPem);
            body.put("keyProof", "httpsig");
            body.put("pep", pep);
            client = GnapClient.create(Config.resolve(body, dir));
            Subject.Person who = person("0b6e-pairwise", "alice", "alice.token", Map.of(
                    "acr", "urn:example:mfa", "amr", List.of("pwd", "otp"), "auth_time", 1_700_000_000));
            Access read = Access.of("read", "order", "42");
            Decision closed = client.decide(who, read);
            assertEquals(Decision.Kind.UNAVAILABLE, closed.kind());
            policiesUp.set(true);
            boolean held = false;
            long deadline = System.currentTimeMillis() + 8_000L;
            while (System.currentTimeMillis() < deadline) {
                if (client.pep().status().holdsPolicy) {
                    held = true;
                    break;
                }
                Thread.sleep(100);
            }
            assertTrue(held, "the poll did not pull a policy: " + client.pep().status().lastError);
            assertTrue(client.decide(who, read).isPermit());
            assertEquals(Decision.Kind.DENY, client.decide(who, Access.of("write", "order", "42")).kind());
            assertEquals(0, evaluations.get());
            assertTrue(policyPulls.get() >= 2, "policies pulls " + policyPulls.get());
        } finally {
            if (client != null && client.pep() != null) client.pep().stop();
            if (server != null) server.stop(0);
            if (pool != null) pool.shutdownNow();
        }
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] raw = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, raw.length);
        exchange.getResponseBody().write(raw);
    }

    private static Map<String, Object> section(String privateKey, String assertionKey, String mode) {
        Map<String, Object> pep = new LinkedHashMap<>();
        pep.put("name", "pep-test");
        if (mode != null) pep.put("mode", mode);
        pep.put("assertionKey", assertionKey);
        pep.put("pdpUrl", "https://sts.example");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("grantEndpoint", "https://sts.example/realm/acme/gnap");
        body.put("application", "app");
        body.put("privateKey", privateKey);
        body.put("keyProof", "httpsig");
        body.put("pep", pep);
        return body;
    }

    private static Map<String, Object> cachedSection(String privateKey, String assertionKey) {
        Map<String, Object> body = section(privateKey, assertionKey, "central");
        @SuppressWarnings("unchecked")
        Map<String, Object> pep = (Map<String, Object>) body.get("pep");
        pep.put("permitCacheMs", 1000);
        return body;
    }

    private static Subject.Person person(String sub, String uid, String preferred, Map<String, Object> claims) {
        return new Subject.Person(sub, new LinkedHashMap<>(claims), true, "https://idp.example", uid, null, null, preferred, null);
    }
}
