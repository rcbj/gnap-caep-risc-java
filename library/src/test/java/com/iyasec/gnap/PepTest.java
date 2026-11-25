// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import com.iyasec.pep.Access;
import com.iyasec.pep.Decision;
import com.iyasec.pep.Mode;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PepTest {
    private static final String SAME_KEY = "pep.assertionKey is the GNAP client instance key (privateKey); the PEP needs a key of its own";

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
