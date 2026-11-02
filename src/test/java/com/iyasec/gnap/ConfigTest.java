// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigTest {
    private static final String PRIVATE = X509Gen.createSelfSigned("app").privateKeyPem;

    private static Config.Resolved resolve(Map<String, Object> extra) {
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("grantEndpoint", "https://idp.example/gnap");
        body.put("application", "app");
        body.put("privateKey", PRIVATE);
        body.put("keyProof", "httpsig");
        if (extra != null) body.putAll(extra);
        return Config.resolve(body, Path.of("."));
    }

    @Test
    void defaultsAccessAndFillsTransmitter() {
        Config.Resolved resolved = resolve(Map.of("transmitterIssuer", "https://idp.example/issuer/"));
        assertEquals(List.of("ssf.read", "ssf.manage"), resolved.access);
        assertEquals("https://idp.example/issuer", resolved.ssf.get("transmitter"));
        assertFalse(resolved.signalsOff);
        Config.Resolved on = resolve(Map.of("signals", true, "transmitterIssuer", "https://idp.example/issuer"));
        assertFalse(on.signalsOff);
        assertNotNull(on.ssf);
    }

    @Test
    void dropsSsfRightsWhenSignalsIsFalse() {
        Config.Resolved resolved = resolve(Map.of(
                "signals", false,
                "access", List.of("openid", "ssf.read"),
                "transmitterIssuer", "https://idp.example",
                "ssf", Map.of("transmitter", "https://idp.example/tx", "pollIntervalMs", 3000)));
        assertEquals(List.of("openid"), resolved.access);
        assertEquals(null, resolved.ssf);
        assertTrue(resolved.signalsOff);
        Config.Resolved kept = resolve(Map.of(
                "signals", false,
                "access", List.of("openid", " ssf.read ", Map.of("type", "ssf.manage", "actions", List.of("read")), Map.of("type", "api"), Map.of("type", " ssf.read ")),
                "ssf", Map.of("transmitter", "not a url")));
        assertEquals(List.of("openid", Map.of("type", "api"), Map.of("type", " ssf.read ")), kept.access);
        assertEquals(null, kept.ssf);
    }

    @Test
    void refusesSignalsOffWhenThoseWereTheOnlyRights() {
        String message = "signals is false and access has no rights left after ssf.read and ssf.manage were removed";
        GnapError err = assertThrows(GnapError.class, () -> resolve(Map.of("signals", false, "access", List.of("ssf.read", "ssf.manage"))));
        assertEquals("config", err.code);
        assertTrue(err.getMessage().contains(message));
        assertTrue(err.getMessage().contains("must name a right this authorization server grants"));
        assertThrows(GnapError.class, () -> resolve(Map.of("signals", false, "transmitterIssuer", "https://idp.example")));
        assertThrows(GnapError.class, () -> resolve(Map.of("signals", false, "access", List.of(Map.of("type", "ssf.read"), Map.of("type", "ssf.manage")))));
    }

    @Test
    void refusesASignalsValueThatIsNotTrueOrFalse() {
        GnapError err = assertThrows(GnapError.class, () -> resolve(Map.of("signals", "no")));
        assertEquals("config", err.code);
        assertEquals("signals must be true or false", err.getMessage());
    }
}
