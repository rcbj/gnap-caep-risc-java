// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class SubjectTest {
    private static final Subject.Check CHECK = new Subject.Check("https://as.example", List.of(), 0, List::of);

    @Test
    void takesUidFromAnAccountIdentifier() {
        Subject.Person person = Subject.personFrom(Map.of("sub_ids", List.of(
                Map.of("format", "iss_sub", "iss", "https://as.example", "sub", "urn:uuid:abc"),
                Map.of("format", "account", "uri", "acct:gnap-demo-user@localhost:8081")
        )), CHECK);
        assertEquals("urn:uuid:abc", person.sub);
        assertEquals("https://as.example", person.iss);
        assertEquals("gnap-demo-user", person.uid);
    }

    @Test
    void percentDecodesAndKeepsInvalidEncoding() {
        Subject.Person decoded = Subject.personFrom(Map.of("sub_ids", List.of(
                Map.of("format", "account", "uri", "acct:ada%20lovelace@idp.example"))), CHECK);
        assertEquals("acct:ada%20lovelace@idp.example", decoded.sub);
        assertEquals("ada lovelace", decoded.uid);
        Subject.Person kept = Subject.personFrom(Map.of("sub_ids", List.of(
                Map.of("format", "account", "uri", "acct:%E0%A4%A@idp.example"))), CHECK);
        assertEquals("%E0%A4%A", kept.uid);
    }

    @Test
    void leavesUidUnsetWithoutAnAccountIdentifier() {
        Subject.Person person = Subject.personFrom(Map.of("sub_ids", List.of(
                Map.of("format", "iss_sub", "iss", "https://as.example", "sub", "urn:uuid:abc"))), CHECK);
        assertNull(person.uid);
        assertEquals("urn:uuid:abc", person.sub);
    }
}
