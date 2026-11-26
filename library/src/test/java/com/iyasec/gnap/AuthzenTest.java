// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.Access;
import com.iyasec.pep.Decision;
import com.iyasec.pep.Mode;
import com.iyasec.pep.Obligation;
import com.iyasec.pep.Pep;
import com.iyasec.pep.Status;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthzenTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void theTableDecidesAsExpectedInLocalMode() throws Exception {
        JsonNode table = table();
        List<Realm> realms = new ArrayList<>();
        List<GnapClient> clients = new ArrayList<>();
        Map<String, Realm> realmOf = new LinkedHashMap<>();
        Map<String, GnapClient> clientOf = new LinkedHashMap<>();
        try {
            Iterator<Map.Entry<String, JsonNode>> groups = table.get("peps").fields();
            while (groups.hasNext()) {
                Map.Entry<String, JsonNode> group = groups.next();
                Realm realm = Realm.start(group.getValue(), table);
                realms.add(realm);
                GnapClient client = localClient(table, group.getValue(), realm);
                clients.add(client);
                waitReady(client, group.getKey());
                realmOf.put(group.getKey(), realm);
                clientOf.put(group.getKey(), client);
            }
            List<String> failures = new ArrayList<>();
            JsonNode cases = table.get("cases");
            Set<String> ids = new LinkedHashSet<>();
            for (JsonNode one : cases) {
                String id = one.get("id").asText();
                assertTrue(ids.add(id), "two cases are called " + id);
                String group = one.path("pep").isTextual() ? one.get("pep").asText() : "main";
                Realm realm = realmOf.get(group);
                GnapClient client = clientOf.get(group);
                assertNotNull(client, id + ": no pep " + group);
                int asked;
                synchronized (realm.seen) {
                    asked = realm.seen.size();
                }
                Decision decision = ask(client, realm, table, one);
                String mismatch = mismatch(id, one, decision, answer(decision));
                if (mismatch != null) failures.add(mismatch);
                if (one.path("grant").isTextual() && !"live".equals(one.get("grant").asText())) {
                    boolean evaluated = false;
                    synchronized (realm.seen) {
                        for (int i = asked; i < realm.seen.size(); i++) {
                            if (realm.seen.get(i).endsWith("/xacml/pip")) evaluated = true;
                        }
                    }
                    assertFalse(evaluated, id + ": an ended grant was decided anyway");
                }
            }
            for (GnapClient client : clients) {
                assertEquals("", client.pep().status().lastError, "the stub refused nothing");
            }
            assertTrue(failures.isEmpty(), failures.size() + " of " + cases.size() + " cases:\n" + String.join("\n", failures));
        } finally {
            for (GnapClient client : clients) {
                if (client.pep() != null) client.pep().stop();
            }
            for (Realm realm : realms) realm.close();
        }
    }

    @Test
    void theTableCoversEachKindOfCase() throws Exception {
        JsonNode table = table();
        JsonNode cases = table.get("cases");
        Set<String> decisions = new TreeSet<>();
        for (JsonNode one : cases) {
            if (one.path("expect").path("decision").isTextual()) decisions.add(one.get("expect").get("decision").asText());
        }
        assertEquals(Set.of("Deny", "Permit", "Unavailable"), decisions);
        Set<String> types = new TreeSet<>();
        for (JsonNode row : table.get("catalogue")) {
            if (row.path("dataType").isTextual()) types.add(row.get("dataType").asText());
        }
        for (String wanted : List.of("integer", "double", "boolean", "dateTime")) {
            assertTrue(types.contains(wanted), "a " + wanted + " row");
        }
        boolean bag = false;
        boolean dotted = false;
        for (JsonNode row : table.get("catalogue")) {
            if ("bag".equals(row.path("multiplicity").asText())) bag = true;
            if (row.path("property").asText("").contains(".")) dotted = true;
        }
        assertTrue(bag);
        assertTrue(dotted);
        for (String grant : List.of("live", "no-subject", "expired", "revoked")) {
            boolean found = false;
            for (JsonNode one : cases) {
                if (grant.equals(one.path("grant").asText())) found = true;
            }
            assertTrue(found, "a " + grant + " grant");
        }
        boolean obligations = false;
        for (JsonNode one : cases) {
            if (one.path("expect").path("obligations").isArray()) obligations = true;
        }
        assertTrue(obligations);
        boolean references = false;
        for (JsonNode group : table.get("peps")) {
            for (JsonNode policy : group.path("policies")) {
                if (policy.path("references").isArray()) references = true;
            }
        }
        assertTrue(references);
    }

    /**
     * A {@code localDefect} or {@code knownLocalDefect} object records the wrong
     * local answer in {@code local}. A string mark means any wrong answer is
     * still that defect. Matching the table's expect then fails, so the mark
     * comes off.
     */
    private static String mismatch(String id, JsonNode one, Decision decision, JsonNode got) {
        JsonNode expect = one.get("expect");
        String name = null;
        JsonNode defect = null;
        if (one.has("localDefect") && !one.get("localDefect").isNull()) {
            name = "localDefect";
            defect = one.get("localDefect");
        } else if (one.has("knownLocalDefect") && !one.get("knownLocalDefect").isNull()) {
            name = "knownLocalDefect";
            defect = one.get("knownLocalDefect");
        }
        if (defect != null && defect.isTextual()) {
            if (got.equals(expect)) return id + ": local now answers as expected; remove " + name;
            return null;
        }
        JsonNode want = expect;
        if (defect != null && defect.isObject()) want = defect.get("local");
        if (want == null || want.isMissingNode()) want = JSON.nullNode();
        if (got.equals(want)) return null;
        String why = decision.kind() == Decision.Kind.PERMIT ? "" : decision.why();
        return id + ": local " + got + " (" + why + "), expected " + want;
    }

    private static JsonNode answer(Decision decision) {
        ObjectNode out = JSON.createObjectNode();
        String name = switch (decision.kind()) {
            case PERMIT -> "Permit";
            case DENY -> "Deny";
            case UNAVAILABLE -> "Unavailable";
        };
        out.put("decision", name);
        if (decision.kind() != Decision.Kind.PERMIT) return out;
        if (!decision.obligations().isEmpty()) {
            ArrayNode list = out.putArray("obligations");
            for (Obligation obligation : decision.obligations()) {
                ObjectNode one = list.addObject();
                one.put("type", obligation.kind);
                one.set("properties", obligation.properties.deepCopy());
            }
        }
        if (!decision.advice().isEmpty()) {
            ArrayNode list = out.putArray("advice");
            for (Obligation advice : decision.advice()) list.add(advice.id);
        }
        return out;
    }

    private static Decision ask(GnapClient client, Realm realm, JsonNode table, JsonNode one) {
        Subject.Person person = person(table, one);
        Access access = access(one);
        if (!one.path("grant").isTextual()) return client.decide(person, access);
        String kind = one.get("grant").asText();
        GnapClient.Grant grant = new GnapClient.Grant();
        grant.accessToken = "unused";
        grant.expiresAt = System.currentTimeMillis() + 600_000L;
        grant.subject = person;
        grant.grantId = one.get("id").asText();
        switch (kind) {
            case "live" -> { }
            case "no-subject" -> grant.subject = null;
            case "expired" -> grant.expiresAt = System.currentTimeMillis() - 1_000L;
            case "revoked" -> {
                grant.continuation = new GnapClient.Continuation(realm.realm() + "/gnap/continue/" + one.get("id").asText(), "ct", null);
                client.revoke(grant);
            }
            default -> throw new IllegalStateException("the table names an unknown grant kind " + kind);
        }
        return client.decideGrant(grant, access);
    }

    private static Subject.Person person(JsonNode table, JsonNode one) {
        JsonNode who = table.get("people").get(one.get("person").asText());
        Map<String, Object> claims = new LinkedHashMap<>();
        if (who.path("claims").isObject()) {
            who.get("claims").fields().forEachRemaining(entry -> claims.put(entry.getKey(), JSON.convertValue(entry.getValue(), Object.class)));
        }
        if (one.path("claims").isObject()) {
            one.get("claims").fields().forEachRemaining(entry -> claims.put(entry.getKey(), JSON.convertValue(entry.getValue(), Object.class)));
        }
        if (one.path("dropClaims").isArray()) {
            for (JsonNode name : one.get("dropClaims")) claims.remove(name.asText());
        }
        String uid = who.path("uid").isTextual() ? who.get("uid").asText() : null;
        String preferred = who.path("preferred_username").isTextual() ? who.get("preferred_username").asText() : null;
        return new Subject.Person(who.get("sub").asText(), claims, true, "https://sts.example", uid, null, null, preferred, null);
    }

    private static Access access(JsonNode one) {
        JsonNode raw = one.get("access");
        JsonNode resource = raw.get("resource");
        Access access = new Access(raw.path("action").asText(""), resource.path("type").asText(""), resource.path("id").asText(""));
        access.resourceProperties = properties(resource.get("properties"));
        access.actionProperties = properties(raw.get("actionProperties"));
        access.context = properties(raw.get("context"));
        return access;
    }

    private static Map<String, JsonNode> properties(JsonNode node) {
        Map<String, JsonNode> out = new LinkedHashMap<>();
        if (node != null && node.isObject()) {
            node.fields().forEachRemaining(entry -> out.put(entry.getKey(), entry.getValue().deepCopy()));
        }
        return out;
    }

    private static void waitReady(GnapClient client, String what) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 30_000L;
        while (true) {
            Pep pep = client.pep();
            Status status = pep.status();
            boolean policy = pep.config().mode == Mode.CENTRAL || status.holdsPolicy;
            String error = status.lastError == null ? "" : status.lastError;
            if (status.registered && policy && !error.contains("pull")) return;
            assertTrue(System.currentTimeMillis() < deadline, what + ": the PEP did not get ready: registered " + status.registered
                    + ", holdsPolicy " + status.holdsPolicy + ", lastError " + error);
            Thread.sleep(200);
        }
    }

    private static GnapClient localClient(JsonNode table, JsonNode group, Realm realm) throws Exception {
        X509Gen.KeyPairPem clientKey = X509Gen.createSelfSigned("app");
        X509Gen.KeyPairPem pepKey = X509Gen.createSelfSigned("pep");
        Path dir = Files.createTempDirectory("gnap-authzen");
        Path file = dir.resolve("pep-key.pem").toAbsolutePath().normalize();
        Files.writeString(file, pepKey.privateKeyPem);
        List<String> obligations = new ArrayList<>();
        for (JsonNode item : table.get("supportedObligations")) {
            if (item.isTextual()) obligations.add(item.asText());
        }
        Map<String, Object> section = new LinkedHashMap<>();
        section.put("name", "pep-authzen-offline");
        section.put("mode", "local");
        section.put("application", group.path("application").asText());
        section.put("supportedObligations", obligations);
        section.put("signals", false);
        section.put("pollIntervalMs", 2000);
        section.put("heartbeatIntervalMs", 60000);
        section.put("assertionKey", file.toString());
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("grantEndpoint", realm.realm() + "/gnap");
        doc.put("application", "gnap-caep-risc-demo");
        doc.put("privateKey", clientKey.privateKeyPem);
        doc.put("keyProof", "httpsig");
        doc.put("allowInsecure", true);
        doc.put("pep", section);
        return GnapClient.create(GnapClient.resolve(doc, dir));
    }

    private static JsonNode table() throws IOException {
        try (InputStream in = AuthzenTest.class.getResourceAsStream("/authzen_cases.json")) {
            if (in == null) throw new IllegalStateException("authzen_cases.json is missing");
            return JSON.readTree(in.readAllBytes());
        }
    }

    private static String textLines(JsonNode lines) {
        if (lines == null || !lines.isArray()) return "";
        StringBuilder out = new StringBuilder();
        boolean first = true;
        for (JsonNode line : lines) {
            if (!line.isTextual()) continue;
            if (!first) out.append('\n');
            first = false;
            out.append(line.asText());
        }
        return out.toString();
    }

    private static String[] described(String document) {
        int start = document.indexOf("<Policy");
        if (start < 0) throw new IllegalStateException("a Policy or PolicySet element");
        String kind = document.startsWith("<PolicySet", start) ? "PolicySet" : "Policy";
        String marker = kind + "Id=\"";
        int at = document.indexOf(marker, start);
        if (at < 0) throw new IllegalStateException("a policy document has no " + marker);
        at += marker.length();
        int end = document.indexOf('"', at);
        if (end < 0) throw new IllegalStateException("a policy document has no " + marker);
        return new String[] {document.substring(at, end), kind};
    }

    private static String pipAnswer(JsonNode directory, String query) {
        String subject = "";
        int marker = query.indexOf("subject:subject-id\"");
        if (marker >= 0) {
            int value = query.indexOf("<AttributeValue", marker);
            if (value >= 0) {
                int open = query.indexOf('>', value);
                int close = open < 0 ? -1 : query.indexOf('<', open + 1);
                if (open >= 0 && close > open) subject = query.substring(open + 1, close);
            }
        }
        StringBuilder attributes = new StringBuilder();
        JsonNode row = directory == null ? null : directory.get(subject);
        if (row != null && row.isObject()) {
            row.fields().forEachRemaining(entry -> {
                String value = entry.getValue().isTextual() ? entry.getValue().asText() : "";
                attributes.append("<Attribute AttributeId=\"").append(xml(entry.getKey()))
                        .append("\" IncludeInResult=\"false\"><AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">")
                        .append(xml(value)).append("</AttributeValue></Attribute>");
            });
        }
        return "<PIPResponse xmlns=\"urn:sts:xacml:pip:1.0\"><Attributes xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" Category=\"urn:oasis:names:tc:xacml:1.0:subject-category:access-subject\">"
                + attributes + "</Attributes></PIPResponse>";
    }

    private static String xml(String text) {
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static final class Realm {
        final HttpServer server;
        final ExecutorService pool;
        final String name;
        final JsonNode directory;
        final byte[] policies;
        final byte[] catalogue;
        final List<String> seen = new ArrayList<>();
        String base;

        private Realm(HttpServer server, ExecutorService pool, String name, JsonNode directory, byte[] policies, byte[] catalogue) {
            this.server = server;
            this.pool = pool;
            this.name = name;
            this.directory = directory;
            this.policies = policies;
            this.catalogue = catalogue;
        }

        String realm() {
            return base + "/realm/" + name;
        }

        static Realm start(JsonNode group, JsonNode table) throws Exception {
            String name = "az";
            ObjectNode policies = JSON.createObjectNode();
            policies.put("syncToken", "p1");
            policies.put("root", "");
            ArrayNode entries = policies.putArray("policies");
            for (JsonNode policy : group.get("policies")) {
                String document = textLines(policy.get("xacml"));
                assertFalse(document.isEmpty(), "a policy of " + group.path("application").asText() + " has no xacml in the table");
                String[] described = described(document);
                ObjectNode entry = entries.addObject();
                entry.put("name", policy.path("name").isTextual() ? policy.get("name").asText() : "own");
                entry.put("policyId", described[0]);
                entry.put("kind", described[1]);
                entry.put("version", "1.0");
                entry.put("isRoot", policy.path("root").isBoolean() && policy.get("root").booleanValue());
                entry.put("description", "");
                entry.put("document", document);
            }
            policies.putArray("withheld");
            policies.put("note", "");
            ObjectNode catalogue = JSON.createObjectNode();
            catalogue.put("syncToken", "c1");
            catalogue.put("realm", name);
            catalogue.set("rows", table.get("catalogue").deepCopy());
            ObjectNode settings = catalogue.putObject("settings");
            JsonNode profile = table.get("obligationsProfile");
            if (profile == null || profile.isNull()) settings.putNull("obligationsProfile");
            else settings.set("obligationsProfile", profile.deepCopy());
            ArrayNode fga = catalogue.putArray("fgaApplications");
            if (group.path("fga").isBoolean() && group.get("fga").booleanValue()) fga.add(group.path("application").asText());
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            ExecutorService pool = Executors.newCachedThreadPool(runnable -> {
                Thread thread = new Thread(runnable, "authzen-stub");
                thread.setDaemon(true);
                return thread;
            });
            Realm realm = new Realm(server, pool, name, table.get("directory"), JSON.writeValueAsBytes(policies), JSON.writeValueAsBytes(catalogue));
            server.setExecutor(pool);
            server.createContext("/", realm::handle);
            server.start();
            realm.base = "http://127.0.0.1:" + server.getAddress().getPort();
            return realm;
        }

        void close() {
            server.stop(0);
            pool.shutdownNow();
        }

        private void handle(HttpExchange exchange) throws IOException {
            try {
                String request = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String path = exchange.getRequestURI().getPath();
                String prefix = "/realm/" + name;
                if (path.startsWith(prefix)) path = path.substring(prefix.length());
                String method = exchange.getRequestMethod();
                synchronized (seen) {
                    seen.add(method + " " + path);
                }
                if (path.startsWith("/gnap/continue/") && "DELETE".equals(method)) {
                    respond(exchange, 204, new byte[0], "application/json");
                    return;
                }
                if ("/oauth2/token".equals(path)) {
                    respond(exchange, 200, "{\"access_token\":\"pep-token\",\"token_type\":\"DPoP\",\"expires_in\":300}".getBytes(StandardCharsets.UTF_8), "application/json");
                    return;
                }
                if ("/xacml/pep/register".equals(path)) {
                    String identity = "{\"registered\":true,\"identity\":\"uid=pep-" + name + ",ou=users,dc=example,dc=com\"}";
                    respond(exchange, 201, identity.getBytes(StandardCharsets.UTF_8), "application/json");
                    return;
                }
                if ("/xacml/pep/heartbeat".equals(path)) {
                    respond(exchange, 200, "{\"acknowledged\":true,\"current\":true}".getBytes(StandardCharsets.UTF_8), "application/json");
                    return;
                }
                if ("/xacml/pep/authzen-catalogue".equals(path)) {
                    respond(exchange, 200, catalogue, "application/json");
                    return;
                }
                if ("/xacml/pep/policies".equals(path)) {
                    respond(exchange, 200, policies, "application/json");
                    return;
                }
                if ("/admin-api/pep-audit".equals(path)) {
                    respond(exchange, 200, "{\"acknowledged\":0}".getBytes(StandardCharsets.UTF_8), "application/json");
                    return;
                }
                if ("/xacml/pip".equals(path)) {
                    respond(exchange, 200, pipAnswer(directory, request).getBytes(StandardCharsets.UTF_8), "application/xml");
                    return;
                }
                if ("/access/v1/evaluation".equals(path)) {
                    respond(exchange, 500, "{\"error\":\"this stub decides nothing\"}".getBytes(StandardCharsets.UTF_8), "application/json");
                    return;
                }
                respond(exchange, 404, "{\"error\":\"not_found\"}".getBytes(StandardCharsets.UTF_8), "application/json");
            } finally {
                exchange.close();
            }
        }

        private static void respond(HttpExchange exchange, int status, byte[] body, String type) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", type);
            if (status == 204) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }
            byte[] raw = body == null ? new byte[0] : body;
            exchange.sendResponseHeaders(status, raw.length);
            if (raw.length > 0) exchange.getResponseBody().write(raw);
        }
    }
}
