// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientTest {
    static HttpsServer server;
    static String base;
    static X509Gen.KeyPairPem clientPem;
    static String serverCert;
    static final List<Map<String, String>> seen = new ArrayList<>();
    static ECPublicKey publicKey;
    static String kid = "";
    static boolean foreign;
    static boolean bearer;
    static boolean tooFast;
    static boolean tooFastSent;
    static String aud = "instance-1";
    static String sub = "user-1";
    static String issSub;
    static KeyPair idKeys;
    static Map<String, Object> idJwk;

    @BeforeAll
    static void up() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        idKeys = rsa.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey) idKeys.getPublic();
        idJwk = new LinkedHashMap<>();
        idJwk.put("kty", "RSA");
        idJwk.put("n", Json.b64url(unsigned(pub.getModulus())));
        idJwk.put("e", Json.b64url(unsigned(pub.getPublicExponent())));
        idJwk.put("kid", "id1");
        idJwk.put("alg", "RS256");
        idJwk.put("use", "sig");
        X509Gen.KeyPairPem serverPem = X509Gen.createSelfSigned("localhost", 1095, List.of("localhost"), List.of("127.0.0.1"));
        clientPem = X509Gen.createSelfSigned("gnap-client");
        serverCert = serverPem.certificatePem;
        Keys.ClientKey serverKey = Keys.load(serverPem.privateKeyPem, serverPem.certificatePem, "httpsig");
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry("server", serverKey.privateKey, new char[0], new Certificate[]{serverPem.certificate});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(store, new char[0]);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String auth) {}
            public void checkServerTrusted(X509Certificate[] chain, String auth) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, null);
        server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(context) {
            public void configure(HttpsParameters params) {
                SSLParameters ssl = context.getDefaultSSLParameters();
                ssl.setWantClientAuth(true);
                params.setSSLParameters(ssl);
            }
        });
        server.createContext("/", ClientTest::handle);
        server.start();
        base = "https://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void down() {
        if (server != null) server.stop(0);
    }

    @Test
    void interactionHashVector() {
        assertEquals("2o3b9NeEcvp0At5d-71yCgybP45eTGm1_pTNMmjv_V0", Hashes.interactionHash("abc", "def", "xyz", "https://as.example/gnap"));
    }

    @Test
    void refusesFrontChannelForeignAndAHashThatIsNotOurs() {
        reset();
        foreign = true;
        GnapClient gnap = client("httpsig");
        assertTrue(assertThrows(GnapError.class, gnap::requestGrant).getMessage().contains("not on the grant endpoint"));
        assertTrue(seen.stream().noneMatch(call -> "/continue".equals(call.get("url"))));
        foreign = false;
        seen.clear();
        GnapClient presenting = client("httpsig");
        Started started = started(presenting);
        assertEquals("httpsig", Json.map(Json.map(started.request.get("client")).get("key")).get("proof"));
        assertFalse(Json.map(started.request.get("client")).containsKey("class_id"));
        assertEquals(List.of("iss_sub", "opaque"), Json.map(started.request.get("subject")).get("sub_id_formats"));
        assertFalse(seen.get(seen.size() - 1).get("signature").isEmpty());
        String digest = finishHash(String.valueOf(Json.map(Json.map(started.request.get("interact")).get("finish")).get("nonce")), "ref-1");
        GnapError front = assertThrows(GnapError.class, () -> presenting.finishRedirect("hash=" + digest + "&interact_ref=ref-1&access_token=no", List.of(started.result.pending.id)));
        assertTrue(front.getMessage().contains("tokens through the browser"));
        assertFalse(front.getMessage().contains("front"));
        assertTrue(assertThrows(GnapError.class, () -> presenting.finishRedirect("hash=" + digest + "&interact_ref=ref-1", List.of("somebody-else"))).getMessage().contains("this browser"));
        assertTrue(seen.stream().noneMatch(call -> "/continue".equals(call.get("url"))));
        assertTrue(assertThrows(GnapError.class, () -> presenting.finishRedirect("hash=nope&interact_ref=ref-1", List.of(started.result.pending.id))).getMessage().contains("this browser"));
    }

    @Test
    void finishesARedirectChecksTheIdTokenAndRotates() {
        reset();
        tooFast = true;
        GnapClient gnap = client("httpsig");
        Started started = started(gnap);
        String digest = finishHash(String.valueOf(Json.map(Json.map(started.request.get("interact")).get("finish")).get("nonce")), "ref-1");
        GnapClient.Finished done = gnap.finishRedirect(Map.of("hash", digest, "interact_ref", "ref-1"), List.of(started.result.pending.id));
        assertEquals("access-1", done.grant.accessToken);
        assertFalse(done.grant.bearer);
        assertEquals("user-1", done.grant.subject.sub);
        assertEquals("user-1@example.com", done.grant.subject.email);
        assertEquals("sess-1", done.grant.subject.sid);
        assertTrue(done.grant.subject.assertionVerified);
        assertEquals("grant-9", done.grant.grantId);
        assertTrue(tooFastSent);
        assertNotNull(gnap.requestGrant().pending);
        Map<String, Object> second = Json.map(Json.parse(seen.stream().filter(call -> "/gnap".equals(call.get("url")) && "POST".equals(call.get("method"))).reduce((a, b) -> b).orElseThrow().get("body")));
        assertEquals("instance-1", second.get("client"));
        GnapClient.Grant rotated = gnap.rotate(done.grant);
        assertEquals("access-2", rotated.accessToken);
        assertEquals("user-1", rotated.subject.sub);
        assertEquals(done.grant.continuation.uri, rotated.continuation.uri);
        gnap.revoke(rotated);
        assertEquals("DELETE", seen.get(seen.size() - 1).get("method"));
        assertTrue(assertThrows(GnapError.class, () -> gnap.finishRedirect(Map.of("hash", digest, "interact_ref", "ref-1"), List.of(started.result.pending.id))).getMessage().contains("already used"));
    }

    @Test
    void provesTheKeyWithDetachedJwsAndMutualTls() {
        reset();
        GnapClient jwsd = client("jwsd");
        Started first = started(jwsd);
        assertEquals("jwsd", Json.map(Json.map(first.request.get("client")).get("key")).get("proof"));
        String digest = finishHash(String.valueOf(Json.map(Json.map(first.request.get("interact")).get("finish")).get("nonce")), "ref-j");
        GnapClient.Finished done = jwsd.finishRedirect("?hash=" + digest + "&interact_ref=ref-j", List.of(first.result.pending.id));
        assertEquals("Ada", done.grant.subject.name);
        assertTrue(seen.stream().anyMatch(call -> "/continue".equals(call.get("url")) && call.get("detached").contains(".")));
        assertEquals("", seen.stream().filter(call -> "/continue".equals(call.get("url"))).findFirst().orElseThrow().get("signature"));
        seen.clear();
        GnapClient mtls = client("mtls");
        Started second = started(mtls);
        assertEquals("mtls", Json.map(Json.map(second.request.get("client")).get("key")).get("proof"));
        Map<String, String> gnapCall = seen.stream().filter(call -> "/gnap".equals(call.get("url"))).findFirst().orElseThrow();
        assertEquals(clientPem.fingerprint256, gnapCall.get("cert"));
        assertEquals("", gnapCall.get("signature"));
        assertEquals("", gnapCall.get("detached"));
        String digest2 = finishHash(String.valueOf(Json.map(Json.map(second.request.get("interact")).get("finish")).get("nonce")), "ref-m");
        GnapClient.Finished finished = mtls.finishPush(Map.of("hash", digest2, "interact_ref", "ref-m"));
        assertEquals("access-1", finished.grant.accessToken);
        Http.Answer answer = mtls.call(finished.grant, base + "/jwks", "GET", null);
        assertEquals(200, answer.status);
        assertTrue(seen.get(seen.size() - 1).get("authorization").matches("GNAP access-1"));
    }

    @Test
    void refusesBearerBadAudienceAndASubjectThatDoesNotMatch() {
        reset();
        bearer = true;
        GnapClient gnap = client("httpsig");
        Started started = started(gnap);
        String digest = finishHash(nonce(started), "ref-b");
        GnapError err = assertThrows(GnapError.class, () -> gnap.finishRedirect(Map.of("hash", digest, "interact_ref", "ref-b"), List.of(started.result.pending.id)));
        assertEquals("validation", err.code);
        assertTrue(err.getMessage().contains("bearer"));
        bearer = false;
        aud = "someone-else";
        GnapClient audience = client("httpsig");
        Started next = started(audience);
        String digest2 = finishHash(nonce(next), "ref-a");
        assertTrue(assertThrows(GnapError.class, () -> audience.finishRedirect(Map.of("hash", digest2, "interact_ref", "ref-a"), List.of(next.result.pending.id))).getMessage().contains("id_token is for"));
        aud = "gnap-caep-risc-demo";
        issSub = "other-user";
        sub = "user-1";
        Started third = started(gnap);
        String digest3 = finishHash(nonce(third), "ref-s");
        assertTrue(assertThrows(GnapError.class, () -> gnap.finishRedirect(Map.of("hash", digest3, "interact_ref", "ref-s"), List.of(third.result.pending.id))).getMessage().contains("somebody other"));
    }

    @Test
    void acceptsTheApplicationIdentifierAsTheAudience() {
        reset();
        aud = "gnap-caep-risc-demo";
        sub = "user-2";
        GnapClient gnap = client("httpsig");
        Started started = started(gnap);
        String digest = finishHash(nonce(started), "ref-app");
        GnapClient.Finished done = gnap.finishRedirect(Map.of("hash", digest, "interact_ref", "ref-app"), List.of(started.result.pending.id));
        assertEquals("user-2", done.grant.subject.sub);
        done.grant.expiresAt = System.currentTimeMillis() + 10_000;
        GnapClient.Grant fresh = gnap.ensureFresh(done.grant, null);
        assertEquals("access-2", fresh.accessToken);
        fresh.expiresAt = System.currentTimeMillis() + 3_600_000;
        assertEquals("access-2", gnap.ensureFresh(fresh, null).accessToken);
    }

    @Test
    void certificateChainPutsTheLeafInTheKeyAndTheChainOnTls() {
        X509Gen.KeyPairPem leaf = X509Gen.createSelfSigned("leaf.example");
        X509Gen.KeyPairPem issuer = X509Gen.createSelfSigned("issuer.example");
        String chain = leaf.certificatePem.trim() + "\n" + issuer.certificatePem.trim() + "\n";
        Keys.ClientKey key = Keys.load(leaf.privateKeyPem, chain, "mtls");
        Map<String, Object> published = Keys.publicKeyObject(key);
        assertEquals(1, count((String) published.get("cert")));
        assertEquals(leaf.fingerprint256, Keys.fingerprint256(read((String) published.get("cert"))));
        GnapClient gnap = GnapClient.create(GnapClient.resolve(Map.of(
                "grantEndpoint", "https://as.example/gnap",
                "application", "chain-demo",
                "keyProof", "mtls",
                "privateKey", leaf.privateKeyPem,
                "certificate", chain,
                "finishUri", "http://127.0.0.1:9/callback"), Path.of(".")));
        assertEquals(2, count((String) gnap.tls().get("cert")));
        assertNull(gnap.instanceId());
    }

    private static void reset() {
        foreign = false;
        bearer = false;
        tooFast = false;
        tooFastSent = false;
        aud = "instance-1";
        sub = "user-1";
        issSub = null;
        seen.clear();
    }

    private static String nonce(Started started) {
        return String.valueOf(Json.map(Json.map(started.request.get("interact")).get("finish")).get("nonce"));
    }

    private static String finishHash(String clientNonce, String interactRef) {
        return Json.b64url(Json.sha256((clientNonce + "\nserver-nonce\n" + interactRef + "\n" + base + "/gnap").getBytes(StandardCharsets.UTF_8)));
    }

    private static GnapClient client(String proof) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("grantEndpoint", base + "/gnap");
        body.put("idTokenIssuer", base);
        body.put("application", "gnap-caep-risc-demo");
        body.put("display", Map.of("name", "GNAP CAEP RISC demo", "uri", "http://127.0.0.1:3000/"));
        body.put("access", List.of("ssf.read", "ssf.manage"));
        body.put("subIdFormats", List.of("iss_sub", "account", "opaque"));
        body.put("assertionFormats", List.of("id_token"));
        body.put("keyProof", proof);
        body.put("privateKey", clientPem.privateKeyPem);
        body.put("certificate", clientPem.certificatePem);
        body.put("finishUri", "http://127.0.0.1:3000/callback");
        body.put("finishMethod", "redirect");
        body.put("tlsCa", serverCert);
        return GnapClient.create(GnapClient.resolve(body, Path.of(".")));
    }

    private static Started started(GnapClient gnap) {
        GnapClient.GrantResult result = gnap.requestGrant();
        assertNotNull(result.pending);
        String body = seen.stream().filter(call -> "POST".equals(call.get("method")) && "/gnap".equals(call.get("url"))).reduce((a, b) -> b).orElseThrow().get("body");
        return new Started(result, Json.map(Json.parse(body)));
    }

    private record Started(GnapClient.GrantResult result, Map<String, Object> request) {}

    private static void handle(com.sun.net.httpserver.HttpExchange exchange) {
        try {
            String raw = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            String target = base + path;
            Map<String, String> headers = new LinkedHashMap<>();
            exchange.getRequestHeaders().forEach((name, values) -> headers.put(name.toLowerCase(), values.get(0)));
            String cert = "";
            if (exchange instanceof HttpsExchange https) {
                try {
                    Certificate[] chain = https.getSSLSession().getPeerCertificates();
                    if (chain.length > 0 && chain[0] instanceof X509Certificate x509) cert = Keys.fingerprint256(x509);
                } catch (Exception ignored) {
                    cert = "";
                }
            }
            Map<String, String> call = new LinkedHashMap<>();
            call.put("method", method);
            call.put("url", path);
            call.put("body", raw);
            call.put("authorization", headers.getOrDefault("authorization", ""));
            call.put("signature", headers.getOrDefault("signature", ""));
            call.put("detached", headers.getOrDefault("detached-jws", ""));
            call.put("cert", cert);
            seen.add(call);
            if ("OPTIONS".equals(method) && "/gnap".equals(path)) {
                send(exchange, 200, Json.dumps(Map.of(
                        "grant_request_endpoint", base + "/gnap",
                        "key_proofs_supported", List.of("httpsig", "jwsd", "mtls"),
                        "interaction_start_modes_supported", List.of("redirect"),
                        "interaction_finish_methods_supported", List.of("redirect", "push"),
                        "sub_id_formats_supported", List.of("iss_sub", "opaque"),
                        "assertion_formats_supported", List.of("id_token"))));
                return;
            }
            if ("/.well-known/openid-configuration".equals(path)) {
                send(exchange, 200, Json.dumps(Map.of("issuer", base, "jwks_uri", base + "/jwks")));
                return;
            }
            if ("/jwks".equals(path)) {
                send(exchange, 200, Json.dumps(Map.of("keys", List.of(idJwk))));
                return;
            }
            if (!raw.isBlank() && "/gnap".equals(path)) remember(raw);
            if (headers.containsKey("signature")) verifyHttpsig(headers, method, raw, target);
            if (headers.containsKey("detached-jws")) verifyJwsd(headers, method, raw, target);
            if ("/gnap".equals(path) && "POST".equals(method)) {
                String cont = foreign ? "https://evil.example/continue" : base + "/continue";
                send(exchange, 200, Json.dumps(Map.of(
                        "instance_id", "instance-1",
                        "interact", Map.of("redirect", base + "/interact/1", "finish", "server-nonce"),
                        "continue", Map.of("uri", cont, "wait", 0, "access_token", Map.of("value", "cont-token")))));
                return;
            }
            if ("/continue".equals(path) && "POST".equals(method)) {
                if (!"GNAP cont-token".equals(headers.get("authorization"))) throw new IllegalStateException("authorization");
                if (tooFast && !tooFastSent) {
                    tooFastSent = true;
                    send(exchange, 400, Json.dumps(Map.of("error", "too_fast", "continue", Map.of("uri", base + "/continue", "wait", 0, "access_token", Map.of("value", "cont-token")))));
                    return;
                }
                String token = idToken(base, aud, sub);
                Map<String, Object> access = new LinkedHashMap<>();
                access.put("value", "access-1");
                access.put("access", List.of("ssf.read", "ssf.manage"));
                access.put("expires_in", 3600);
                if (bearer) access.put("flags", List.of("bearer"));
                access.put("manage", Map.of("uri", base + "/token/grant-9", "access_token", Map.of("value", "manage-1")));
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("instance_id", "instance-1");
                body.put("access_token", access);
                body.put("continue", Map.of("uri", base + "/continue/grant-9", "access_token", Map.of("value", "cont-next")));
                body.put("subject", Map.of(
                        "sub_ids", List.of(Map.of("format", "iss_sub", "iss", base, "sub", issSub == null ? sub : issSub)),
                        "assertions", List.of(Map.of("format", "id_token", "value", token))));
                send(exchange, 200, Json.dumps(body));
                return;
            }
            if ("/token/grant-9".equals(path) && "POST".equals(method)) {
                if (!"GNAP manage-1".equals(headers.get("authorization"))) throw new IllegalStateException("manage");
                send(exchange, 200, Json.dumps(Map.of("access_token", Map.of("value", "access-2", "expires_in", 3600, "manage", Map.of("uri", base + "/token/grant-9", "access_token", Map.of("value", "manage-2"))))));
                return;
            }
            if ("DELETE".equals(method)) {
                exchange.sendResponseHeaders(204, -1);
                exchange.close();
                return;
            }
            send(exchange, 404, Json.dumps(Map.of("error", "not_found")));
        } catch (Exception err) {
            try {
                send(exchange, 401, Json.dumps(Map.of("error", "invalid_client", "error_description", String.valueOf(err.getMessage()))));
            } catch (Exception ignored) {
                exchange.close();
            }
        }
    }

    private static void remember(String body) {
        Map<String, Object> doc = Json.map(Json.parse(body));
        Map<String, Object> client = Json.map(doc.get("client"));
        Map<String, Object> key = client == null ? null : Json.map(client.get("key"));
        Map<String, Object> jwk = key == null ? null : Json.map(key.get("jwk"));
        if (jwk != null) {
            publicKey = (ECPublicKey) Keys.publicKeyFromJwk(jwk);
            kid = String.valueOf(jwk.get("kid"));
        }
    }

    private static void verifyHttpsig(Map<String, String> headers, String method, String raw, String target) throws Exception {
        String input = headers.getOrDefault("signature-input", "");
        if (input.contains(";alg=")) throw new IllegalStateException("alg");
        Matcher match = Pattern.compile("^sig1=\\(([^)]*)\\)(.*)$").matcher(input);
        if (!match.matches()) throw new IllegalStateException(input);
        List<String> components = new ArrayList<>();
        Matcher names = Pattern.compile("\"([^\"]+)\"").matcher(match.group(1));
        while (names.find()) components.add(names.group(1));
        String serialised = "(" + String.join(" ", components.stream().map(item -> "\"" + item + "\"").toList()) + ")" + match.group(2);
        if (!match.group(2).contains("tag=\"gnap\"")) throw new IllegalStateException("tag");
        if (!match.group(2).contains("keyid=\"" + kid + "\"")) throw new IllegalStateException("keyid");
        List<String> lines = new ArrayList<>();
        for (String component : components) {
            String value = "@method".equals(component) ? method.toUpperCase() : "@target-uri".equals(component) ? target : headers.getOrDefault(component, "").trim();
            lines.add("\"" + component + "\": " + value);
        }
        lines.add("\"@signature-params\": " + serialised);
        Matcher sig = Pattern.compile("^sig1=:([A-Za-z0-9+/=]*):$").matcher(headers.getOrDefault("signature", ""));
        if (!sig.matches()) throw new IllegalStateException("signature");
        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(publicKey);
        verifier.update(String.join("\n", lines).getBytes(StandardCharsets.UTF_8));
        if (!verifier.verify(java.util.Base64.getDecoder().decode(sig.group(1)))) throw new IllegalStateException("httpsig");
        if (!raw.isEmpty()) {
            String digest = "sha-256=:" + Json.b64(Json.sha256(raw.getBytes(StandardCharsets.UTF_8))) + ":";
            if (!digest.equals(headers.get("content-digest"))) throw new IllegalStateException("digest");
        }
    }

    private static void verifyJwsd(Map<String, String> headers, String method, String raw, String target) throws Exception {
        String[] parts = headers.getOrDefault("detached-jws", "").split("\\.", -1);
        if (parts.length != 3) throw new IllegalStateException("jws");
        Map<String, Object> header = Json.map(Json.parse(new String(Json.b64urlDecode(parts[0]), StandardCharsets.UTF_8)));
        if (!"gnap-binding-jwsd".equals(header.get("typ")) || !"ES256".equals(header.get("alg")) || !kid.equals(header.get("kid"))) throw new IllegalStateException("header");
        if (!method.equalsIgnoreCase(String.valueOf(header.get("htm"))) || !target.equals(header.get("uri"))) throw new IllegalStateException("uri");
        String token = headers.getOrDefault("authorization", "").replaceFirst("^GNAP ", "");
        if (headers.containsKey("authorization")) {
            if (!Json.b64url(Json.sha256(token.getBytes(StandardCharsets.US_ASCII))).equals(header.get("ath"))) throw new IllegalStateException("ath");
        } else if (header.containsKey("ath")) throw new IllegalStateException("ath");
        String payload = raw.isEmpty() ? "" : Json.b64url(Json.sha256(raw.getBytes(StandardCharsets.UTF_8)));
        if (!payload.equals(parts[1])) throw new IllegalStateException("payload");
        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(publicKey);
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        if (!verifier.verify(Json.b64urlDecode(parts[2]))) throw new IllegalStateException("jwsd");
    }

    private static String idToken(String issuer, String audience, String subject) throws Exception {
        String header = Json.b64url(Json.dumps(Map.of("alg", "RS256", "kid", "id1", "typ", "JWT")).getBytes(StandardCharsets.UTF_8));
        long now = System.currentTimeMillis() / 1000;
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("aud", audience);
        claims.put("sub", subject);
        claims.put("exp", now + 600);
        claims.put("iat", now);
        claims.put("email", subject + "@example.com");
        claims.put("sid", "sess-1");
        claims.put("name", "Ada");
        String payload = Json.b64url(Json.dumps(claims).getBytes(StandardCharsets.UTF_8));
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(idKeys.getPrivate());
        signature.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
        return header + "." + payload + "." + Json.b64url(signature.sign());
    }

    private static void send(com.sun.net.httpserver.HttpExchange exchange, int status, String body) throws Exception {
        byte[] raw = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, raw.length);
        exchange.getResponseBody().write(raw);
        exchange.close();
    }

    private static int count(String pem) {
        int n = 0;
        int at = 0;
        while ((at = pem.indexOf("BEGIN CERTIFICATE", at)) >= 0) {
            n++;
            at += 1;
        }
        return n;
    }

    private static X509Certificate read(String pem) {
        try {
            return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception err) {
            throw new RuntimeException(err);
        }
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
