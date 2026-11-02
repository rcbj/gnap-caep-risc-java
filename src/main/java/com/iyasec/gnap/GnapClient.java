// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Server-side GNAP client. The private key stays in this process. Tokens are key-bound.
 * Call {@link #fromFile}, {@link #requestGrant}, then {@link #finishRedirect}.
 */
public final class GnapClient {
    private static final Set<String> FRONT = Set.of("access_token", "id_token", "token", "value", "continue", "refresh_token");
    private final Config.Resolved config;
    private Map<String, Object> metadata;
    private String instanceId;
    private final List<String> subIdFormats;
    private final List<String> assertionFormats;
    private List<Map<String, Object>> jwks;
    private final Map<String, Pending> pending = new LinkedHashMap<>();
    private final Map<String, Boolean> used = new LinkedHashMap<>();

    private GnapClient(Config.Resolved config) {
        this.config = config;
        this.subIdFormats = new ArrayList<>(config.subIdFormats);
        this.assertionFormats = new ArrayList<>(config.assertionFormats);
    }

    public static GnapClient fromFile(String path) {
        return new GnapClient(Config.readFile(path));
    }

    public static GnapClient create(Config.Resolved config) {
        return new GnapClient(config);
    }

    public static Config.Resolved resolve(Object raw, Path baseDir) {
        return Config.resolve(raw, baseDir);
    }

    public Config.Resolved config() { return config; }
    public Keys.ClientKey key() { return config.key; }
    public String instanceId() { return instanceId; }

    public Map<String, Object> tls() {
        Map<String, Object> out = new LinkedHashMap<>();
        if (config.tlsCa != null) out.put("ca", config.tlsCa);
        if ("mtls".equals(config.key.proof) && (config.key.tlsChainPem != null || config.key.certificatePem != null)) {
            out.put("cert", config.key.tlsChainPem != null ? config.key.tlsChainPem : config.key.certificatePem);
            out.put("key", config.key.privatePem());
        }
        return out;
    }

    public Map<String, Object> discover() {
        if (metadata != null) return metadata;
        Map<String, Object> found = Discovery.discoverGrantServer(config.grantEndpoint, tls());
        List<String> proofs = stringList(found.get("key_proofs_supported"));
        if (proofs != null && !proofs.contains(config.key.proof)) {
            throw new GnapError("discovery", "the grant server does not accept the " + config.key.proof + " key proof");
        }
        List<String> finishes = stringList(found.get("interaction_finish_methods_supported"));
        if (finishes != null && config.finishUri != null && !finishes.contains(config.finishMethod)) {
            throw new GnapError("discovery", "the grant server does not accept a " + config.finishMethod + " interaction finish");
        }
        List<String> sub = stringList(found.get("sub_id_formats_supported"));
        if (sub != null) subIdFormats.removeIf(item -> !sub.contains(item));
        List<String> assertions = stringList(found.get("assertion_formats_supported"));
        if (assertions != null) assertionFormats.removeIf(item -> !assertions.contains(item));
        metadata = found;
        return found;
    }

    public GrantResult requestGrant() {
        return requestGrant(null, null, null, true);
    }

    public GrantResult requestGrant(List<Object> access, Object user, String expectedSub, boolean subject) {
        discover();
        List<Object> rights = access == null ? config.access : access;
        if (rights == null || rights.isEmpty()) throw new GnapError("config", "access is required");
        byte[] nonce = new byte[24];
        new SecureRandom().nextBytes(nonce);
        String clientNonce = Json.b64url(nonce);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", Json.obj("access", rights));
        body.put("client", clientMember());
        if (config.finishUri != null) {
            body.put("interact", Json.obj(
                    "start", config.interactionStart,
                    "finish", Json.obj("method", config.finishMethod, "uri", config.finishUri, "nonce", clientNonce)));
        }
        if (subject && (!subIdFormats.isEmpty() || !assertionFormats.isEmpty())) {
            Map<String, Object> subjectBody = new LinkedHashMap<>();
            if (!subIdFormats.isEmpty()) subjectBody.put("sub_id_formats", new ArrayList<>(subIdFormats));
            if (!assertionFormats.isEmpty()) subjectBody.put("assertion_formats", new ArrayList<>(assertionFormats));
            body.put("subject", subjectBody);
        }
        if (user != null) body.put("user", user);
        Object answer = signedJson("POST", config.grantEndpoint, body, null);
        rememberInstance(answer);
        Map<String, Object> doc = Json.map(answer);
        if (doc != null && doc.get("interact") != null) {
            String redirect = redirect(doc);
            Pending held = rememberPending(doc, clientNonce, expectedSub);
            return new GrantResult(redirect, held, null);
        }
        if (hasToken(answer)) {
            Grant grant = grantFrom(answer, null);
            expect(grant, expectedSub);
            return new GrantResult(null, null, grant);
        }
        throw new GnapError("protocol", "the grant response has neither an interaction nor an access token");
    }

    public Finished finishRedirect(Object query, Collection<String> allowedIds) {
        List<String[]> pairs = params(query);
        Map<String, List<String>> names = new LinkedHashMap<>();
        for (String[] pair : pairs) names.computeIfAbsent(pair[0], key -> new ArrayList<>()).add(pair[1]);
        List<String> injected = new ArrayList<>();
        for (String name : FRONT) if (names.containsKey(name)) injected.add(name);
        if (!injected.isEmpty()) {
            throw new GnapError("validation", "the finish redirect carries " + String.join(", ", injected) + "; GNAP does not send tokens through the browser");
        }
        for (Map.Entry<String, List<String>> entry : names.entrySet()) {
            if (entry.getValue().size() > 1) throw new GnapError("validation", "the finish redirect repeats \"" + entry.getKey() + "\"");
        }
        String digest = first(names, "hash");
        String interactRef = first(names, "interact_ref");
        if (digest == null || interactRef == null) {
            String error = first(names, "error");
            if (error != null) {
                String description = first(names, "error_description");
                throw new GnapError("protocol", description != null ? description : error, null, error, null);
            }
            throw new GnapError("validation", "the finish redirect has no hash or interact_ref");
        }
        return finish(match(digest, interactRef, allowedIds), interactRef, digest);
    }

    public Finished finishPush(Object body) {
        Map<String, Object> doc = Json.map(body);
        if (doc == null) throw new GnapError("validation", "a push finish is a JSON object");
        if (!(doc.get("hash") instanceof String digest) || !(doc.get("interact_ref") instanceof String interactRef)) {
            if (doc.get("error") instanceof String error) throw new GnapError("protocol", error, null, error, null);
            throw new GnapError("validation", "a push finish needs hash and interact_ref");
        }
        return finish(match(digest, interactRef, null), interactRef, digest);
    }

    public Map<String, String> authorizationHeaders(Grant grant, String method, String url, String body) {
        return proofHeaders(method, url, body, grant.accessToken, null);
    }

    public Http.Answer call(Grant grant, String url, String method, String body) {
        Map<String, String> proof = authorizationHeaders(grant, method, url, body);
        return Http.send(url, method, proof, body, tls(), "protocol");
    }

    public Grant rotate(Grant grant) {
        if (grant.manage == null) throw new GnapError("protocol", "this access token has no manage URI");
        checkSameOrigin(grant.manage.uri, "manage.uri");
        Object answer = signedJson("POST", grant.manage.uri, null, grant.manage.accessToken);
        if (!hasToken(answer)) throw new GnapError("protocol", "the rotation returned no access token");
        Grant next = grantFrom(answer, grant);
        if (!grant.bearer && next.bearer) throw new GnapError("validation", "rotating a key-bound token returned a bearer token");
        return next;
    }

    public void revoke(Grant grant) {
        if (grant.continuation == null) throw new GnapError("protocol", "this grant has no continuation, so it cannot be revoked");
        checkSameOrigin(grant.continuation.uri, "continue.uri");
        signedJson("DELETE", grant.continuation.uri, null, grant.continuation.accessToken);
    }

    public Grant ensureFresh(Grant grant, Long now) {
        long clock = now == null ? System.currentTimeMillis() : now;
        if (grant.expiresAt == null || grant.expiresAt - clock > 60_000L) return grant;
        return rotate(grant);
    }

    private Object clientMember() {
        if (config.useInstanceId && instanceId != null) return instanceId;
        Map<String, Object> member = new LinkedHashMap<>();
        member.put("key", Keys.publicKeyObject(config.key));
        if (config.display != null) member.put("display", config.display);
        if (config.classId != null) member.put("class_id", config.classId);
        return member;
    }

    private void rememberInstance(Object answer) {
        Map<String, Object> doc = Json.map(answer);
        if (!config.useInstanceId || doc == null) return;
        if (doc.get("instance_id") instanceof String id && !id.isBlank()) instanceId = id;
    }

    private String redirect(Map<String, Object> answer) {
        Map<String, Object> interact = Json.map(answer.get("interact"));
        Object redirect = interact == null ? null : interact.get("redirect");
        if (!(redirect instanceof String url)) throw new GnapError("protocol", "the interaction is not a redirect");
        URI parts;
        try {
            parts = URI.create(url);
            if (parts.getScheme() == null || parts.getHost() == null) throw new IllegalArgumentException(url);
        } catch (Exception err) {
            Caught.error(err);
            throw new GnapError("protocol", "interact.redirect is not a URL: " + url, err);
        }
        if (!"https".equals(parts.getScheme()) && !("http".equals(parts.getScheme()) && (config.allowInsecure || Urls.isLoopback(url)))) {
            throw new GnapError("validation", "interact.redirect must use https: " + url);
        }
        return url;
    }

    private Pending rememberPending(Map<String, Object> answer, String clientNonce, String expectedSub) {
        Map<String, Object> interact = Json.map(answer.get("interact"));
        Object finish = interact == null ? null : interact.get("finish");
        if (!(finish instanceof String serverNonce) || serverNonce.isBlank()) {
            throw new GnapError("protocol", "the grant response has no interaction finish nonce");
        }
        Continuation cont = continuation(answer.get("continue"), "continue");
        Pending held = new Pending();
        held.id = clientNonce;
        held.clientNonce = clientNonce;
        held.serverNonce = serverNonce;
        held.continuation = cont;
        held.continueNotBefore = System.currentTimeMillis() + (long) ((cont.wait == null ? 0 : cont.wait) * 1000);
        held.grantEndpoint = config.grantEndpoint;
        held.createdAt = System.currentTimeMillis();
        held.instanceId = instanceId;
        held.expectedSub = expectedSub;
        sweep();
        pending.put(held.id, held);
        return held;
    }

    private Pending match(String digest, String interactRef, Collection<String> allowedIds) {
        if (used.containsKey(digest)) throw new GnapError("validation", "this interaction finish was already used");
        for (Pending item : pending.values()) {
            if (allowedIds != null && !allowedIds.contains(item.id)) continue;
            String expected = Hashes.interactionHash(item.clientNonce, item.serverNonce, interactRef, item.grantEndpoint);
            if (!Hashes.hashEqual(digest, expected)) continue;
            if (System.currentTimeMillis() - item.createdAt > config.transactionTtlSec * 1000) {
                pending.remove(item.id);
                throw new GnapError("validation", "the approval took too long; start again");
            }
            return item;
        }
        throw new GnapError("validation", allowedIds != null
                ? "this finish is not a sign-in this browser started"
                : "the interaction hash matches no grant in progress");
    }

    private Finished finish(Pending item, String interactRef, String digest) {
        pending.remove(item.id);
        used.put(digest, Boolean.TRUE);
        if (used.size() > 1000) used.remove(used.keySet().iterator().next());
        long due = item.continueNotBefore - System.currentTimeMillis();
        if (due > 0) {
            try {
                Thread.sleep(Math.min(due, config.maxWaitSec * 1000));
            } catch (InterruptedException err) {
                Caught.error(err);
                Thread.currentThread().interrupt();
                throw new GnapError("protocol", "interrupted while waiting to continue", err);
            }
        }
        Object answer;
        try {
            answer = cont(item.continuation, Json.obj("interact_ref", interactRef));
        } catch (GnapError err) {
            err.context = item.context;
            throw err;
        }
        if (!hasToken(answer)) {
            GnapError err = new GnapError("protocol", "the resource owner did not approve the grant", null, "user_denied", null);
            err.context = item.context;
            throw err;
        }
        try {
            Grant grant = grantFrom(answer, null);
            if (grant.continuation == null) grant.continuation = item.continuation;
            expect(grant, item.expectedSub);
            return new Finished(grant);
        } catch (GnapError err) {
            err.context = item.context;
            throw err;
        }
    }

    private Object cont(Continuation current, Map<String, Object> body) {
        Continuation cursor = current;
        double waited = 0;
        int immediate = 0;
        while (true) {
            try {
                return signedJson("POST", cursor.uri, body, cursor.accessToken);
            } catch (GnapError err) {
                if (!"too_fast".equals(err.gnapError)) throw err;
                if (err.continuation != null) {
                    checkSameOrigin(err.continuation.uri, "continue.uri");
                    cursor = new Continuation(err.continuation.uri, err.continuation.accessToken, err.continuation.wait);
                }
                double wait = Math.max(0, cursor.wait == null ? 0 : cursor.wait);
                if (wait == 0) {
                    immediate += 1;
                    if (immediate > 2) throw err;
                    continue;
                }
                if (waited + wait > config.maxWaitSec) throw err;
                try {
                    Thread.sleep((long) (wait * 1000));
                } catch (InterruptedException interrupted) {
                    Caught.error(interrupted);
                    Thread.currentThread().interrupt();
                    throw err;
                }
                waited += wait;
            }
        }
    }

    private Object signedJson(String method, String url, Object body, String token) {
        checkSameOrigin(url, "the request URL");
        String text = body == null ? null : Json.dumps(body);
        Map<String, String> extra = text == null ? null : Map.of("content-type", "application/json");
        Map<String, String> headers = proofHeaders(method, url, text, token, extra);
        headers.put("accept", "application/json");
        return read(Http.send(url, method, headers, text, tls(), "protocol"));
    }

    private Map<String, String> proofHeaders(String method, String url, String body, String token, Map<String, String> extra) {
        Map<String, String> headers = new LinkedHashMap<>();
        if (extra != null) headers.putAll(extra);
        if (token != null) headers.put("authorization", "GNAP " + token);
        if ("httpsig".equals(config.key.proof)) headers.putAll(HttpSig.sign(config.key, method, url, headers, body));
        else if ("jwsd".equals(config.key.proof)) headers.put("detached-jws", Jwsd.detached(config.key, method, url, body, token));
        return headers;
    }

    private Object read(Http.Answer answer) {
        if (answer.status == 204 || answer.body == null || answer.body.isEmpty()) {
            if (answer.status >= 400) throw new GnapError("protocol", "the authorization server answered " + answer.status);
            return null;
        }
        Object parsed;
        try {
            parsed = Json.parse(answer.body);
        } catch (Exception err) {
            Caught.error(err);
            throw new GnapError("protocol", "the authorization server answered " + answer.status + " with a body that is not JSON", err);
        }
        if (answer.status >= 200 && answer.status < 300) return parsed;
        Map<String, Object> doc = Json.map(parsed);
        if (doc == null) doc = Map.of();
        String code = doc.get("error") instanceof String text ? text : null;
        GnapError.Continuation continuation = null;
        Map<String, Object> raw = Json.map(doc.get("continue"));
        if (raw != null && raw.get("uri") instanceof String uri) {
            Map<String, Object> token = Json.map(raw.get("access_token"));
            if (token != null && token.get("value") instanceof String value) {
                continuation = new GnapError.Continuation(uri, value, raw.get("wait") instanceof Number number ? number.doubleValue() : null);
            }
        }
        String description = doc.get("error_description") instanceof String text && !text.isBlank() ? text : null;
        throw new GnapError("protocol", description != null ? description : code != null ? code : "the authorization server answered " + answer.status, null, code, continuation);
    }

    private boolean hasToken(Object answer) {
        Map<String, Object> doc = Json.map(answer);
        return doc != null && doc.get("access_token") != null;
    }

    private Grant grantFrom(Object answer, Grant previous) {
        Map<String, Object> doc = Json.map(answer);
        if (doc == null) doc = Map.of();
        Object tokenRaw = doc.get("access_token");
        if (tokenRaw instanceof List<?> list) tokenRaw = list.isEmpty() ? null : list.get(0);
        Map<String, Object> token = Json.map(tokenRaw);
        if (token == null) throw new GnapError("protocol", "the access token is not an object");
        if (!(token.get("value") instanceof String value) || value.isBlank()) throw new GnapError("protocol", "the access token has no value");
        List<String> flags = new ArrayList<>();
        if (token.get("flags") instanceof List<?> list) for (Object item : list) flags.add(String.valueOf(item));
        boolean bearer = flags.contains("bearer");
        if (bearer && config.requireBoundTokens) {
            throw new GnapError("validation", "the authorization server issued a bearer token, and this client requires a key-bound one");
        }
        rememberInstance(answer);
        Continuation manage = null;
        if (token.get("manage") instanceof Map<?, ?> rawMap) {
            @SuppressWarnings("unchecked")
            Map<String, Object> raw = (Map<String, Object>) rawMap;
            Map<String, Object> manageToken = Json.map(raw.get("access_token"));
            if (!(raw.get("uri") instanceof String uri) || manageToken == null || !(manageToken.get("value") instanceof String manageValue)) {
                throw new GnapError("protocol", "the access token manage object is not usable");
            }
            checkSameOrigin(uri, "manage.uri");
            manage = new Continuation(uri, manageValue, null);
        } else if (previous != null) manage = previous.manage;
        Continuation cont;
        if (doc.get("continue") != null) cont = continuation(doc.get("continue"), "continue");
        else if (previous != null) cont = previous.continuation;
        else cont = null;
        List<String> audiences = new ArrayList<>();
        if (instanceId != null) audiences.add(instanceId);
        if (config.application != null) audiences.add(config.application);
        Subject.Person subject = null;
        if (doc.get("subject") != null) {
            subject = Subject.personFrom(doc.get("subject"), new Subject.Check(config.idTokenIssuer, audiences, config.clockToleranceSec, this::idTokenKeys));
        } else if (previous != null) subject = previous.subject;
        Long expiresIn = token.get("expires_in") instanceof Number number ? number.longValue() : null;
        Long expiresAt = expiresIn == null ? null : System.currentTimeMillis() + expiresIn * 1000;
        Grant grant = new Grant();
        grant.accessToken = value;
        grant.bearer = bearer;
        grant.access = token.get("access");
        grant.expiresIn = expiresIn;
        grant.expiresAt = expiresAt;
        grant.manage = manage;
        grant.continuation = cont;
        grant.instanceId = instanceId;
        grant.subject = subject;
        grant.grantId = grantId(cont == null ? null : cont.uri);
        return grant;
    }

    private void expect(Grant grant, String expectedSub) {
        if (expectedSub != null && grant.subject != null && !expectedSub.equals(grant.subject.sub)) {
            throw new GnapError("validation", "the grant was approved by somebody other than the account that was asked for");
        }
    }

    private Continuation continuation(Object raw, String what) {
        Map<String, Object> doc = Json.map(raw);
        if (doc == null) throw new GnapError("protocol", "the response has no " + what + " object");
        Map<String, Object> token = Json.map(doc.get("access_token"));
        if (!(doc.get("uri") instanceof String uri) || token == null || !(token.get("value") instanceof String value)) {
            throw new GnapError("protocol", "the response has no usable " + what + " object");
        }
        checkSameOrigin(uri, what + ".uri");
        if (doc.containsKey("wait") && doc.get("wait") != null && (!(doc.get("wait") instanceof Number number) || number.doubleValue() < 0)) {
            throw new GnapError("protocol", what + ".wait is not a number of seconds");
        }
        return new Continuation(uri, value, doc.get("wait") instanceof Number number ? number.doubleValue() : null);
    }

    private void checkSameOrigin(String uri, String what) {
        URI parts;
        try {
            parts = URI.create(uri);
            if (parts.getScheme() == null || parts.getHost() == null || (!"https".equals(parts.getScheme()) && !"http".equals(parts.getScheme()))) {
                throw new IllegalArgumentException(uri);
            }
        } catch (Exception err) {
            Caught.error(err);
            throw new GnapError("validation", what + " is not a URL: " + uri, err);
        }
        if (!"https".equals(parts.getScheme()) && !config.allowInsecure) {
            throw new GnapError("validation", what + " must use https: " + uri);
        }
        if (!Urls.origin(uri).equals(Urls.origin(config.grantEndpoint))) {
            throw new GnapError("validation", what + " " + uri + " is not on the grant endpoint's origin");
        }
    }

    private List<Map<String, Object>> idTokenKeys() {
        if (jwks != null) return jwks;
        Map<String, Object> metadata = Discovery.discoverOpenId(config.idTokenIssuer, tls());
        Http.Answer answer = Http.send(String.valueOf(metadata.get("jwks_uri")), "GET", Map.of("accept", "application/json"), null, tls(), "discovery");
        Object parsed;
        try {
            parsed = Json.parse(answer.body);
        } catch (Exception err) {
            Caught.error(err);
            throw new GnapError("discovery", "the issuer JWKS is not JSON", err);
        }
        Map<String, Object> doc = Json.map(parsed);
        List<Object> keys = doc == null ? null : Json.list(doc.get("keys"));
        if (answer.status != 200 || keys == null) throw new GnapError("discovery", "the issuer JWKS answered " + answer.status);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object key : keys) {
            Map<String, Object> one = Json.map(key);
            if (one != null) out.add(one);
        }
        jwks = out;
        return out;
    }

    private void sweep() {
        long cutoff = System.currentTimeMillis() - config.transactionTtlSec * 1000;
        pending.entrySet().removeIf(entry -> entry.getValue().createdAt < cutoff);
        while (pending.size() > 1000) pending.remove(pending.keySet().iterator().next());
    }

    private static String grantId(String uri) {
        if (uri == null) return null;
        try {
            String path = URI.create(uri).getPath();
            if (path == null) return null;
            String[] parts = path.split("/");
            String last = "";
            for (String part : parts) if (!part.isEmpty()) last = part;
            return last.isEmpty() ? null : java.net.URLDecoder.decode(last, StandardCharsets.UTF_8);
        } catch (Exception err) {
            Caught.warn(err);
            return null;
        }
    }

    private static String first(Map<String, List<String>> names, String key) {
        List<String> values = names.get(key);
        return values == null || values.isEmpty() || values.get(0) == null || values.get(0).isBlank() ? null : values.get(0);
    }

    private static List<String> stringList(Object value) {
        List<Object> list = Json.list(value);
        if (list == null) return null;
        List<String> out = new ArrayList<>();
        for (Object item : list) if (item instanceof String text) out.add(text);
        return out;
    }

    private static List<String[]> params(Object value) {
        List<String[]> pairs = new ArrayList<>();
        if (value instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String key = String.valueOf(entry.getKey());
                if (entry.getValue() instanceof List<?> list) {
                    for (Object item : list) if (item instanceof String text) pairs.add(new String[]{key, text});
                } else if (entry.getValue() instanceof String text) pairs.add(new String[]{key, text});
            }
            return pairs;
        }
        if (value instanceof String text) {
            String query = text;
            if (text.matches("(?i)^[a-z][a-z0-9+.-]*:.*") || text.startsWith("/")) query = URI.create(text).getRawQuery();
            else if (text.startsWith("?") || text.startsWith("#")) query = text.substring(1);
            if (query == null) return pairs;
            for (String part : query.split("&")) {
                if (part.isEmpty()) continue;
                int eq = part.indexOf('=');
                String key = eq < 0 ? part : part.substring(0, eq);
                String raw = eq < 0 ? "" : part.substring(eq + 1);
                pairs.add(new String[]{decode(key), decode(raw)});
            }
            return pairs;
        }
        throw new GnapError("validation", "the finish redirect could not be read");
    }

    private static String decode(String value) {
        return java.net.URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    public static final class Continuation {
        public final String uri;
        public final String accessToken;
        public final Double wait;

        public Continuation(String uri, String accessToken, Double wait) {
            this.uri = uri;
            this.accessToken = accessToken;
            this.wait = wait;
        }
    }

    public static final class Pending {
        public String id;
        public String clientNonce;
        public String serverNonce;
        public Continuation continuation;
        public long continueNotBefore;
        public String grantEndpoint;
        public long createdAt;
        public Object context;
        public String instanceId;
        public String expectedSub;
    }

    public static final class Grant {
        public String accessToken;
        public boolean bearer;
        public Object access;
        public Long expiresIn;
        public Long expiresAt;
        public Continuation manage;
        public Continuation continuation;
        public String instanceId;
        public Subject.Person subject;
        public String grantId;
    }

    public static final class GrantResult {
        public final String redirectUrl;
        public final Pending pending;
        public final Grant grant;

        public GrantResult(String redirectUrl, Pending pending, Grant grant) {
            this.redirectUrl = redirectUrl;
            this.pending = pending;
            this.grant = grant;
        }
    }

    public static final class Finished {
        public final Grant grant;

        public Finished(Grant grant) { this.grant = grant; }
    }
}
