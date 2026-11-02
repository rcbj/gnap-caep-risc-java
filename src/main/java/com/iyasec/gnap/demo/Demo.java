// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap.demo;

import com.iyasec.gnap.GnapClient;
import com.iyasec.gnap.GnapError;
import com.iyasec.gnap.Json;
import com.iyasec.gnap.Subject;
import com.iyasec.gnap.ssf.SessionIndex;
import com.iyasec.gnap.ssf.SignalsReceiver;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A small GNAP sign-in demo. PORT is the bind port. Loopback finish URLs follow it.
 * PUBLIC_URL or --public-url replaces the origin and keeps the path.
 */
public final class Demo {
    private static final Path HERE = Path.of("demo");
    private static final byte[] SECRET = secret();
    private static GnapClient gnap;
    private static String gnapError;
    private static SignalsReceiver receiver;
    private static GnapClient.Grant latest;
    private static final Map<String, Session> SESSIONS = new ConcurrentHashMap<>();

    private Demo() {}

    public static void main(String[] args) throws Exception {
        String publicUrl = System.getenv("PUBLIC_URL");
        boolean given = publicUrl != null && !publicUrl.isBlank();
        for (int i = 0; i < args.length; i++) {
            if ("--public-url".equals(args[i]) && i + 1 < args.length) {
                publicUrl = args[++i];
                given = true;
            }
        }
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "3000"));
        String configPath = System.getenv().getOrDefault("GNAP_CONFIG", HERE.resolve("gnap.json").toString());
        boolean explicit = given;
        String published = publicUrl == null ? "" : publicUrl.replaceAll("/+$", "");
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", exchange -> {
            try {
                handle(exchange, port, published, explicit, Path.of(configPath));
            } catch (Exception err) {
                byte[] body = page("Error", "<h1>Something went wrong</h1><p>" + esc(err.getMessage()) + "</p>").getBytes(StandardCharsets.UTF_8);
                write(exchange, 500, body, "text/html; charset=utf-8", null);
            }
        });
        server.start();
        System.out.println("gnap-caep-risc demo on port " + port + ", configuration " + configPath);
    }

    private static void handle(HttpExchange exchange, int port, String publicUrl, boolean given, Path config) throws Exception {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();
        if ("/healthz".equals(path) && "GET".equals(method)) {
            write(exchange, 200, "ok".getBytes(StandardCharsets.UTF_8), "text/plain", null);
            return;
        }
        if ("/styles.css".equals(path)) {
            sendFile(exchange, HERE.resolve("public/styles.css"), "text/css; charset=utf-8");
            return;
        }
        if ("/app.js".equals(path)) {
            sendFile(exchange, HERE.resolve("public/app.js"), "text/javascript; charset=utf-8");
            return;
        }
        if ("/".equals(path) && "GET".equals(method)) {
            home(exchange, config, port, publicUrl, given);
            return;
        }
        if ("/login".equals(path) && "GET".equals(method)) {
            login(exchange, config, port, publicUrl, given);
            return;
        }
        if ("/callback".equals(path) && "GET".equals(method)) {
            callback(exchange, config, port, publicUrl, given);
            return;
        }
        if ("/logout".equals(path) && "POST".equals(method)) {
            logout(exchange);
            return;
        }
        if ("/gnap/push".equals(path) && "POST".equals(method)) {
            push(exchange, config, port, publicUrl, given);
            return;
        }
        write(exchange, 404, page("Not found", "<h1>Not found</h1>").getBytes(StandardCharsets.UTF_8), "text/html; charset=utf-8", null);
    }

    private static void home(HttpExchange exchange, Path config, int port, String publicUrl, boolean given) throws Exception {
        GnapClient client = tryClient(config, port, publicUrl, given);
        Session session = session(exchange);
        if (session != null && session.person != null) {
            String who = session.person.email != null ? session.person.email : session.person.name != null ? session.person.name : session.person.sub;
            write(exchange, 200, page("Signed in", "<h1>Signed in</h1><p>" + esc(who) + "</p><form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form>").getBytes(StandardCharsets.UTF_8), "text/html; charset=utf-8", null);
            return;
        }
        String problem = client == null ? "<p>The GNAP client is not configured yet: " + esc(gnapError == null ? "the key could not be read" : gnapError) + ". Generate the key at the privateKey path, then run scripts/configure_iya_sts.py.</p>" : "";
        String link = client == null ? "" : "<p><a class=\"button\" href=\"/login\">Sign in with GNAP</a></p>";
        write(exchange, 200, page("GNAP demo", "<h1>GNAP CAEP RISC demo</h1>" + problem + link).getBytes(StandardCharsets.UTF_8), "text/html; charset=utf-8", null);
    }

    private static void login(HttpExchange exchange, Path config, int port, String publicUrl, boolean given) throws Exception {
        try {
            GnapClient.GrantResult started = client(config, port, publicUrl, given).requestGrant();
            if (started.grant != null) {
                place(exchange, started.grant, null);
                return;
            }
            String cookie = "gpending=" + seal(Json.obj("ids", List.of(started.pending.id))) + "; Path=/callback; Max-Age=600; HttpOnly; SameSite=Lax";
            exchange.getResponseHeaders().add("Location", started.redirectUrl);
            exchange.getResponseHeaders().add("Cache-Control", "no-store");
            write(exchange, 302, new byte[0], "text/plain", cookie);
        } catch (Exception err) {
            write(exchange, 400, page("Sign-in failed", "<h1>Sign-in failed</h1><p>" + esc(err.getMessage()) + "</p><p><a href=\"/\">Start again</a></p>").getBytes(StandardCharsets.UTF_8), "text/html; charset=utf-8", null);
        }
    }

    private static void callback(HttpExchange exchange, Path config, int port, String publicUrl, boolean given) throws Exception {
        Map<String, Object> pending = Json.map(unseal(cookie(exchange, "gpending")));
        List<String> ids = new ArrayList<>();
        if (pending != null && pending.get("ids") instanceof List<?> list) for (Object item : list) ids.add(String.valueOf(item));
        String clear = "gpending=; Path=/callback; Max-Age=0; HttpOnly; SameSite=Lax";
        try {
            Map<String, String> query = query(exchange.getRequestURI().getRawQuery());
            GnapClient.Finished done = client(config, port, publicUrl, given).finishRedirect(query, ids);
            if (done.grant.subject == null) throw new GnapError("validation", "the grant has no subject");
            place(exchange, done.grant, clear);
            watch(done.grant, config);
        } catch (Exception err) {
            write(exchange, 400, page("Sign-in failed", "<h1>Sign-in failed</h1><p>" + esc(err.getMessage()) + "</p>").getBytes(StandardCharsets.UTF_8), "text/html; charset=utf-8", clear);
        }
    }

    private static void logout(HttpExchange exchange) throws Exception {
        Map<String, Object> opened = Json.map(unseal(cookie(exchange, "gsid")));
        if (opened != null) {
            Session session = SESSIONS.remove(String.valueOf(opened.get("id")));
            if (session != null && session.grant != null) {
                try { if (receiver != null && session.grant.grantId != null) receiver.untrack(session.grant.grantId); } catch (Exception ignored) {}
                try { if (gnap != null) gnap.revoke(session.grant); } catch (Exception ignored) {}
            }
        }
        exchange.getResponseHeaders().add("Location", "/");
        write(exchange, 303, new byte[0], "text/plain", "gsid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
    }

    private static void push(HttpExchange exchange, Path config, int port, String publicUrl, boolean given) throws Exception {
        try {
            String text = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            GnapClient.Finished done = client(config, port, publicUrl, given).finishPush(text.isBlank() ? null : Json.parse(text));
            if (done.grant.subject != null) watch(done.grant, config);
            write(exchange, 204, new byte[0], "text/plain", null);
        } catch (Exception err) {
            write(exchange, 400, Json.dumps(Json.obj("error", err.getMessage())).getBytes(StandardCharsets.UTF_8), "application/json", null);
        }
    }

    private static void place(HttpExchange exchange, GnapClient.Grant grant, String extra) throws Exception {
        String id = Json.b64url(random(9));
        SESSIONS.put(id, new Session(grant.subject, grant));
        exchange.getResponseHeaders().add("Location", "/");
        exchange.getResponseHeaders().add("Set-Cookie", "gsid=" + seal(Json.obj("id", id)) + "; Path=/; HttpOnly; SameSite=Lax");
        if (extra != null) exchange.getResponseHeaders().add("Set-Cookie", extra);
        write(exchange, 303, new byte[0], "text/plain", null);
    }

    private static void watch(GnapClient.Grant grant, Path config) {
        latest = grant;
        if (receiver != null) return;
        Map<String, Object> raw;
        try { raw = Json.map(Json.parse(Files.readString(config))); } catch (Exception err) { return; }
        if (raw == null || Boolean.FALSE.equals(raw.get("signals"))) return;
        Map<String, Object> ssf = Json.map(raw.get("ssf"));
        if (ssf == null || !(ssf.get("transmitter") instanceof String transmitter)) return;
        long interval = ssf.get("pollIntervalMs") instanceof Number number ? number.longValue() : 5000L;
        receiver = new SignalsReceiver(transmitter, (ids, event) -> { for (String id : ids) SESSIONS.remove(id); }, gnap.tls(), request -> {
            if (latest == null) return Map.of();
            return gnap.authorizationHeaders(latest, String.valueOf(request.get("method")), String.valueOf(request.get("url")), request.get("body") instanceof String body ? body : null);
        }, interval);
        try {
            receiver.start();
            if (grant.subject != null) receiver.track(SessionIndex.fromPerson(grant.grantId == null ? grant.subject.sub : grant.grantId, grant.subject, grant.expiresAt));
        } catch (Exception err) {
            System.out.println("ssf: not started: " + err.getMessage());
            receiver = null;
        }
    }

    private static GnapClient client(Path config, int port, String publicUrl, boolean given) throws Exception {
        if (gnap == null) {
            try {
                gnap = GnapClient.create(GnapClient.resolve(readRaw(config, port, publicUrl, given), config.getParent()));
                gnapError = null;
            } catch (Exception err) {
                gnapError = err instanceof GnapError g ? g.code + ": " + g.getMessage() : err.getMessage();
                throw err;
            }
        }
        return gnap;
    }

    private static GnapClient tryClient(Path config, int port, String publicUrl, boolean given) {
        try { return client(config, port, publicUrl, given); } catch (Exception err) { return null; }
    }

    private static Map<String, Object> readRaw(Path config, int port, String publicUrl, boolean given) throws IOException {
        Map<String, Object> raw = Json.map(Json.parse(Files.readString(config)));
        if (raw == null) throw new GnapError("config", "configuration must be a JSON object");
        Map<String, Object> display = Json.map(raw.get("display"));
        Redirects.Moved moved = Redirects.redirectsFor(
                raw.get("finishUri") instanceof String finish ? finish : "",
                display != null && display.get("uri") instanceof String uri ? uri : "",
                publicUrl.isBlank() ? "http://localhost:3000" : publicUrl,
                given,
                port);
        if (moved.finishUri() != null && !moved.finishUri().isBlank()) raw.put("finishUri", moved.finishUri());
        if (display != null && moved.displayUri() != null && !moved.displayUri().isBlank()) {
            display.put("uri", moved.displayUri());
            raw.put("display", display);
        }
        return raw;
    }

    private static void sendFile(HttpExchange exchange, Path path, String type) throws IOException {
        if (!Files.isRegularFile(path)) {
            write(exchange, 404, page("Not found", "<h1>Not found</h1>").getBytes(StandardCharsets.UTF_8), "text/html; charset=utf-8", null);
            return;
        }
        write(exchange, 200, Files.readAllBytes(path), type, null);
    }

    private static void write(HttpExchange exchange, int status, byte[] body, String type, String cookie) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", type);
        if (cookie != null && exchange.getResponseHeaders().getFirst("Set-Cookie") == null) exchange.getResponseHeaders().add("Set-Cookie", cookie);
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) { out.write(body); }
        exchange.close();
    }

    private static String page(String title, String body) {
        return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>" + esc(title) + "</title><link rel=\"stylesheet\" href=\"/styles.css\"></head><body><main>" + body + "</main></body></html>";
    }

    private static String esc(String value) {
        return String.valueOf(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static Session session(HttpExchange exchange) {
        Map<String, Object> opened = Json.map(unseal(cookie(exchange, "gsid")));
        if (opened == null) return null;
        return SESSIONS.get(String.valueOf(opened.get("id")));
    }

    private static String cookie(HttpExchange exchange, String name) {
        List<String> headers = exchange.getRequestHeaders().get("Cookie");
        if (headers == null) return "";
        for (String header : headers) {
            for (String part : header.split(";")) {
                String item = part.trim();
                if (item.startsWith(name + "=")) return item.substring(name.length() + 1);
            }
        }
        return "";
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> out = new LinkedHashMap<>();
        if (raw == null || raw.isBlank()) return out;
        for (String part : raw.split("&")) {
            int eq = part.indexOf('=');
            String key = URLDecoder.decode(eq < 0 ? part : part.substring(0, eq), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(eq < 0 ? "" : part.substring(eq + 1), StandardCharsets.UTF_8);
            out.put(key, value);
        }
        return out;
    }

    private static String seal(Object payload) throws Exception {
        String raw = Json.b64url(Json.dumps(payload).getBytes(StandardCharsets.UTF_8));
        return raw + "." + mac(raw);
    }

    private static Object unseal(String token) {
        if (token == null || !token.contains(".")) return null;
        int dot = token.lastIndexOf('.');
        String raw = token.substring(0, dot);
        String got = token.substring(dot + 1);
        try {
            if (!MessageDigest.isEqual(mac(raw).getBytes(StandardCharsets.UTF_8), got.getBytes(StandardCharsets.UTF_8))) return null;
            return Json.parse(new String(Base64.getUrlDecoder().decode(pad(raw)), StandardCharsets.UTF_8));
        } catch (Exception err) {
            return null;
        }
    }

    private static String mac(String raw) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(SECRET, "HmacSHA256"));
        byte[] digest = mac.doFinal(raw.getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        for (byte b : digest) out.append(String.format("%02x", b));
        return out.toString();
    }

    private static String pad(String value) {
        return value + "=".repeat((4 - value.length() % 4) % 4);
    }

    private static byte[] secret() {
        String env = System.getenv("SESSION_SECRET");
        if (env != null && !env.isBlank()) return env.getBytes(StandardCharsets.UTF_8);
        return random(32);
    }

    private static byte[] random(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private record Session(Subject.Person person, GnapClient.Grant grant) {}
}
