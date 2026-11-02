// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Configuration. JSON keys match the Node library so the same gnap.json loads. */
public final class Config {
    private static final Set<String> SSF = Set.of("ssf.read", "ssf.manage");

    private Config() {}

    public static final class Resolved {
        public String grantEndpoint;
        public String idTokenIssuer;
        public String application;
        public String classId;
        public Map<String, Object> display;
        public List<Object> access;
        /** True only when the document set signals to false. Omitted when signals stay on. */
        public boolean signalsOff;
        public List<String> subIdFormats;
        public List<String> assertionFormats;
        public Keys.ClientKey key;
        public String finishUri;
        public String finishMethod;
        public List<String> interactionStart;
        public String hashMethod = "sha-256";
        public boolean requireBoundTokens = true;
        public boolean useInstanceId = true;
        public String tlsCa;
        public boolean allowInsecure;
        public long clockToleranceSec = 30;
        public long maxWaitSec = 30;
        public long transactionTtlSec = 600;
        /** Present only when signals stay on and a transmitter was named. */
        public Map<String, Object> ssf;
    }

    public static Resolved readFile(String path) {
        Path file = Path.of(path);
        try {
            Object raw = Json.parse(Files.readString(file));
            return resolve(raw, file.toAbsolutePath().getParent());
        } catch (GnapError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            throw new GnapError("config", "could not read " + path + ": " + err.getMessage(), err);
        }
    }

    public static Resolved resolve(Object raw, Path baseDir) {
        Map<String, Object> doc = Json.map(raw);
        if (doc == null) throw new GnapError("config", "configuration must be a JSON object");
        if (doc.containsKey("signals") && !(doc.get("signals") instanceof Boolean)) {
            throw new GnapError("config", "signals must be true or false");
        }
        boolean signalsOff = Boolean.FALSE.equals(doc.get("signals"));
        String application = doc.get("application") instanceof String app ? app.trim() : "";
        if (application.isEmpty()) throw new GnapError("config", "application is required: the registered GNAP client");
        String grantRaw = doc.get("grantEndpoint") instanceof String grant ? grant.trim() : "";
        if (grantRaw.isEmpty()) throw new GnapError("config", "grantEndpoint is required");
        boolean allowInsecure = Boolean.TRUE.equals(doc.get("allowInsecure"));
        String grantEndpoint = checkUrl(grantRaw, "grantEndpoint", allowInsecure);
        String origin = Urls.origin(grantEndpoint);
        String idToken = String.valueOf(doc.getOrDefault("idTokenIssuer", "")).trim();
        if (idToken.isEmpty() || "null".equals(idToken)) idToken = origin;
        idToken = idToken.replaceAll("/+$", "");
        if (!idToken.startsWith("https://") && !idToken.startsWith("http://")) {
            throw new GnapError("config", "idTokenIssuer must be an http(s) URL");
        }
        String proofRaw = doc.get("keyProof") == null ? "" : String.valueOf(doc.get("keyProof")).trim();
        if (!proofRaw.isEmpty() && !Keys.PROOFS.contains(proofRaw)) {
            throw new GnapError("config", "keyProof must be " + String.join(", ", Keys.PROOFS) + ", not " + proofRaw);
        }
        if (doc.get("privateKey") == null) throw new GnapError("config", "privateKey is required");
        Path base = baseDir == null ? Path.of(".") : baseDir;
        String privateKey = keyValue(String.valueOf(doc.get("privateKey")), base, "the private key");
        String certificate = doc.get("certificate") == null ? null : keyValue(String.valueOf(doc.get("certificate")), base, "the certificate");
        Keys.ClientKey key = Keys.load(privateKey, certificate, proofRaw.isEmpty() ? null : proofRaw);
        if ("mtls".equals(key.proof) && !grantEndpoint.startsWith("https:")) {
            throw new GnapError("config", "mutual TLS needs an https grant endpoint");
        }
        String finishMethod = doc.get("finishMethod") == null ? "redirect" : String.valueOf(doc.get("finishMethod"));
        if (!"redirect".equals(finishMethod) && !"push".equals(finishMethod)) {
            throw new GnapError("config", "finishMethod must be redirect or push");
        }
        String finishRaw = doc.get("finishUri") == null ? "" : String.valueOf(doc.get("finishUri")).trim();
        boolean finishLoopback = false;
        if (!finishRaw.isEmpty()) {
            try {
                finishLoopback = Urls.isLoopback(finishRaw);
            } catch (Exception ignored) {
                Caught.error(ignored);
                finishLoopback = false;
            }
        }
        String finishUri = finishRaw.isEmpty() ? null : checkUrl(finishRaw, "finishUri", allowInsecure || finishLoopback);
        String hashMethod = doc.get("hashMethod") == null ? "sha-256" : String.valueOf(doc.get("hashMethod"));
        if (!"sha-256".equals(hashMethod)) throw new GnapError("config", "hashMethod must be sha-256");
        Object interactionRaw = doc.get("interactionStart");
        List<String> interaction = new ArrayList<>();
        if (interactionRaw == null) interaction.add("redirect");
        else {
            List<Object> modes = Json.list(interactionRaw);
            if (modes == null || modes.isEmpty()) throw new GnapError("config", "interactionStart must name at least one mode");
            for (Object mode : modes) {
                if (!(mode instanceof String text) || text.isBlank()) throw new GnapError("config", "interactionStart must name at least one mode");
                interaction.add(text);
            }
        }
        Object requestedRaw = doc.containsKey("access") ? doc.get("access") : List.of("ssf.read", "ssf.manage");
        List<Object> requested = Json.list(requestedRaw);
        if (requested == null) throw new GnapError("config", "access must list at least one right");
        List<Object> access = new ArrayList<>();
        for (Object right : requested) {
            if (signalsOff && ssfRight(right)) continue;
            access.add(right);
        }
        if (access.isEmpty()) {
            throw new GnapError("config", signalsOff
                    ? "signals is false and access has no rights left after ssf.read and ssf.manage were removed; the caller must name a right this authorization server grants"
                    : "access must list at least one right");
        }
        String tlsCa = readTrust(doc.get("tlsCa"), base);
        Map<String, Object> ssf = null;
        if (!signalsOff) {
            Map<String, Object> rawSsf = Json.map(doc.get("ssf"));
            if (rawSsf == null) rawSsf = Map.of();
            Object transmitter = rawSsf.get("transmitter") != null ? rawSsf.get("transmitter") : doc.get("transmitterIssuer");
            if (transmitter instanceof String text) {
                text = text.replaceAll("/+$", "");
                if (!text.startsWith("https://") && !text.startsWith("http://")) {
                    throw new GnapError("config", "ssf.transmitter must be an http(s) URL");
                }
                ssf = new LinkedHashMap<>();
                ssf.put("transmitter", text);
                if (rawSsf.get("pollIntervalMs") instanceof Number && ((Number) rawSsf.get("pollIntervalMs")).doubleValue() != 0) {
                    ssf.put("pollIntervalMs", rawSsf.get("pollIntervalMs"));
                }
            }
        }
        Map<String, Object> displayIn = Json.map(doc.get("display"));
        Map<String, Object> display = null;
        if (displayIn != null && (displayIn.get("name") != null || displayIn.get("uri") != null)) {
            display = new LinkedHashMap<>();
            if (displayIn.get("name") != null) display.put("name", displayIn.get("name"));
            if (displayIn.get("uri") != null) display.put("uri", displayIn.get("uri"));
        }
        Resolved out = new Resolved();
        out.grantEndpoint = grantEndpoint;
        out.idTokenIssuer = idToken;
        out.application = application;
        if (doc.get("classId") instanceof String classId && !classId.isBlank()) out.classId = classId;
        out.display = display;
        out.access = access;
        out.signalsOff = signalsOff;
        out.subIdFormats = strings(doc.get("subIdFormats"), List.of("iss_sub", "account", "opaque"));
        out.assertionFormats = strings(doc.get("assertionFormats"), List.of("id_token"));
        out.key = key;
        out.finishUri = finishUri;
        out.finishMethod = finishMethod;
        out.interactionStart = interaction;
        out.requireBoundTokens = !Boolean.FALSE.equals(doc.get("requireBoundTokens"));
        out.useInstanceId = !Boolean.FALSE.equals(doc.get("useInstanceId"));
        out.tlsCa = tlsCa;
        out.allowInsecure = allowInsecure;
        if (doc.get("clockToleranceSec") instanceof Number number) out.clockToleranceSec = number.longValue();
        if (doc.get("maxWaitSec") instanceof Number number) out.maxWaitSec = number.longValue();
        if (doc.get("transactionTtlSec") instanceof Number number) out.transactionTtlSec = number.longValue();
        out.ssf = ssf;
        return out;
    }

    private static List<String> strings(Object value, List<String> fallback) {
        if (value == null) return new ArrayList<>(fallback);
        List<Object> list = Json.list(value);
        List<String> out = new ArrayList<>();
        if (list == null) return out;
        for (Object item : list) if (item instanceof String text) out.add(text);
        return out;
    }

    private static boolean ssfRight(Object right) {
        if (right instanceof String text) return SSF.contains(text.trim());
        Map<String, Object> map = Json.map(right);
        return map != null && SSF.contains(map.get("type"));
    }

    private static String checkUrl(String value, String name, boolean allowHttp) {
        String href;
        try {
            href = Urls.href(value);
        } catch (Exception err) {
            Caught.error(err);
            throw new GnapError("config", name + " is not a URL: " + value, err);
        }
        if (href.startsWith("https:")) return href;
        if (href.startsWith("http:") && allowHttp) return href;
        String extra = allowHttp ? "" : ", or http on loopback";
        throw new GnapError("config", name + " must use https" + extra + ": " + value);
    }

    private static String keyValue(String raw, Path base, String what) {
        String value = raw == null ? "" : raw.trim();
        if (value.startsWith("env:")) {
            String found = System.getenv(value.substring(4));
            if (found == null || found.isBlank()) throw new GnapError("config", value + " is not set");
            return found;
        }
        if (value.contains("-----BEGIN")) return value;
        return readPath(value.startsWith("file:") ? value.substring(5) : value, base, what);
    }

    private static String readPath(String path, Path base, String what) {
        Path full = Path.of(path).isAbsolute() ? Path.of(path) : base.resolve(path);
        try {
            return Files.readString(full);
        } catch (Exception err) {
            Caught.error(err);
            throw new GnapError("config", "could not read " + what + " at " + full + ": " + err.getMessage(), err);
        }
    }

    static String readTrust(Object raw, Path base) {
        if (!(raw instanceof String text) || text.isBlank()) return null;
        if (text.contains("-----BEGIN")) return text;
        if (text.startsWith("env:")) {
            String found = System.getenv(text.substring(4));
            return found == null || found.isBlank() ? null : found;
        }
        String path = text.startsWith("file:") ? text.substring(5) : text;
        Path full = Path.of(path).isAbsolute() ? Path.of(path) : base.resolve(path);
        try {
            return Files.readString(full);
        } catch (Exception err) {
            Caught.warn(err);
            return null;
        }
    }
}
