// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap.demo;

import com.iyasec.gnap.Json;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Writes the listener CA trust chain named by tlsCa. A failure exits 0 and leaves the file as it is. */
public final class TrustChain {
    private static final Pattern CERT = Pattern.compile("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----");

    private TrustChain() {}

    public static void main(String[] args) {
        try {
            String config = System.getenv().getOrDefault("GNAP_CONFIG", "");
            for (int i = 0; i < args.length; i++) {
                if ("--config".equals(args[i])) config = args[++i];
            }
            if (config.isBlank()) throw new IllegalArgumentException("trust-chain needs --config <file> or GNAP_CONFIG");
            Path file = Path.of(config);
            Map<String, Object> raw = Json.map(Json.parse(Files.readString(file)));
            String grant = raw == null || !(raw.get("grantEndpoint") instanceof String text) ? "" : text.trim();
            if (grant.isBlank()) throw new IllegalArgumentException(file + " has no grantEndpoint");
            String dest = trustPath(raw.get("tlsCa"), file.getParent());
            if (dest == null) throw new IllegalArgumentException(file + " tlsCa is not a file this process can update");
            URI endpoint = URI.create(grant);
            String origin = endpoint.getScheme() + "://" + endpoint.getRawAuthority();
            String pem = fetch(origin);
            Path path = Path.of(dest);
            if (path.getParent() != null) Files.createDirectories(path.getParent());
            Files.writeString(path, pem);
            int count = 0;
            Matcher matcher = CERT.matcher(pem);
            while (matcher.find()) count++;
            System.out.println("Saved " + origin + "'s listener CA trust chain (" + count + " certificate(s)) to " + path);
        } catch (Exception err) {
            System.err.println("tls ca: not updated: " + err.getMessage());
        }
    }

    static String trustPath(Object raw, Path base) {
        if (!(raw instanceof String value) || value.isBlank() || value.contains("-----BEGIN") || value.startsWith("env:")) return null;
        String path = value.startsWith("file:") ? value.substring(5) : value;
        if (path.isBlank()) return null;
        Path full = Path.of(path).isAbsolute() ? Path.of(path) : base.resolve(path);
        return full.toString();
    }

    private static String fetch(String origin) throws Exception {
        try {
            return published(origin);
        } catch (Exception err) {
            return handshake(origin);
        }
    }

    private static String published(String origin) throws Exception {
        URL url = new URL(origin + "/tls/server-certificate");
        var conn = (javax.net.ssl.HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(trustAll().getSocketFactory());
        conn.setHostnameVerifier((host, session) -> true);
        conn.setConnectTimeout(10_000);
        conn.setReadTimeout(10_000);
        if (conn.getResponseCode() != 200) throw new IllegalStateException(url + " answered " + conn.getResponseCode());
        String body = new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!body.contains("BEGIN CERTIFICATE")) throw new IllegalStateException("the trust chain has no certificates");
        return body.endsWith("\n") ? body : body + "\n";
    }

    private static String handshake(String origin) throws Exception {
        URI uri = URI.create(origin);
        SSLSocket socket = (SSLSocket) trustAll().getSocketFactory().createSocket(uri.getHost(), uri.getPort() < 0 ? 443 : uri.getPort());
        socket.setSoTimeout(10_000);
        socket.startHandshake();
        List<String> blocks = new ArrayList<>();
        for (Certificate certificate : socket.getSession().getPeerCertificates()) {
            if (certificate instanceof X509Certificate x509) blocks.add(pem(x509.getEncoded()));
        }
        socket.close();
        if (blocks.isEmpty()) throw new IllegalStateException("the trust chain has no certificates");
        return String.join("\n", blocks) + "\n";
    }

    private static SSLContext trustAll() throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String auth) {}
            public void checkServerTrusted(X509Certificate[] chain, String auth) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, null);
        return context;
    }

    private static String pem(byte[] der) {
        return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der) + "\n-----END CERTIFICATE-----";
    }
}
