// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** The back channel. TLS is verified unless the caller turns it off. Answers are capped at 2 MiB. */
public final class Http {
    public static final int MAX_BYTES = 2 * 1024 * 1024;
    public static final int TIMEOUT_MS = 15_000;

    private Http() {}

    public static final class Answer {
        public final int status;
        public final String contentType;
        public final String body;

        public Answer(int status, String contentType, String body) {
            this.status = status;
            this.contentType = contentType == null ? "" : contentType;
            this.body = body == null ? "" : body;
        }
    }

    public static Answer send(String url, String method, Map<String, String> headers, String body, Map<String, Object> tls, String code) {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (Exception err) {
            Caught.error(err);
            throw new GnapError(code, url + " is not an http(s) URL", err);
        }
        if (!"https".equals(uri.getScheme()) && !"http".equals(uri.getScheme())) {
            throw new GnapError(code, url + " is not an http(s) URL");
        }
        byte[] payload = body == null ? null : body.getBytes(StandardCharsets.UTF_8);
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestMethod(method);
            if (conn instanceof HttpsURLConnection https) {
                SSLContext context = context(tls);
                https.setSSLSocketFactory(context.getSocketFactory());
                if (tls != null && Boolean.FALSE.equals(tls.get("rejectUnauthorized"))) {
                    https.setHostnameVerifier((host, session) -> true);
                }
            }
            if (headers != null) {
                for (Map.Entry<String, String> entry : headers.entrySet()) conn.setRequestProperty(entry.getKey(), entry.getValue());
            }
            if (payload != null) {
                conn.setFixedLengthStreamingMode(payload.length);
                conn.setDoOutput(true);
                try (OutputStream out = conn.getOutputStream()) {
                    out.write(payload);
                }
            }
            int status = conn.getResponseCode();
            InputStream stream;
            try {
                stream = conn.getInputStream();
            } catch (Exception err) {
                stream = conn.getErrorStream();
            }
            byte[] raw = readLimited(stream, url, code);
            String type = conn.getContentType() == null ? "" : conn.getContentType();
            conn.disconnect();
            return new Answer(status, type, new String(raw, StandardCharsets.UTF_8));
        } catch (GnapError err) {
            throw err;
        } catch (java.net.SocketTimeoutException err) {
            Caught.error(err);
            throw new GnapError(code, url + " did not answer within 15 s", err);
        } catch (Exception err) {
            Caught.error(err);
            String message = err.getMessage() == null ? err.getClass().getSimpleName() : err.getMessage();
            if (message.toLowerCase().contains("timed out")) throw new GnapError(code, url + " did not answer within 15 s", err);
            throw new GnapError(code, url + ": " + message, err);
        }
    }

    private static byte[] readLimited(InputStream stream, String url, String code) throws Exception {
        if (stream == null) return new byte[0];
        byte[] buffer = new byte[65536];
        int total = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int read;
        while ((read = stream.read(buffer)) >= 0) {
            total += read;
            if (total > MAX_BYTES) throw new GnapError(code, url + " answered more than " + MAX_BYTES + " bytes");
            out.write(buffer, 0, read);
        }
        stream.close();
        return out.toByteArray();
    }

    private static SSLContext context(Map<String, Object> tls) throws Exception {
        Map<String, Object> options = tls == null ? Map.of() : tls;
        boolean insecure = Boolean.FALSE.equals(options.get("rejectUnauthorized"));
        List<X509Certificate> pins = certificates(options.get("ca"));
        TrustManager[] trust;
        if (insecure) {
            trust = new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String auth) {}
                public void checkServerTrusted(X509Certificate[] chain, String auth) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }};
        } else {
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init((KeyStore) null);
            X509TrustManager fallback = null;
            for (TrustManager manager : factory.getTrustManagers()) {
                if (manager instanceof X509TrustManager x509) fallback = x509;
            }
            X509TrustManager system = fallback;
            X509TrustManager pinned = pins.isEmpty() ? null : anchoredAt(pins);
            trust = new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String auth) throws CertificateException {
                    if (system != null) system.checkClientTrusted(chain, auth);
                }
                public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
                    CertificateException refused = null;
                    if (pinned != null) {
                        try {
                            pinned.checkServerTrusted(chain, auth);
                            return;
                        } catch (CertificateException err) {
                            Caught.warn(err);
                            refused = err;
                        }
                    }
                    if (system == null) throw refused != null ? refused : new CertificateException("no trust manager");
                    try {
                        system.checkServerTrusted(chain, auth);
                    } catch (CertificateException err) {
                        if (refused != null) err.addSuppressed(refused);
                        throw err;
                    }
                }
                public X509Certificate[] getAcceptedIssuers() {
                    return system == null ? new X509Certificate[0] : system.getAcceptedIssuers();
                }
            }};
        }
        KeyManager[] keys = null;
        if (options.get("cert") instanceof String cert && options.get("key") instanceof String key) {
            keys = keyManagers(cert, key);
        }
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys, trust, null);
        return context;
    }

    /**
     * Every certificate in tlsCa's file is a trust anchor, and the presented chain must be
     * built and verified to one of them (PKIX). The file is the whole listener CA trust chain
     * (leaf, TLS Issuing CA, Intermediate, Root), so a reissued leaf from the same CA is trusted.
     * A certificate that merely appears in the presented chain proves nothing: CA certificates
     * are public, and anyone can send them after a leaf of their own.
     */
    private static X509TrustManager anchoredAt(List<X509Certificate> pins) throws Exception {
        KeyStore anchors = KeyStore.getInstance("PKCS12");
        anchors.load(null, null);
        for (int i = 0; i < pins.size(); i++) anchors.setCertificateEntry("tls-ca-" + i, pins.get(i));
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(anchors);
        for (TrustManager manager : factory.getTrustManagers()) {
            if (manager instanceof X509TrustManager x509) return x509;
        }
        throw new GnapError("config", "no X.509 trust manager for tlsCa");
    }

    private static List<X509Certificate> certificates(Object pem) {
        List<X509Certificate> out = new ArrayList<>();
        if (!(pem instanceof String text) || !text.contains("-----BEGIN")) return out;
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (Certificate certificate : factory.generateCertificates(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)))) {
                if (certificate instanceof X509Certificate x509) out.add(x509);
            }
        } catch (Exception err) {
            Caught.error(err);
            throw new GnapError("config", "the certificate could not be read: " + err.getMessage(), err);
        }
        return out;
    }

    private static KeyManager[] keyManagers(String certificatePem, String keyPem) throws Exception {
        Keys.ClientKey loaded = Keys.load(keyPem, certificatePem, "mtls");
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<Certificate> chain = new ArrayList<>();
        for (Certificate certificate : factory.generateCertificates(new ByteArrayInputStream(certificatePem.getBytes(StandardCharsets.UTF_8)))) {
            chain.add(certificate);
        }
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        PrivateKey privateKey = loaded.privateKey;
        store.setKeyEntry("client", privateKey, new char[0], chain.toArray(Certificate[]::new));
        KeyManagerFactory managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        managers.init(store, new char[0]);
        KeyManager[] found = managers.getKeyManagers();
        for (int i = 0; i < found.length; i++) {
            if (found[i] instanceof X509ExtendedKeyManager extended) found[i] = new ClientKeyManager(extended);
        }
        return found;
    }

    /** GNAP registers the certificate by value. The server names its own CA, so the default manager would send no certificate. */
    private static final class ClientKeyManager extends X509ExtendedKeyManager {
        private final X509ExtendedKeyManager inner;

        ClientKeyManager(X509ExtendedKeyManager inner) { this.inner = inner; }

        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return inner.chooseClientAlias(keyType, null, socket);
        }

        public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
            return inner.chooseEngineClientAlias(keyType, null, engine);
        }

        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return inner.getClientAliases(keyType, null);
        }

        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return inner.chooseServerAlias(keyType, issuers, socket);
        }

        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            return inner.chooseEngineServerAlias(keyType, issuers, engine);
        }

        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return inner.getServerAliases(keyType, issuers);
        }

        public X509Certificate[] getCertificateChain(String alias) { return inner.getCertificateChain(alias); }

        public PrivateKey getPrivateKey(String alias) { return inner.getPrivateKey(alias); }
    }
}
