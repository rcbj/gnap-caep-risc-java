// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap.demo;

import com.iyasec.gnap.Caught;
import com.iyasec.gnap.Json;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Writes the listener CA trust chain named by tlsCa. A failure exits 0 and leaves the file as it is.
 *
 * The fetch is verified against the file already there (the chain from the image build, or from
 * the last start): every certificate in it is a trust anchor, the presented chain must verify to
 * one of them (PKIX), and the host name must match the leaf. That covers a reissued listener
 * certificate under the same CA.
 *
 * A development iya-sts makes a new CA when it restarts, and then the file has nothing that can
 * verify the new chain. Only then is the chain taken on first use: the presented chain must still
 * verify (PKIX) up to the top certificate it presents, and the host name must still match, but
 * nothing outside the connection vouches for that root. The program says so and prints the
 * root's subject and SHA-256 fingerprint to compare with the Root CA on iya-sts's PKI page.
 * A chain that does not hold together, or does not name the host, is refused either way.
 * TLS_CA_REFRESH=0 turns the refresh off.
 */
public final class TrustChain {
    private static final String BEGIN = "-----BEGIN CERTIFICATE-----";

    private TrustChain() {}

    public static void main(String[] args) {
        try {
            String config = System.getenv().getOrDefault("GNAP_CONFIG", "");
            for (int i = 0; i < args.length; i++) {
                if ("--config".equals(args[i])) config = args[++i];
            }
            if (config.isBlank()) throw new IllegalArgumentException("trust-chain needs --config <file> or GNAP_CONFIG");
            refresh(Path.of(config));
        } catch (Exception err) {
            Caught.error(err);
            System.err.println("tls ca: not updated: " + err.getMessage());
        }
    }

    /** Refreshes tlsCa's file and says how the chain was trusted: "verified" or "first use". A failure throws and writes nothing. */
    public static String refresh(Path file) throws Exception {
        Map<String, Object> raw = Json.map(Json.parse(Files.readString(file)));
        String grant = raw == null || !(raw.get("grantEndpoint") instanceof String text) ? "" : text.trim();
        if (grant.isBlank()) throw new IllegalArgumentException(file + " has no grantEndpoint");
        String dest = trustPath(raw.get("tlsCa"), file.getParent());
        if (dest == null) throw new IllegalArgumentException(file + " tlsCa is not a file this process can update");
        URI endpoint = URI.create(grant);
        String origin = endpoint.getScheme() + "://" + endpoint.getRawAuthority();
        Path path = Path.of(dest);
        List<X509Certificate> anchors = Files.isRegularFile(path) ? certificates(Files.readString(path)) : List.of();
        String pem = null;
        if (!anchors.isEmpty()) {
            try {
                pem = fetch(origin, anchoredAt(anchors));
            } catch (Exception err) {
                Caught.warn(err);
                System.err.println("tls ca: the chain from " + origin + " does not verify to " + path + "; taking it on first use");
            }
        }
        X509Certificate firstUse = null;
        if (pem == null) {
            FirstUse trust = new FirstUse();
            pem = fetch(origin, trust);
            firstUse = anchorOf(certificates(pem), trust.top);
        }
        if (path.getParent() != null) Files.createDirectories(path.getParent());
        Files.writeString(path, pem);
        System.out.println("Saved " + origin + "'s listener CA trust chain (" + count(pem) + " certificate(s)) to " + path);
        if (firstUse == null) return "verified";
        System.out.println("tls ca: taken on first use; trust anchor " + firstUse.getSubjectX500Principal().getName()
                + " sha256 " + HexFormat.ofDelimiter(":").withUpperCase().formatHex(MessageDigest.getInstance("SHA-256").digest(firstUse.getEncoded()))
                + ". Compare it with the Root CA on iya-sts's PKI page.");
        return "first use";
    }

    /** The self-signed certificate in the saved chain, else the top certificate the listener presented. */
    private static X509Certificate anchorOf(List<X509Certificate> saved, X509Certificate top) {
        for (int i = saved.size() - 1; i >= 0; i--) {
            X509Certificate cert = saved.get(i);
            if (cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) return cert;
        }
        return top;
    }

    static String trustPath(Object raw, Path base) {
        if (!(raw instanceof String value) || value.isBlank() || value.contains("-----BEGIN") || value.startsWith("env:")) return null;
        String path = value.startsWith("file:") ? value.substring(5) : value;
        if (path.isBlank()) return null;
        Path full = Path.of(path).isAbsolute() ? Path.of(path) : base.resolve(path);
        return full.toString();
    }

    /** The number of PEM certificate blocks, counted without a regular expression. */
    public static int count(String pem) {
        int count = 0;
        for (int at = pem.indexOf(BEGIN); at >= 0; at = pem.indexOf(BEGIN, at + BEGIN.length())) count++;
        return count;
    }

    private static String fetch(String origin, X509TrustManager trust) throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{trust}, null);
        try {
            String pem = published(origin, context);
            // On first use the published chain must hold the certificate the handshake was verified up to.
            if (trust instanceof FirstUse first && !certificates(pem).contains(first.top)) {
                throw new IllegalStateException("the published chain does not hold the certificate the listener presented");
            }
            return pem;
        } catch (Exception err) {
            Caught.error(err);
            return handshake(origin, context);
        }
    }

    /** GET /tls/server-certificate. HttpsURLConnection checks the host name against the leaf itself. */
    private static String published(String origin, SSLContext context) throws Exception {
        URL url = new URL(origin + "/tls/server-certificate");
        var conn = (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(context.getSocketFactory());
        conn.setConnectTimeout(10_000);
        conn.setReadTimeout(10_000);
        if (conn.getResponseCode() != 200) throw new IllegalStateException(url + " answered " + conn.getResponseCode());
        String body = new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!body.contains("BEGIN CERTIFICATE")) throw new IllegalStateException("the trust chain has no certificates");
        return body.endsWith("\n") ? body : body + "\n";
    }

    /** The handshake's own chain, with the host name checked by the TLS stack (endpoint identification). */
    private static String handshake(String origin, SSLContext context) throws Exception {
        URI uri = URI.create(origin);
        try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(uri.getHost(), uri.getPort() < 0 ? 443 : uri.getPort())) {
            SSLParameters params = socket.getSSLParameters();
            params.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(params);
            socket.setSoTimeout(10_000);
            socket.startHandshake();
            List<String> blocks = new ArrayList<>();
            for (Certificate certificate : socket.getSession().getPeerCertificates()) {
                if (certificate instanceof X509Certificate x509) blocks.add(pem(x509.getEncoded()));
            }
            if (blocks.isEmpty()) throw new IllegalStateException("the trust chain has no certificates");
            return String.join("\n", blocks) + "\n";
        }
    }

    static List<X509Certificate> certificates(String pem) throws Exception {
        List<X509Certificate> out = new ArrayList<>();
        if (count(pem) == 0) return out;
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        for (Certificate certificate : factory.generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)))) {
            if (certificate instanceof X509Certificate x509) out.add(x509);
        }
        return out;
    }

    /** Every certificate in the file is a trust anchor; the presented chain must verify to one (PKIX). */
    static X509TrustManager anchoredAt(List<X509Certificate> pins) throws Exception {
        KeyStore anchors = KeyStore.getInstance("PKCS12");
        anchors.load(null, null);
        for (int i = 0; i < pins.size(); i++) anchors.setCertificateEntry("tls-ca-" + i, pins.get(i));
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(anchors);
        for (TrustManager manager : factory.getTrustManagers()) {
            if (manager instanceof X509TrustManager x509) return x509;
        }
        throw new IllegalStateException("no X.509 trust manager");
    }

    /**
     * First use: nothing outside the connection vouches for the chain, so the presented chain must
     * at least hold together. Every certificate in it must verify (PKIX: signatures, validity, CA
     * constraints) up to the top one it presented, which is taken as the anchor. That refuses a
     * leaf the presented CA did not sign; it cannot tell a genuine new root from an impostor's,
     * which is why the anchor is printed to compare.
     */
    static final class FirstUse implements X509TrustManager {
        X509Certificate top;

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String auth) throws CertificateException {
            throw new CertificateException("this trust manager does not accept clients");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
            if (chain == null || chain.length == 0) throw new CertificateException("no certificates presented");
            X509Certificate last = chain[chain.length - 1];
            if (chain.length > 1) {
                try {
                    PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(last, null)));
                    params.setRevocationEnabled(false);
                    List<X509Certificate> path = Arrays.asList(chain).subList(0, chain.length - 1);
                    CertPathValidator.getInstance("PKIX").validate(CertificateFactory.getInstance("X.509").generateCertPath(path), params);
                } catch (Exception err) {
                    throw new CertificateException("the presented chain does not verify to its own top certificate", err);
                }
            } else {
                last.checkValidity();
            }
            top = last;
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    private static String pem(byte[] der) {
        return BEGIN + "\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der) + "\n-----END CERTIFICATE-----";
    }
}
