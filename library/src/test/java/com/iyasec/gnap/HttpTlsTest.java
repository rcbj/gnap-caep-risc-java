// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.SSLContext;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Http's trust decisions, against real TLS listeners: the presented chain must verify (PKIX) to a
 * tlsCa anchor or to the JDK default store, and the host name is checked against the leaf even
 * when the leaf itself is the pinned anchor. Only rejectUnauthorized=false turns either off.
 */
class HttpTlsTest {
    private record Issued(KeyPair keys, X509Certificate certificate, X500Name name) {}

    @Test
    void aPinnedSelfSignedLeafIsTrustedForItsOwnHost() throws Exception {
        Issued leaf = issue("server", null, false, List.of("127.0.0.1"));
        assertEquals("ok", get(leaf, List.of(leaf.certificate), Map.of("ca", pem(leaf.certificate))));
    }

    @Test
    void aPinnedSelfSignedLeafIsStillCheckedForTheHostName() throws Exception {
        Issued leaf = issue("other.example", null, false, List.of());
        GnapError refused = assertThrows(GnapError.class,
                () -> get(leaf, List.of(leaf.certificate), Map.of("ca", pem(leaf.certificate))));
        assertEquals("protocol", refused.code);
    }

    @Test
    void aLeafIssuedByThePinnedCaIsTrusted() throws Exception {
        Issued ca = issue("pinned CA", null, true, List.of());
        Issued leaf = issue("server", ca, false, List.of("127.0.0.1"));
        assertEquals("ok", get(leaf, List.of(leaf.certificate, ca.certificate), Map.of("ca", pem(ca.certificate))));
    }

    @Test
    void thePinnedCaSentAfterALeafItDidNotIssueIsNotTrust() throws Exception {
        Issued ca = issue("pinned CA", null, true, List.of());
        Issued other = issue("other CA", null, true, List.of());
        Issued leaf = issue("server", other, false, List.of("127.0.0.1"));
        assertThrows(GnapError.class,
                () -> get(leaf, List.of(leaf.certificate, ca.certificate), Map.of("ca", pem(ca.certificate))));
    }

    @Test
    void anUnpinnedSelfSignedServerIsRefusedByDefault() throws Exception {
        Issued leaf = issue("server", null, false, List.of("127.0.0.1"));
        Issued unrelated = issue("unrelated", null, false, List.of("127.0.0.1"));
        assertThrows(GnapError.class, () -> get(leaf, List.of(leaf.certificate), Map.of()));
        assertThrows(GnapError.class, () -> get(leaf, List.of(leaf.certificate), null));
        assertThrows(GnapError.class,
                () -> get(leaf, List.of(leaf.certificate), Map.of("ca", pem(unrelated.certificate))));
    }

    @Test
    void onlyAnExplicitRejectUnauthorizedFalseSkipsBothChecks() throws Exception {
        Issued leaf = issue("other.example", null, false, List.of());
        assertEquals("ok", get(leaf, List.of(leaf.certificate), Map.of("rejectUnauthorized", false)));
        assertThrows(GnapError.class, () -> get(leaf, List.of(leaf.certificate), Map.of("rejectUnauthorized", true)));
    }

    private static String get(Issued leaf, List<X509Certificate> chain, Map<String, Object> tls) throws Exception {
        // A key manager of its own, so the listener can present a chain no key store would accept.
        X509Certificate[] presented = chain.toArray(X509Certificate[]::new);
        X509ExtendedKeyManager keys = new X509ExtendedKeyManager() {
            public String[] getClientAliases(String type, Principal[] issuers) { return null; }
            public String chooseClientAlias(String[] type, Principal[] issuers, Socket socket) { return null; }
            public String[] getServerAliases(String type, Principal[] issuers) { return new String[]{"server"}; }
            public String chooseServerAlias(String type, Principal[] issuers, Socket socket) { return "server"; }
            public String chooseEngineServerAlias(String type, Principal[] issuers, SSLEngine engine) { return "server"; }
            public X509Certificate[] getCertificateChain(String alias) { return presented; }
            public PrivateKey getPrivateKey(String alias) { return leaf.keys.getPrivate(); }
        };
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(new KeyManager[]{keys}, null, null);
        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(context));
        server.createContext("/", exchange -> {
            byte[] body = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            String url = "https://127.0.0.1:" + server.getAddress().getPort() + "/";
            return Http.send(url, "GET", Map.of(), null, tls, "protocol").body;
        } finally {
            server.stop(0);
        }
    }

    private static Issued issue(String commonName, Issued issuer, boolean ca, List<String> ips) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys = generator.generateKeyPair();
        X500Name name = new X500Name("CN=" + commonName);
        Date notBefore = new Date(System.currentTimeMillis() - 60_000L);
        Date notAfter = new Date(notBefore.getTime() + 86_400_000L);
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                issuer == null ? name : issuer.name, new BigInteger(64, new SecureRandom()), notBefore, notAfter, name,
                SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded()));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(ca
                ? KeyUsage.keyCertSign | KeyUsage.cRLSign
                : KeyUsage.digitalSignature));
        List<GeneralName> alt = new ArrayList<>();
        if (!ca) alt.add(new GeneralName(GeneralName.dNSName, commonName.contains(".") ? commonName : "server.invalid"));
        for (String ip : ips) alt.add(new GeneralName(GeneralName.iPAddress, ip));
        if (!alt.isEmpty()) {
            builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(alt.toArray(GeneralName[]::new)));
        }
        KeyPair signer = issuer == null ? keys : issuer.keys;
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate())));
        return new Issued(keys, certificate, name);
    }

    private static String pem(X509Certificate certificate) throws Exception {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(certificate.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n";
    }
}
