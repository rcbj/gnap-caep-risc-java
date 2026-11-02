// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import com.iyasec.gnap.demo.TrustChain;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * tlsCa: the install script writes the whole listener CA trust chain to the
 * file the parameter names, and the library takes that file as its trust
 * store.
 *
 * keytool makes a four-certificate chain shaped like iya-sts's (leaf, TLS
 * Issuing CA, Intermediate, Root). The stub provider is HTTPS on that chain
 * and publishes it, leaf first, at GET /tls/server-certificate. A second stub
 * presents a different leaf from the same TLS Issuing CA (iya-sts reissuing
 * its listener certificate), which only a trust store holding every block of
 * the file, not just the first, can trust. A third presents a leaf of its own
 * key, named for the TLS Issuing CA but not signed by it, followed by the real
 * CA certificates: those are public, so their presence in a chain proves
 * nothing, and the library must refuse it.
 */
class TrustChainTest {
    static final String DEFAULT_TLS_CA = "generated/idp-ca.pem";
    static final Path ROOT = Path.of(System.getProperty("user.dir"));
    static final Path SHIPPED_CONFIG = ROOT.resolve("demo/gnap.json");

    static Path work;
    static String published;
    static X509Certificate root;
    static HttpsServer provider;
    static HttpsServer reissued;
    static HttpsServer impostor;
    static String origin;

    @BeforeAll
    static void up() throws Exception {
        work = Files.createTempDirectory("trust-chain-");
        Path store = work.resolve("ca.p12");
        String[] names = {"root", "intermediate", "issuing", "leaf", "leaf2", "impostor", "forged"};
        String[] subjects = {"CN=sts Root CA", "CN=sts Intermediate CA", "CN=sts TLS Issuing CA", "CN=127.0.0.1", "CN=127.0.0.1",
                "CN=sts TLS Issuing CA", "CN=127.0.0.1"};
        for (int i = 0; i < names.length; i++) {
            List<String> args = new ArrayList<>(List.of("-genkeypair", "-alias", names[i], "-keyalg", "EC", "-groupname", "secp256r1",
                    "-dname", subjects[i], "-validity", "2"));
            if (i < 3 || i == 5) args.addAll(List.of("-ext", "bc:c=ca:true"));
            keytool(store, args.toArray(String[]::new));
        }
        String rootPem = pem(keytool(store, "-exportcert", "-rfc", "-alias", "root"));
        String intermediatePem = sign(store, "intermediate", "root", "bc:c=ca:true", "ku:c=keyCertSign,cRLSign");
        String issuingPem = sign(store, "issuing", "intermediate", "bc:c=ca:true", "ku:c=keyCertSign,cRLSign");
        String leafPem = sign(store, "leaf", "issuing", "san=ip:127.0.0.1", "eku=serverAuth");
        String leaf2Pem = sign(store, "leaf2", "issuing", "san=ip:127.0.0.1", "eku=serverAuth");
        String forgedPem = sign(store, "forged", "impostor", "san=ip:127.0.0.1", "eku=serverAuth");
        published = leafPem + issuingPem + intermediatePem + rootPem;
        root = certificates(rootPem).get(0);
        provider = serve(store, "leaf", leafPem + issuingPem + intermediatePem);
        origin = "https://127.0.0.1:" + provider.getAddress().getPort();
        reissued = serve(store, "leaf2", leaf2Pem + issuingPem + intermediatePem);
        impostor = serve(store, "forged", forgedPem + issuingPem + intermediatePem);
    }

    @AfterAll
    static void down() {
        for (HttpsServer server : new HttpsServer[]{provider, reissued, impostor}) {
            if (server != null) server.stop(0);
        }
    }

    @Test
    void theShippedDemoNamesGeneratedIdpCaPem() throws Exception {
        assertEquals(DEFAULT_TLS_CA, Json.map(Json.parse(Files.readString(SHIPPED_CONFIG))).get("tlsCa"));
    }

    @Test
    void theInstallScriptWritesTheWholeChainToTlsCa() throws Exception {
        Path demo = demoDir("install");
        String code = String.join("\n",
                "import json, sys",
                "sys.path.insert(0, 'scripts')",
                "import configure_iya_sts, trust_chain",
                "files = configure_iya_sts.files_of(sys.argv[1], 'http://127.0.0.1:3000')",
                "saved = trust_chain.save_trust_chain(sys.argv[2], files['tlsCa'])",
                "print(json.dumps({'tlsCa': files['tlsCa'], 'count': saved['count'],",
                "    'anchor': saved['anchor_subject'], 'fingerprint': saved['anchor_fingerprint']}))");
        Map<String, Object> saved = Json.map(Json.parse(python("-c", code, demo.resolve("gnap.json").toString(), origin)));
        Path target = demo.resolve(DEFAULT_TLS_CA);
        assertEquals(target.toString(), saved.get("tlsCa"));
        assertEquals(published, Files.readString(target));
        assertEquals(4, ((Number) saved.get("count")).intValue());
        assertEquals("CN=sts Root CA", saved.get("anchor"));
        assertEquals(fingerprint(root), saved.get("fingerprint"));
    }

    @Test
    void thePythonRefreshWritesTlsCaAndNamesTheAnchor() throws Exception {
        Path demo = demoDir("refresh");
        String printed = python("scripts/trust_chain.py", "--config", demo.resolve("gnap.json").toString());
        Path target = demo.resolve(DEFAULT_TLS_CA);
        assertEquals(published, Files.readString(target));
        assertTrue(printed.contains(target.toRealPath().toString()), printed);
        assertTrue(printed.contains("(4 certificate(s))"), printed);
        assertTrue(printed.contains("CN=sts Root CA"), printed);
        assertTrue(printed.contains("sha256 " + fingerprint(root)), printed);
    }

    @Test
    void theEntrypointRefreshWritesTheWholeChainToTlsCa() throws Exception {
        Path demo = demoDir("entrypoint");
        TrustChain.main(new String[]{"--config", demo.resolve("gnap.json").toString()});
        assertEquals(certificates(published), certificates(Files.readString(demo.resolve(DEFAULT_TLS_CA))));
    }

    @Test
    void theEntrypointRefreshVerifiesAReissuedLeafAgainstTheFileItHas() throws Exception {
        Path demo = demoDir("verified", port(reissued));
        Files.createDirectories(demo.resolve("generated"));
        Files.writeString(demo.resolve(DEFAULT_TLS_CA), published);
        assertEquals("verified", TrustChain.refresh(demo.resolve("gnap.json")));
        assertEquals(certificates(published), certificates(Files.readString(demo.resolve(DEFAULT_TLS_CA))));
    }

    @Test
    void theEntrypointRefreshTakesANewChainOnFirstUseOnlyWhenTheFileCannotVerifyIt() throws Exception {
        Path demo = demoDir("first-use");
        assertEquals("first use", TrustChain.refresh(demo.resolve("gnap.json")));
        // A file from another CA (a development iya-sts that restarted) cannot verify the chain.
        X509Gen.KeyPairPem other = X509Gen.createSelfSigned("old sts Root CA");
        Files.writeString(demo.resolve(DEFAULT_TLS_CA), other.certificatePem);
        assertEquals("first use", TrustChain.refresh(demo.resolve("gnap.json")));
        assertEquals(certificates(published), certificates(Files.readString(demo.resolve(DEFAULT_TLS_CA))));
    }

    @Test
    void theEntrypointRefreshRefusesAForgedLeafEvenOnFirstUseAndKeepsTheFile() throws Exception {
        Path demo = demoDir("forged", port(impostor));
        Files.createDirectories(demo.resolve("generated"));
        X509Gen.KeyPairPem other = X509Gen.createSelfSigned("old sts Root CA");
        Files.writeString(demo.resolve(DEFAULT_TLS_CA), other.certificatePem);
        assertThrows(Exception.class, () -> TrustChain.refresh(demo.resolve("gnap.json")));
        assertEquals(other.certificatePem, Files.readString(demo.resolve(DEFAULT_TLS_CA)));
        TrustChain.main(new String[]{"--config", demo.resolve("gnap.json").toString()});
        assertEquals(other.certificatePem, Files.readString(demo.resolve(DEFAULT_TLS_CA)));
    }

    @Test
    void theEntrypointRefreshRefusesTheRightChainUnderTheWrongName() throws Exception {
        // The leaf names IP 127.0.0.1 only.
        Path demo = demoDir("wrong-name", "https://localhost:" + provider.getAddress().getPort());
        assertThrows(Exception.class, () -> TrustChain.refresh(demo.resolve("gnap.json")));
        assertTrue(!Files.exists(demo.resolve(DEFAULT_TLS_CA)));
    }

    @Test
    void theEntrypointCountsCertificatesWithoutARegex() {
        assertEquals(4, TrustChain.count(published));
        assertEquals(0, TrustChain.count("-----BEGIN CERTIFICATE\n".repeat(10_000)));
        assertEquals(10_000, TrustChain.count("-----BEGIN CERTIFICATE-----".repeat(10_000)));
    }

    @Test
    void theLibraryTrustsTheProviderThroughTheSavedFile() throws Exception {
        Path demo = demoDir("library");
        String url = origin + "/gnap";
        Files.createDirectories(demo.resolve("generated"));
        X509Gen.KeyPairPem client = X509Gen.createSelfSigned("gnap-caep-risc-demo");
        Files.writeString(demo.resolve("generated/client.key"), client.privateKeyPem);
        Files.writeString(demo.resolve("generated/client.crt"), client.certificatePem);
        // No tlsCa file yet: the JDK's trust store does not know this CA.
        assertThrows(GnapError.class, () -> Http.send(url, "GET", null, null, configured(demo).tls(), "discovery"));
        Files.writeString(demo.resolve(DEFAULT_TLS_CA), published);
        GnapClient gnap = configured(demo);
        assertEquals(published, gnap.config().tlsCa);
        Map<String, Object> tls = gnap.tls();
        Http.Answer answered = Http.send(url, "GET", null, null, tls, "discovery");
        assertEquals(200, answered.status);
        assertEquals(origin, Json.map(Json.parse(answered.body)).get("issuer"));
        // A listener certificate the file does not hold, from the same TLS
        // Issuing CA: trusted through the CA certificates after the first block.
        Http.Answer again = Http.send(port(reissued) + "/gnap", "GET", null, null, tls, "discovery");
        assertEquals(200, again.status);
    }

    @Test
    void aLeafTheIssuingCaDidNotSignIsRefusedEvenWithTheRealCaCertificatesAfterIt() throws Exception {
        Map<String, Object> tls = Map.of("ca", published);
        GnapError refused = assertThrows(GnapError.class,
                () -> Http.send(port(impostor) + "/gnap", "GET", null, null, tls, "discovery"));
        assertTrue(causes(refused).toLowerCase().contains("certification path")
                || causes(refused).toLowerCase().contains("signature"), causes(refused));
    }

    @Test
    void theRightChainUnderTheWrongNameIsRefused() throws Exception {
        Map<String, Object> tls = Map.of("ca", published);
        // The leaf names IP 127.0.0.1 only.
        assertEquals(200, Http.send(origin + "/gnap", "GET", null, null, tls, "discovery").status);
        String wrong = "https://localhost:" + provider.getAddress().getPort() + "/gnap";
        GnapError refused = assertThrows(GnapError.class, () -> Http.send(wrong, "GET", null, null, tls, "discovery"));
        assertTrue(causes(refused).contains("No name matching localhost")
                || causes(refused).toLowerCase().contains("subject alternative"), causes(refused));
    }

    static GnapClient configured(Path demo) throws Exception {
        return GnapClient.create(GnapClient.resolve(Json.parse(Files.readString(demo.resolve("gnap.json"))), demo));
    }

    static String port(HttpsServer server) {
        return "https://127.0.0.1:" + server.getAddress().getPort();
    }

    static String causes(Throwable err) {
        StringBuilder out = new StringBuilder();
        for (Throwable at = err; at != null; at = at.getCause()) out.append(at).append(" | ");
        return out.toString();
    }

    static Path demoDir(String name) throws Exception {
        return demoDir(name, origin);
    }

    static Path demoDir(String name, String at) throws Exception {
        Path demo = work.resolve(name).resolve("demo");
        Files.createDirectories(demo);
        Map<String, Object> raw = Json.map(Json.parse(Files.readString(SHIPPED_CONFIG)));
        raw.put("grantEndpoint", at + "/gnap");
        Files.writeString(demo.resolve("gnap.json"), Json.dumps(raw));
        return demo;
    }

    static String sign(Path store, String alias, String issuer, String... extensions) throws Exception {
        Path request = work.resolve(alias + ".csr");
        keytool(store, "-certreq", "-alias", alias, "-file", request.toString());
        List<String> args = new ArrayList<>(List.of("-gencert", "-rfc", "-alias", issuer, "-infile", request.toString(), "-validity", "2"));
        for (String extension : extensions) {
            args.add("-ext");
            args.add(extension);
        }
        return pem(keytool(store, args.toArray(String[]::new)));
    }

    /** One certificate as PEM in the form the install script writes it. */
    static String pem(String text) throws Exception {
        byte[] der = certificates(text).get(0).getEncoded();
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
                + "\n-----END CERTIFICATE-----\n";
    }

    static String keytool(Path store, String... args) throws Exception {
        List<String> command = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "keytool").toString()));
        command.addAll(List.of(args));
        command.addAll(List.of("-keystore", store.toString(), "-storetype", "PKCS12", "-storepass", "changeit", "-noprompt"));
        return run(command);
    }

    static String python(String... args) throws Exception {
        List<String> command = new ArrayList<>(List.of("python3"));
        command.addAll(List.of(args));
        return run(command);
    }

    static String run(List<String> command) throws Exception {
        Path errors = Files.createTempFile(work, "stderr-", ".txt");
        Process process = new ProcessBuilder(command).directory(ROOT.toFile())
                .redirectError(errors.toFile()).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), command.get(0) + " did not finish");
        assertEquals(0, process.exitValue(), String.join(" ", command) + "\n" + output + Files.readString(errors));
        return output;
    }

    static List<X509Certificate> certificates(String pem) throws Exception {
        List<X509Certificate> out = new ArrayList<>();
        for (Certificate certificate : CertificateFactory.getInstance("X.509")
                .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)))) {
            out.add((X509Certificate) certificate);
        }
        return out;
    }

    static String fingerprint(X509Certificate certificate) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        return HexFormat.ofDelimiter(":").withUpperCase().formatHex(digest);
    }

    static HttpsServer serve(Path store, String alias, String chainPem) throws Exception {
        KeyStore source = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(store.toFile())) {
            source.load(in, "changeit".toCharArray());
        }
        PrivateKey key = (PrivateKey) source.getKey(alias, "changeit".toCharArray());
        KeyStore served = KeyStore.getInstance("PKCS12");
        served.load(null, null);
        served.setKeyEntry("server", key, new char[0], certificates(chainPem).toArray(Certificate[]::new));
        KeyManagerFactory managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        managers.init(served, new char[0]);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(managers.getKeyManagers(), null, null);
        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(context));
        server.createContext("/", TrustChainTest::handle);
        server.start();
        return server;
    }

    static void handle(HttpExchange exchange) {
        try (exchange) {
            String path = exchange.getRequestURI().getPath();
            byte[] body;
            String type;
            if ("/tls/server-certificate".equals(path)) {
                body = published.getBytes(StandardCharsets.US_ASCII);
                type = "text/plain";
            } else if ("/gnap".equals(path)) {
                String self = "https://127.0.0.1:" + exchange.getLocalAddress().getPort();
                body = Json.dumps(Map.of("issuer", self)).getBytes(StandardCharsets.UTF_8);
                type = "application/json";
            } else {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
            exchange.getResponseHeaders().set("content-type", type);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
        } catch (Exception err) {
            Caught.warn(err);
        }
    }
}
