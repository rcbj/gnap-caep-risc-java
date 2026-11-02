// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/** A self-signed P-256 certificate. Only key usage is digitalSignature. */
public final class X509Gen {
    private X509Gen() {}

    public static final class KeyPairPem {
        public final String privateKeyPem;
        public final String certificatePem;
        public final X509Certificate certificate;
        public final String fingerprint256;

        KeyPairPem(String privateKeyPem, String certificatePem, X509Certificate certificate) {
            this.privateKeyPem = privateKeyPem;
            this.certificatePem = certificatePem;
            this.certificate = certificate;
            this.fingerprint256 = Keys.fingerprint256(certificate);
        }
    }

    public static KeyPairPem createSelfSigned(String commonName) {
        return createSelfSigned(commonName, 1095, List.of(), List.of());
    }

    public static KeyPairPem createSelfSigned(String commonName, int days, List<String> dns, List<String> ip) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair pair = generator.generateKeyPair();
            X500Name name = new X500Name("CN=" + commonName.replace(",", "\\,"));
            Date notBefore = new Date(System.currentTimeMillis() - 60_000L);
            Date notAfter = new Date(notBefore.getTime() + days * 86_400_000L);
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                    name, new BigInteger(64, new SecureRandom()), notBefore, notAfter, name,
                    org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()));
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            List<GeneralName> alt = new ArrayList<>();
            for (String host : dns) alt.add(new GeneralName(GeneralName.dNSName, host));
            for (String address : ip) alt.add(new GeneralName(GeneralName.iPAddress, address));
            if (!alt.isEmpty()) builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(alt.toArray(GeneralName[]::new)));
            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(
                    builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(pair.getPrivate())));
            return new KeyPairPem(pem("PRIVATE KEY", pair.getPrivate().getEncoded()), pem("CERTIFICATE", certificate.getEncoded()), certificate);
        } catch (Exception err) {
            Caught.error(err);
            throw new GnapError("config", "the certificate could not be read: " + err.getMessage(), err);
        }
    }

    private static String pem(String kind, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return "-----BEGIN " + kind + "-----\n" + body + "\n-----END " + kind + "-----\n";
    }
}
