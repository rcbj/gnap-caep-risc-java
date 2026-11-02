// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** The one client key. A JWK kid is its RFC 7638 thumbprint. ECDSA signatures are raw R||S. */
public final class Keys {
    public static final List<String> PROOFS = List.of("mtls", "httpsig", "jwsd");
    private static final Pattern CERT = Pattern.compile("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----");

    private Keys() {}

    public static final class ClientKey {
        public final String proof;
        public final PrivateKey privateKey;
        public final PublicKey publicKey;
        public final String thumbprint;
        public final String alg;
        public final String kid;
        public final Map<String, Object> jwk;
        public final String certificatePem;
        public final String tlsChainPem;

        ClientKey(String proof, PrivateKey privateKey, PublicKey publicKey, String thumbprint, String alg, String kid,
                  Map<String, Object> jwk, String certificatePem, String tlsChainPem) {
            this.proof = proof;
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.thumbprint = thumbprint;
            this.alg = alg;
            this.kid = kid;
            this.jwk = jwk;
            this.certificatePem = certificatePem;
            this.tlsChainPem = tlsChainPem;
        }

        public String privatePem() {
            String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(privateKey.getEncoded());
            return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n";
        }

        public byte[] sign(byte[] data) {
            try {
                if ("EdDSA".equals(alg) || "Ed25519".equals(alg)) {
                    Signature signature = Signature.getInstance("Ed25519");
                    signature.initSign(privateKey);
                    signature.update(data);
                    return signature.sign();
                }
                if (alg.startsWith("ES")) {
                    Signature signature = Signature.getInstance(hashName(alg) + "withECDSAinP1363Format");
                    signature.initSign(privateKey);
                    signature.update(data);
                    return signature.sign();
                }
                if (alg.startsWith("PS")) {
                    Signature signature = Signature.getInstance("RSASSA-PSS");
                    int salt = switch (alg) {
                        case "PS384" -> 48;
                        case "PS512" -> 64;
                        default -> 32;
                    };
                    String hash = switch (alg) {
                        case "PS384" -> "SHA-384";
                        case "PS512" -> "SHA-512";
                        default -> "SHA-256";
                    };
                    MGF1ParameterSpec mgf = new MGF1ParameterSpec(hash);
                    signature.setParameter(new PSSParameterSpec(hash, "MGF1", mgf, salt, 1));
                    signature.initSign(privateKey);
                    signature.update(data);
                    return signature.sign();
                }
                Signature signature = Signature.getInstance(hashName(alg) + "withRSA");
                signature.initSign(privateKey);
                signature.update(data);
                return signature.sign();
            } catch (GnapError err) {
                throw err;
            } catch (Exception err) {
                Caught.error(err);
                throw new GnapError("config", "this library does not sign with " + alg, err);
            }
        }
    }

    public static boolean verify(PublicKey key, String alg, byte[] data, byte[] signature) {
        try {
            if ("EdDSA".equals(alg) || "Ed25519".equals(alg)) {
                Signature verifier = Signature.getInstance("Ed25519");
                verifier.initVerify(key);
                verifier.update(data);
                return verifier.verify(signature);
            }
            if (alg.startsWith("ES")) {
                Signature verifier = Signature.getInstance(hashName(alg) + "withECDSAinP1363Format");
                verifier.initVerify(key);
                verifier.update(data);
                return verifier.verify(signature);
            }
            if (alg.startsWith("PS")) {
                Signature verifier = Signature.getInstance("RSASSA-PSS");
                int salt = switch (alg) {
                    case "PS384" -> 48;
                    case "PS512" -> 64;
                    default -> 32;
                };
                String hash = switch (alg) {
                    case "PS384" -> "SHA-384";
                    case "PS512" -> "SHA-512";
                    default -> "SHA-256";
                };
                verifier.setParameter(new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(hash), salt, 1));
                verifier.initVerify(key);
                verifier.update(data);
                return verifier.verify(signature);
            }
            if (!alg.startsWith("RS")) return false;
            Signature verifier = Signature.getInstance(hashName(alg) + "withRSA");
            verifier.initVerify(key);
            verifier.update(data);
            return verifier.verify(signature);
        } catch (Exception err) {
            Caught.warn(err);
            return false;
        }
    }

    public static Map<String, Object> publicKeyObject(ClientKey key) {
        if ("mtls".equals(key.proof)) {
            if (key.certificatePem == null) throw new GnapError("config", "mutual TLS needs the client certificate");
            return Json.obj("proof", "mtls", "cert", key.certificatePem.trim());
        }
        if (key.jwk == null) throw new GnapError("config", key.proof + " needs a JWK");
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", key.jwk.get("kty"));
        for (String name : List.of("crv", "x", "y", "n", "e")) {
            if (key.jwk.get(name) != null) jwk.put(name, key.jwk.get(name));
        }
        jwk.put("alg", key.alg);
        jwk.put("kid", key.kid);
        return Json.obj("proof", key.proof, "jwk", jwk);
    }

    public static PublicKey publicKeyFromJwk(Map<String, Object> jwk) {
        try {
            String kty = Json.text(jwk.get("kty"));
            if ("RSA".equals(kty)) {
                return RSAKey.parse(Json.dumps(minimal(jwk))).toRSAPublicKey();
            }
            if ("EC".equals(kty)) {
                return ECKey.parse(Json.dumps(minimal(jwk))).toECPublicKey();
            }
            if ("OKP".equals(kty)) {
                return OctetKeyPair.parse(Json.dumps(minimal(jwk))).toPublicKey();
            }
        } catch (GnapError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            throw new GnapError("signature", "the key " + (jwk.get("kid") == null ? "" : jwk.get("kid")) + " cannot be read: " + err.getMessage(), err);
        }
        throw new GnapError("signature", "the key " + (jwk.get("kid") == null ? "" : jwk.get("kid")) + " cannot be read: unsupported " + jwk.get("kty"));
    }

    public static ClientKey load(String privateKeyPem, String certificatePem, String proof) {
        PrivateKey privateKey;
        PublicKey publicKey;
        try {
            Parsed parsed = readPrivate(privateKeyPem);
            privateKey = parsed.privateKey;
            publicKey = parsed.publicKey;
        } catch (GnapError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            throw new GnapError("config", "the private key could not be read: " + err.getMessage(), err);
        }
        Map<String, Object> jwk = publicJwk(publicKey);
        X509Certificate certificate = null;
        if (certificatePem != null && !certificatePem.isBlank()) {
            try {
                certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(certificatePem.getBytes(StandardCharsets.UTF_8)));
            } catch (Exception err) {
                Caught.error(err);
                throw new GnapError("config", "the certificate could not be read: " + err.getMessage(), err);
            }
            if (!sameKey(privateKey, publicKey, certificate.getPublicKey())) {
                throw new GnapError("config", "the certificate is not the public half of the private key");
            }
        }
        String chosen = proof == null || proof.isBlank() ? (certificate != null ? "mtls" : "httpsig") : proof;
        if ("mtls".equals(chosen) && certificate == null) throw new GnapError("config", "keyProof \"mtls\" needs certificate");
        if ("mtls".equals(chosen)) {
            List<String> blocks = certificateBlocks(certificatePem);
            String leaf = (blocks.isEmpty() ? certificatePem : blocks.get(0)).trim() + "\n";
            String chain = (blocks.isEmpty() ? certificatePem.trim() : String.join("\n", blocks.stream().map(String::trim).toList())) + "\n";
            try {
                String thumb = Json.b64url(Json.sha256(certificate.getEncoded()));
                return new ClientKey("mtls", privateKey, publicKey, thumb, Json.text(jwk.get("alg")), Json.text(jwk.get("kid")), jwk, leaf, chain);
            } catch (Exception err) {
                Caught.error(err);
                throw new GnapError("config", "the certificate could not be read: " + err.getMessage(), err);
            }
        }
        return new ClientKey(chosen, privateKey, publicKey, Json.text(jwk.get("kid")), Json.text(jwk.get("alg")), Json.text(jwk.get("kid")), jwk, certificatePem, null);
    }

    public static String fingerprint256(X509Certificate certificate) {
        try {
            byte[] digest = Json.sha256(certificate.getEncoded());
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < digest.length; i++) {
                if (i > 0) out.append(':');
                out.append(String.format("%02X", digest[i]));
            }
            return out.toString();
        } catch (Exception err) {
            Caught.error(err);
            throw new GnapError("config", "the certificate could not be read: " + err.getMessage(), err);
        }
    }

    public static List<String> certificateBlocks(String pem) {
        List<String> blocks = new ArrayList<>();
        Matcher matcher = CERT.matcher(pem == null ? "" : pem);
        while (matcher.find()) blocks.add(matcher.group());
        return blocks;
    }

    public static Map<String, Object> publicJwk(PublicKey publicKey) {
        try {
            Map<String, Object> jwk = new LinkedHashMap<>();
            if (publicKey instanceof ECPublicKey ec) {
                int size = (ec.getParams().getCurve().getField().getFieldSize() + 7) / 8;
                String curve = curveName(ec);
                jwk.put("kty", "EC");
                jwk.put("crv", curve);
                jwk.put("x", Json.b64url(fixed(ec.getW().getAffineX(), size)));
                jwk.put("y", Json.b64url(fixed(ec.getW().getAffineY(), size)));
                jwk.put("alg", algOf(jwk));
                jwk.put("kid", thumbprint(jwk));
                return jwk;
            }
            if (publicKey instanceof RSAPublicKey rsa) {
                jwk.put("kty", "RSA");
                jwk.put("n", Json.b64url(unsigned(rsa.getModulus())));
                jwk.put("e", Json.b64url(unsigned(rsa.getPublicExponent())));
                jwk.put("alg", "RS256");
                jwk.put("kid", thumbprint(jwk));
                return jwk;
            }
            if (publicKey instanceof EdECPublicKey ed) {
                byte[] encoded = ed.getEncoded();
                byte[] raw = new byte[32];
                System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
                jwk.put("kty", "OKP");
                jwk.put("crv", "Ed25519");
                jwk.put("x", Json.b64url(raw));
                jwk.put("alg", "EdDSA");
                jwk.put("kid", thumbprint(jwk));
                return jwk;
            }
        } catch (GnapError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            throw new GnapError("config", "a key of this type is not a GNAP client key this library loads", err);
        }
        throw new GnapError("config", "a key of this type is not a GNAP client key this library loads");
    }

    public static String thumbprint(Map<String, Object> jwk) {
        try {
            JWK parsed = switch (String.valueOf(jwk.get("kty"))) {
                case "EC" -> new ECKey.Builder(Curve.parse(String.valueOf(jwk.get("crv"))), new Base64URL(String.valueOf(jwk.get("x"))), new Base64URL(String.valueOf(jwk.get("y")))).build();
                case "RSA" -> new RSAKey.Builder(new Base64URL(String.valueOf(jwk.get("n"))), new Base64URL(String.valueOf(jwk.get("e")))).build();
                case "OKP" -> new OctetKeyPair.Builder(Curve.parse(String.valueOf(jwk.get("crv"))), new Base64URL(String.valueOf(jwk.get("x")))).build();
                default -> throw new GnapError("config", "a " + jwk.get("kty") + " key is not a GNAP client key this library loads");
            };
            return parsed.computeThumbprint().toString();
        } catch (GnapError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            throw new GnapError("config", "a " + jwk.get("kty") + " key is not a GNAP client key this library loads", err);
        }
    }

    public static String algOf(Map<String, Object> jwk) {
        Object alg = jwk.get("alg");
        if (alg instanceof String text && !text.isBlank() && !"none".equals(text)) return text;
        String kty = String.valueOf(jwk.get("kty"));
        if ("EC".equals(kty)) {
            return switch (String.valueOf(jwk.get("crv"))) {
                case "P-256" -> "ES256";
                case "P-384" -> "ES384";
                case "P-521" -> "ES512";
                default -> throw new GnapError("config", "the curve " + jwk.get("crv") + " has no signature algorithm");
            };
        }
        if ("RSA".equals(kty)) return "RS256";
        if ("OKP".equals(kty)) return "EdDSA";
        throw new GnapError("config", "a " + kty + " key is not a GNAP client key this library loads");
    }

    private static Map<String, Object> minimal(Map<String, Object> jwk) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (String name : List.of("kty", "crv", "x", "y", "n", "e", "alg", "kid", "use")) {
            if (jwk.get(name) != null) out.put(name, jwk.get(name));
        }
        return out;
    }

    private static String hashName(String alg) {
        if (alg.endsWith("384")) return "SHA384";
        if (alg.endsWith("512")) return "SHA512";
        return "SHA256";
    }

    private static String curveName(ECPublicKey key) {
        int field = key.getParams().getCurve().getField().getFieldSize();
        if (field == 256) return "P-256";
        if (field == 384) return "P-384";
        if (field == 521) return "P-521";
        throw new GnapError("config", "the curve " + field + " has no signature algorithm");
    }

    private static byte[] fixed(java.math.BigInteger value, int size) {
        byte[] raw = unsigned(value);
        if (raw.length == size) return raw;
        byte[] out = new byte[size];
        System.arraycopy(raw, 0, out, size - raw.length, raw.length);
        return out;
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

    private static boolean sameKey(PrivateKey privateKey, PublicKey derived, PublicKey certificate) {
        byte[] nonce = "gnap-key-check".getBytes(StandardCharsets.UTF_8);
        try {
            String algorithm = derived instanceof RSAPublicKey ? "SHA256withRSA" : derived instanceof EdECPublicKey ? "Ed25519" : "SHA256withECDSA";
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey);
            signature.update(nonce);
            byte[] signed = signature.sign();
            signature.initVerify(certificate);
            signature.update(nonce);
            return signature.verify(signed);
        } catch (Exception err) {
            Caught.warn(err);
            return false;
        }
    }

    private record Parsed(PrivateKey privateKey, PublicKey publicKey) {}

    private static Parsed readPrivate(String pem) throws Exception {
        String body = pem.replaceAll("-----BEGIN [^-]+-----", "").replaceAll("-----END [^-]+-----", "").replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(body);
        PrivateKeyInfo info = PrivateKeyInfo.getInstance(der);
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PrivateKey privateKey = converter.getPrivateKey(info);
        AsymmetricKeyParameter parameter = PrivateKeyFactory.createKey(info);
        PublicKey publicKey;
        if (parameter instanceof ECPrivateKeyParameters ec) {
            var point = ec.getParameters().getG().multiply(ec.getD()).normalize();
            var pub = new org.bouncycastle.crypto.params.ECPublicKeyParameters(point, ec.getParameters());
            publicKey = converter.getPublicKey(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pub));
        } else if (parameter instanceof RSAPrivateCrtKeyParameters rsa) {
            var pub = new org.bouncycastle.crypto.params.RSAKeyParameters(false, rsa.getModulus(), rsa.getPublicExponent());
            publicKey = converter.getPublicKey(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pub));
        } else if (parameter instanceof Ed25519PrivateKeyParameters ed) {
            var pub = ed.generatePublicKey();
            publicKey = converter.getPublicKey(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pub));
        } else {
            publicKey = KeyFactory.getInstance(privateKey.getAlgorithm()).generatePublic(new X509EncodedKeySpec(privateKey.getEncoded()));
        }
        if (privateKey == null) {
            privateKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
        }
        return new Parsed(privateKey, publicKey);
    }
}
