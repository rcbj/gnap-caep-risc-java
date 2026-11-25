// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iyasec.pep.Decision;
import com.iyasec.pep.Mode;
import com.iyasec.pep.Pep;
import com.iyasec.pep.PepConfig;
import com.iyasec.pep.PepException;
import com.iyasec.pep.key.SigningKey;

import java.net.URI;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Wires {@code com.iyasec:iya-pep} into this GNAP client. The PEP knows no
 * GNAP: this class fills the {@code pep} section's defaults, refuses a key
 * this library already holds, and turns a grant's person into the PEP's subject.
 */
public final class EmbeddedPep {
    private static final ObjectMapper JSON = new ObjectMapper();

    private EmbeddedPep() {}

    /**
     * The iya-sts base a GNAP grant endpoint belongs to, realm prefix kept.
     * {@code https://sts/realm/acme/gnap} and a named server's
     * {@code https://sts/realm/acme/as/gnap} both give {@code https://sts/realm/acme}.
     * {@code https://sts/gnap} gives {@code https://sts}. An unparseable URL
     * gives {@code ""}. {@code idTokenIssuer} is not used: it is the origin
     * and drops the realm.
     */
    public static String defaultPdpUrl(String grantEndpoint) {
        URI url;
        try {
            url = URI.create(grantEndpoint);
            if (url.getScheme() == null || url.getHost() == null) return "";
        } catch (Exception err) {
            Caught.warn(err);
            return "";
        }
        String origin;
        try {
            origin = Urls.origin(grantEndpoint);
        } catch (Exception err) {
            Caught.warn(err);
            return "";
        }
        String path = url.getPath() == null ? "" : url.getPath();
        String[] parts = path.split("/");
        String realm = null;
        String id = null;
        for (String part : parts) {
            if (part.isEmpty()) continue;
            if (realm == null) {
                realm = part;
                continue;
            }
            id = part;
            break;
        }
        if ("realm".equals(realm) && id != null && !id.isEmpty()) return origin + "/realm/" + id;
        return origin;
    }

    /**
     * Builds the PEP from the configuration's {@code pep} section. Checks
     * that its key is not the client instance key. Sends nothing;
     * {@link GnapClient#create} starts it.
     */
    static Pep build(Map<String, Object> section, String grantEndpoint, String application, boolean signals,
                      String tlsCa, Path baseDir, Keys.ClientKey clientKey) {
        if (section == null) throw new GnapError("config", "pep must be an object");
        Map<String, Object> map = new LinkedHashMap<>(section);
        if (!map.containsKey("signals")) map.put("signals", signals);
        if (!map.containsKey("tlsCa") && tlsCa != null && tlsCa.contains("-----BEGIN")) map.put("tlsCa", tlsCa);
        if (map.get("assertionKey") instanceof String key && !key.isEmpty() && !Path.of(key).isAbsolute()) {
            Path base = baseDir == null ? Path.of(".") : baseDir;
            map.put("assertionKey", base.resolve(key).toAbsolutePath().normalize().toString());
        }
        PepConfig config;
        try {
            config = PepConfig.fromJson(JSON.valueToTree(map), defaultPdpUrl(grantEndpoint), application == null ? "" : application);
        } catch (PepException err) {
            throw new GnapError("config", err.detail(), err);
        }
        Pep pep;
        try {
            pep = Pep.create(config);
        } catch (PepException err) {
            throw new GnapError("config", err.detail(), err);
        }
        String clientThumb = null;
        try {
            if (clientKey != null && clientKey.jwk != null) clientThumb = SigningKey.jwkThumbprint(JSON.valueToTree(clientKey.jwk));
        } catch (RuntimeException err) {
            Caught.warn(err);
        }
        String pepThumb = pep.keyThumbprint();
        if (clientThumb != null && !clientThumb.isEmpty() && pepThumb != null && !pepThumb.isEmpty() && clientThumb.equals(pepThumb)) {
            throw new GnapError("config", "pep.assertionKey is the GNAP client instance key (privateKey); the PEP needs a key of its own");
        }
        return pep;
    }

    /** Whether a receiver given this PEP asks for {@code pep-policies-changed}. */
    public static boolean wantsEvents(Pep pep) {
        PepConfig config = pep.config();
        return config.mode == Mode.LOCAL || config.permitCacheMs > 0;
    }

    /**
     * The id iya-sts's PIP resolves: {@code uid} from the {@code account}
     * identifier, else the assertion's {@code username} claim, else
     * {@code preferred_username}, else {@code sub}. Empty values are skipped
     * until {@code sub}, which is kept even when empty.
     */
    static String subjectId(Subject.Person person) {
        if (person.uid != null && !person.uid.isEmpty()) return person.uid;
        Object username = person.claims == null ? null : person.claims.get("username");
        if (username instanceof String text && !text.isEmpty()) return text;
        if (person.preferredUsername != null && !person.preferredUsername.isEmpty()) return person.preferredUsername;
        return person.sub == null ? "" : person.sub;
    }

    /** The PEP's subject for the person a GNAP grant names. No request header is read. */
    static com.iyasec.pep.Subject subjectFor(Subject.Person person) {
        Map<String, JsonNode> properties = new LinkedHashMap<>();
        if (person.claims != null) {
            person.claims.forEach((name, value) -> properties.put(name, JSON.valueToTree(value)));
        }
        return com.iyasec.pep.Subject.user(subjectId(person), properties);
    }

    /** A Deny that did not ask the PDP. */
    static Decision deny(String why) {
        return Decision.deny(why);
    }

    /** No PEP is configured, or a decision could not be asked. */
    static Decision unavailable(String why) {
        return Decision.unavailable(why);
    }

    /** The event body as the JSON {@link Pep#onPolicyEvent} takes. */
    public static JsonNode toJson(Object value) {
        return JSON.valueToTree(value == null ? Map.of() : value);
    }
}
