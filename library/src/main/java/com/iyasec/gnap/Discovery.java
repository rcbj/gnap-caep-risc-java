// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Grant-server discovery is an OPTIONS on the grant endpoint. OpenID and SSF use RFC 8615 well-known URLs. */
public final class Discovery {
    private Discovery() {}

    public static List<String> wellKnown(String issuer, String suffix) {
        String href = Urls.href(issuer);
        String origin = Urls.origin(issuer);
        String path = "";
        int scheme = href.indexOf("://");
        int start = href.indexOf('/', scheme + 3);
        if (start >= 0) {
            String rest = href.substring(start);
            int query = rest.indexOf('?');
            path = (query >= 0 ? rest.substring(0, query) : rest).replaceAll("/+$", "");
        }
        String inserted = origin + "/.well-known/" + suffix + path;
        String appended = origin + path + "/.well-known/" + suffix;
        return inserted.equals(appended) ? List.of(inserted) : List.of(inserted, appended);
    }

    public static Map<String, Object> validateGrantServer(Map<String, Object> raw, String grantEndpoint) {
        if (raw == null) throw new GnapError("discovery", "grant-server metadata must be a JSON object");
        String endpoint = Json.text(raw.get("grant_request_endpoint"));
        if (endpoint == null || endpoint.isBlank()) throw new GnapError("discovery", "grant-server metadata has no grant_request_endpoint");
        String advertised = Urls.href(endpoint).replaceAll("/+$", "");
        String asked = Urls.href(grantEndpoint).replaceAll("/+$", "");
        if (!advertised.equals(asked)) {
            throw new GnapError("discovery", "the grant server says its endpoint is " + endpoint + ", not " + grantEndpoint);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("grant_request_endpoint", endpoint);
        out.put("interaction_start_modes_supported", strings(raw.get("interaction_start_modes_supported")));
        out.put("interaction_finish_methods_supported", strings(raw.get("interaction_finish_methods_supported")));
        out.put("key_proofs_supported", strings(raw.get("key_proofs_supported")));
        out.put("sub_id_formats_supported", strings(raw.get("sub_id_formats_supported")));
        out.put("assertion_formats_supported", strings(raw.get("assertion_formats_supported")));
        return out;
    }

    public static Map<String, Object> discoverGrantServer(String grantEndpoint, Map<String, Object> tls) {
        Http.Answer answer = Http.send(grantEndpoint, "OPTIONS", Map.of("accept", "application/json"), null, tls, "discovery");
        Object parsed;
        try {
            parsed = Json.parse(answer.body);
        } catch (Exception err) {
            Caught.error(err);
            throw new GnapError("discovery", grantEndpoint + " did not answer JSON grant-server metadata (" + answer.status + ")", err);
        }
        if (answer.status != 200) throw new GnapError("discovery", grantEndpoint + " answered " + answer.status + " for discovery");
        return validateGrantServer(Json.map(parsed), grantEndpoint);
    }

    public static Map<String, Object> discoverOpenId(String issuer, Map<String, Object> tls) {
        List<String> urls = wellKnown(issuer, "openid-configuration");
        GnapError last = new GnapError("discovery", "no OpenID Provider metadata at " + String.join(" or ", urls));
        for (String url : urls) {
            Http.Answer answer = Http.send(url, "GET", Map.of("accept", "application/json"), null, tls, "discovery");
            if (answer.status == 404 && !url.equals(urls.get(urls.size() - 1))) continue;
            Map<String, Object> doc = null;
            try {
                doc = Json.map(Json.parse(answer.body));
            } catch (Exception ignored) {
                Caught.error(ignored);
                doc = null;
            }
            if (answer.status != 200 || doc == null || !(doc.get("jwks_uri") instanceof String)) {
                last = new GnapError("discovery", url + " answered " + answer.status + " without OpenID Provider metadata");
                continue;
            }
            String got = Json.text(doc.get("issuer"));
            if (got != null && !got.replaceAll("/+$", "").equals(issuer.replaceAll("/+$", ""))) {
                throw new GnapError("discovery", url + " says its issuer is " + got + ", not " + issuer);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("issuer", got == null ? issuer : got);
            out.put("jwks_uri", doc.get("jwks_uri"));
            return out;
        }
        throw last;
    }

    private static List<String> strings(Object value) {
        if (value == null) return null;
        List<Object> list = Json.list(value);
        if (list == null) throw new GnapError("discovery", "a grant-server metadata list is not an array of strings");
        List<String> out = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof String text)) throw new GnapError("discovery", "a grant-server metadata list is not an array of strings");
            out.add(text);
        }
        return out;
    }
}
