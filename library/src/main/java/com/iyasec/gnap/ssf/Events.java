// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap.ssf;

import com.iyasec.gnap.Json;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** CAEP, RISC, and SSF event types, and what an event's subject names. */
public final class Events {
    public static final String CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
    public static final String RISC = "https://schemas.openid.net/secevent/risc/event-type/";
    public static final String SSF = "https://schemas.openid.net/secevent/ssf/event-type/";
    public static final String SESSION_REVOKED = CAEP + "session-revoked";
    public static final String TOKEN_CLAIMS_CHANGE = CAEP + "token-claims-change";
    public static final String CREDENTIAL_CHANGE = CAEP + "credential-change";
    public static final String ASSURANCE_LEVEL_CHANGE = CAEP + "assurance-level-change";
    public static final String DEVICE_COMPLIANCE_CHANGE = CAEP + "device-compliance-change";
    public static final String SESSION_ESTABLISHED = CAEP + "session-established";
    public static final String SESSION_PRESENTED = CAEP + "session-presented";
    public static final String RISK_LEVEL_CHANGE = CAEP + "risk-level-change";
    public static final String ACCOUNT_CREDENTIAL_CHANGE_REQUIRED = RISC + "account-credential-change-required";
    public static final String ACCOUNT_PURGED = RISC + "account-purged";
    public static final String ACCOUNT_DISABLED = RISC + "account-disabled";
    public static final String ACCOUNT_ENABLED = RISC + "account-enabled";
    public static final String IDENTIFIER_CHANGED = RISC + "identifier-changed";
    public static final String IDENTIFIER_RECYCLED = RISC + "identifier-recycled";
    public static final String CREDENTIAL_COMPROMISE = RISC + "credential-compromise";
    public static final String OPT_IN = RISC + "opt-in";
    public static final String OPT_OUT_INITIATED = RISC + "opt-out-initiated";
    public static final String OPT_OUT_CANCELLED = RISC + "opt-out-cancelled";
    public static final String OPT_OUT_EFFECTIVE = RISC + "opt-out-effective";
    public static final String RECOVERY_ACTIVATED = RISC + "recovery-activated";
    public static final String RECOVERY_INFORMATION_CHANGED = RISC + "recovery-information-changed";
    public static final String SESSIONS_REVOKED = RISC + "sessions-revoked";
    public static final String VERIFICATION = SSF + "verification";
    public static final String STREAM_UPDATED = SSF + "stream-updated";
    public static final List<String> DEFAULT_EVENTS_REQUESTED = List.of(
            SESSION_REVOKED, CREDENTIAL_CHANGE, ASSURANCE_LEVEL_CHANGE, TOKEN_CLAIMS_CHANGE,
            ACCOUNT_DISABLED, ACCOUNT_ENABLED, ACCOUNT_PURGED, CREDENTIAL_COMPROMISE,
            SESSIONS_REVOKED, ACCOUNT_CREDENTIAL_CHANGE_REQUIRED);
    public static final List<String> DEFAULT_ENDING = List.of(
            SESSION_REVOKED, ACCOUNT_DISABLED, ACCOUNT_PURGED, CREDENTIAL_COMPROMISE, SESSIONS_REVOKED);

    private Events() {}

    public static Map<String, String> subjectOf(Object subId, String issuer) {
        Map<String, Object> doc = Json.map(subId);
        if (doc == null) return Map.of();
        String format = String.valueOf(doc.get("format") != null ? doc.get("format") : doc.getOrDefault("subject_type", ""));
        if ("null".equals(format)) format = "";
        if ("complex".equals(format) || (format.isEmpty() && (doc.get("user") != null || doc.get("session") != null))) {
            Map<String, String> user = simple(doc.get("user"), issuer);
            Map<String, String> session = simple(doc.get("session"), issuer);
            Map<String, String> out = new LinkedHashMap<>();
            if (user.get("sub") != null) out.put("person", user.get("sub"));
            if (user.get("email") != null) out.put("email", user.get("email"));
            String sessionId = session.get("opaque") != null ? session.get("opaque") : session.get("sub");
            if (sessionId != null) out.put("idp_session", sessionId);
            return out;
        }
        Map<String, String> one = simple(doc, issuer);
        Map<String, String> out = new LinkedHashMap<>();
        if (one.get("sub") != null) out.put("person", one.get("sub"));
        if (one.get("email") != null) out.put("email", one.get("email"));
        return out;
    }

    private static Map<String, String> simple(Object identifier, String issuer) {
        Map<String, Object> doc = Json.map(identifier);
        if (doc == null) return Map.of();
        String format = String.valueOf(doc.get("format") != null ? doc.get("format") : doc.getOrDefault("subject_type", ""));
        if ("iss_sub".equals(format) && doc.get("sub") instanceof String sub && (doc.get("iss") == null || issuer.equals(doc.get("iss")))) {
            return Map.of("sub", sub);
        }
        if ("email".equals(format) && doc.get("email") instanceof String email) return Map.of("email", email);
        if ("opaque".equals(format) && doc.get("id") instanceof String id) return Map.of("opaque", id);
        if ("aliases".equals(format) && doc.get("identifiers") instanceof List<?> list) {
            Map<String, String> merged = new LinkedHashMap<>();
            for (Object item : list) merged.putAll(simple(item, issuer));
            return merged;
        }
        return Map.of();
    }
}
