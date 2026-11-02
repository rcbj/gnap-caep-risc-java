// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap.ssf;

import com.iyasec.gnap.Subject;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/** Which local sessions belong to which person and which provider session. */
public final class SessionIndex {
    private SessionIndex() {}

    public static final class Tracked {
        public final String localId;
        public final String person;
        public final String email;
        public final String idpSession;
        public final Long expiresAt;

        public Tracked(String localId, String person, String email, String idpSession, Long expiresAt) {
            this.localId = localId;
            this.person = person;
            this.email = email;
            this.idpSession = idpSession;
            this.expiresAt = expiresAt;
        }
    }

    public static Tracked fromPerson(String localId, Subject.Person person, Long expiresAt) {
        return new Tracked(localId, person == null ? null : person.sub, person == null ? null : person.email, person == null ? null : person.sid, expiresAt);
    }

    public static final class Memory {
        private final Map<String, Tracked> sessions = new LinkedHashMap<>();
        private final int max;

        public Memory() { this(100_000); }
        public Memory(int max) { this.max = max; }

        public void add(Tracked session) {
            if (sessions.size() >= max && !sessions.containsKey(session.localId)) {
                long now = System.currentTimeMillis();
                sessions.entrySet().removeIf(entry -> entry.getValue().expiresAt != null && entry.getValue().expiresAt <= now);
                while (sessions.size() >= max) {
                    String oldest = sessions.keySet().stream().findFirst().orElse(null);
                    if (oldest == null) break;
                    sessions.remove(oldest);
                }
            }
            sessions.put(session.localId, new Tracked(
                    session.localId, session.person,
                    session.email == null ? null : session.email.toLowerCase(),
                    session.idpSession, session.expiresAt));
        }

        public void remove(String localId) { sessions.remove(localId); }

        public List<String> byPerson(String person) { return find(session -> person.equals(session.person)); }
        public List<String> byEmail(String email) {
            String wanted = email.toLowerCase();
            return find(session -> wanted.equals(session.email));
        }
        public List<String> byIdpSession(String idpSession) { return find(session -> idpSession.equals(session.idpSession)); }

        private List<String> find(Predicate<Tracked> match) {
            long now = System.currentTimeMillis();
            List<String> out = new ArrayList<>();
            for (Map.Entry<String, Tracked> entry : new ArrayList<>(sessions.entrySet())) {
                if (entry.getValue().expiresAt != null && entry.getValue().expiresAt <= now) {
                    sessions.remove(entry.getKey());
                    continue;
                }
                if (match.test(entry.getValue())) out.add(entry.getKey());
            }
            return out;
        }
    }
}
