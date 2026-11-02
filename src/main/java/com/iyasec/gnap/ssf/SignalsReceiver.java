// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap.ssf;

import com.iyasec.gnap.Discovery;
import com.iyasec.gnap.GnapError;
import com.iyasec.gnap.Http;
import com.iyasec.gnap.Json;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.regex.Pattern;

/** One Shared Signals poll stream (RFC 8936) for CAEP and RISC. */
public final class SignalsReceiver {
    public static final String POLL = "urn:ietf:rfc:8936";
    private static final Pattern RETRY = Pattern.compile("publishes no|signing key|does not verify");

    private final String transmitter;
    private final Map<String, Object> tls;
    private final Function<Map<String, Object>, Map<String, String>> headers;
    private final List<String> eventsRequested;
    private final List<String> endOn;
    private final String description;
    private final long pollIntervalMs;
    private final int maxEvents;
    private final BiConsumer<List<String>, Event> onEnd;
    private final SessionIndex.Memory index;
    private final Map<String, List<Consumer<Event>>> handlers = new LinkedHashMap<>();
    private Map<String, Object> config;
    private Map<String, Object> stream;
    private List<Map<String, Object>> keys = List.of();
    private long keysAt;
    private volatile boolean running;
    private final List<String> ack = new ArrayList<>();
    private final Map<String, Object> errs = new LinkedHashMap<>();
    private final Object gate = new Object();
    private CompletableFuture<Boolean> inflight;
    private ScheduledExecutorService scheduler;
    private ScheduledFuture<?> timer;

    public SignalsReceiver(String transmitter, BiConsumer<List<String>, Event> onEnd, Map<String, Object> tls,
                           Function<Map<String, Object>, Map<String, String>> headers, Long pollIntervalMs) {
        if (onEnd == null) throw new GnapError("config", "onEndSessions is required");
        if (transmitter == null || (!transmitter.startsWith("https://") && !transmitter.startsWith("http://"))) {
            throw new GnapError("config", "transmitter must be an http(s) URL");
        }
        this.transmitter = transmitter.replaceAll("/+$", "");
        this.tls = tls == null ? Map.of() : tls;
        this.headers = headers;
        this.eventsRequested = new ArrayList<>(Events.DEFAULT_EVENTS_REQUESTED);
        this.endOn = new ArrayList<>(Events.DEFAULT_ENDING);
        this.description = null;
        this.pollIntervalMs = pollIntervalMs == null ? 5000 : pollIntervalMs;
        this.maxEvents = 50;
        this.onEnd = onEnd;
        this.index = new SessionIndex.Memory();
    }

    public Map<String, Object> stream() { return stream; }
    public void track(SessionIndex.Tracked session) { index.add(session); }
    public void untrack(String localId) { index.remove(localId); }
    public SignalsReceiver on(String type, Consumer<Event> handler) {
        handlers.computeIfAbsent(type, key -> new ArrayList<>()).add(handler);
        return this;
    }

    public void start() {
        if (running) return;
        config = discover();
        jwks(true);
        stream = ensureStream();
        Object endpoint = delivery(stream).get("endpoint_url");
        if (!(endpoint instanceof String)) throw new GnapError("ssf", "the stream has no poll endpoint_url");
        running = true;
        loop();
    }

    public void stop() {
        running = false;
        if (timer != null) timer.cancel(false);
        if (scheduler != null) scheduler.shutdownNow();
    }

    public boolean pollOnce() {
        CompletableFuture<Boolean> future;
        boolean owner;
        synchronized (gate) {
            if (inflight != null) {
                future = inflight;
                owner = false;
            } else {
                future = inflight = new CompletableFuture<>();
                owner = true;
            }
        }
        if (!owner) return join(future);
        try {
            boolean result = pollNow();
            future.complete(result);
            return result;
        } catch (RuntimeException err) {
            future.completeExceptionally(err);
            throw err;
        } finally {
            synchronized (gate) {
                if (inflight == future) inflight = null;
            }
        }
    }

    private static boolean join(CompletableFuture<Boolean> future) {
        try {
            return future.get();
        } catch (ExecutionException err) {
            Throwable cause = err.getCause();
            if (cause instanceof RuntimeException runtime) throw runtime;
            if (cause instanceof Error error) throw error;
            throw new IllegalStateException(cause);
        } catch (InterruptedException err) {
            Thread.currentThread().interrupt();
            throw new GnapError("ssf", "the poll was interrupted");
        }
    }

    public void verify(String state) {
        Object endpoint = config == null ? null : config.get("verification_endpoint");
        if (!(endpoint instanceof String url)) throw new GnapError("ssf", "the transmitter publishes no verification_endpoint");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("stream_id", stream.get("stream_id"));
        if (state != null && !state.isBlank()) body.put("state", state);
        int status = call("POST", url, body).status;
        if (status != 200 && status != 204) throw new GnapError("ssf", "verification answered " + status);
    }

    private void loop() {
        if (!running) return;
        long delay = pollIntervalMs;
        try {
            if (pollOnce()) delay = 0;
        } catch (Exception err) {
            delay = Math.min(pollIntervalMs * 4, 60_000);
        }
        if (!running) return;
        if (scheduler == null) scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "gnap-ssf");
            thread.setDaemon(true);
            return thread;
        });
        timer = scheduler.schedule(this::loop, delay, TimeUnit.MILLISECONDS);
    }

    private boolean pollNow() {
        String url = String.valueOf(delivery(stream).get("endpoint_url"));
        List<String> sentAck = new ArrayList<>(ack);
        Map<String, Object> sentErrs = new LinkedHashMap<>(errs);
        ack.clear();
        errs.clear();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("maxEvents", maxEvents);
        body.put("returnImmediately", true);
        if (!sentAck.isEmpty()) body.put("ack", sentAck);
        if (!sentErrs.isEmpty()) body.put("setErrs", sentErrs);
        Reply reply = call("POST", url, body);
        if (reply.status != 200) {
            ack.addAll(0, sentAck);
            errs.putAll(sentErrs);
            throw new GnapError("ssf", "the poll answered " + reply.status + ": " + Json.dumps(reply.body));
        }
        Map<String, Object> doc = Json.map(reply.body);
        if (doc == null) doc = Map.of();
        Map<String, Object> sets = Json.map(doc.get("sets"));
        if (sets == null) sets = Map.of();
        for (Map.Entry<String, Object> entry : sets.entrySet()) {
            try {
                handle(entry.getKey(), String.valueOf(entry.getValue()));
                ack.add(entry.getKey());
            } catch (Exception err) {
                String code = err instanceof GnapError gnap && "signature".equals(gnap.code) ? "invalid_key" : "invalid_request";
                Map<String, Object> problem = new LinkedHashMap<>();
                problem.put("err", code);
                problem.put("description", String.valueOf(err.getMessage()));
                errs.put(entry.getKey(), problem);
            }
        }
        return Boolean.TRUE.equals(doc.get("moreAvailable"));
    }

    private void handle(String jti, String token) {
        Map<String, Object> verified;
        try {
            verified = Jws.verify(token, jwks(false));
        } catch (GnapError err) {
            if (!RETRY.matcher(String.valueOf(err.getMessage())).find()) throw err;
            verified = Jws.verify(token, jwks(true));
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> header = (Map<String, Object>) verified.get("header");
        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) verified.get("payload");
        if (header.get("typ") != null && !"secevent+jwt".equalsIgnoreCase(String.valueOf(header.get("typ")))) {
            throw new GnapError("validation", "the SET's typ is " + header.get("typ"));
        }
        if (!String.valueOf(config.get("issuer")).equals(payload.get("iss"))) {
            throw new GnapError("validation", "the SET was issued by " + payload.get("iss") + ", not " + config.get("issuer"));
        }
        List<String> want = strings(stream.get("aud"));
        List<String> aud = strings(payload.get("aud"));
        if (!want.isEmpty() && aud.stream().noneMatch(want::contains)) {
            throw new GnapError("validation", "the SET is for " + String.join(", ", aud) + ", not this stream");
        }
        if (payload.containsKey("jti") && payload.get("jti") != null && !jti.equals(String.valueOf(payload.get("jti")))) {
            throw new GnapError("validation", "the SET's jti is not the one it was delivered under");
        }
        Map<String, Object> events = Json.map(payload.get("events"));
        if (events == null || events.isEmpty()) throw new GnapError("validation", "the SET carries no events");
        for (Map.Entry<String, Object> entry : events.entrySet()) {
            Object subjectRaw = payload.get("sub_id");
            if (subjectRaw == null && entry.getValue() instanceof Map<?, ?> body) subjectRaw = body.get("subject");
            Map<String, String> subject = Events.subjectOf(subjectRaw, String.valueOf(config.get("issuer")));
            List<String> sessions = sessionsFor(entry.getKey(), subject);
            boolean ends = endOn.contains(entry.getKey()) && !sessions.isEmpty();
            Event event = new Event(entry.getKey(), entry.getValue() == null ? Map.of() : entry.getValue(), subject, jti, sessions, ends);
            if (ends) {
                try {
                    onEnd.accept(sessions, event);
                } catch (Exception err) {
                    event.ended = false;
                }
                if (event.ended) for (String localId : sessions) index.remove(localId);
            }
            List<Consumer<Event>> both = new ArrayList<>();
            if (handlers.get(entry.getKey()) != null) both.addAll(handlers.get(entry.getKey()));
            if (handlers.get("*") != null) both.addAll(handlers.get("*"));
            for (Consumer<Event> handler : both) {
                try { handler.accept(event); } catch (Exception ignored) { }
            }
        }
    }

    private List<String> sessionsFor(String type, Map<String, String> subject) {
        if (Events.VERIFICATION.equals(type) || Events.STREAM_UPDATED.equals(type)) return List.of();
        if (subject.get("idp_session") != null) {
            List<String> found = index.byIdpSession(subject.get("idp_session"));
            if (!found.isEmpty() || Events.SESSION_REVOKED.equals(type)) return found;
        }
        if (subject.get("person") != null) return index.byPerson(subject.get("person"));
        if (subject.get("email") != null) return index.byEmail(subject.get("email"));
        return List.of();
    }

    private Map<String, Object> discover() {
        List<String> urls = Discovery.wellKnown(transmitter, "ssf-configuration");
        GnapError last = new GnapError("ssf", "no transmitter configuration at " + String.join(" or ", urls));
        for (String url : urls) {
            Reply reply = call("GET", url, null);
            Map<String, Object> doc = Json.map(reply.body);
            if (reply.status == 404 && !url.equals(urls.get(urls.size() - 1))) continue;
            if (reply.status != 200 || doc == null || doc.get("configuration_endpoint") == null || doc.get("jwks_uri") == null) {
                last = new GnapError("ssf", url + " answered " + reply.status + " without a usable transmitter configuration");
                continue;
            }
            List<Object> methods = Json.list(doc.get("delivery_methods_supported"));
            if (methods != null && !methods.contains(POLL)) throw new GnapError("ssf", "the transmitter does not offer poll delivery (RFC 8936)");
            return doc;
        }
        throw last;
    }

    private List<Map<String, Object>> jwks(boolean force) {
        if (!force && !keys.isEmpty() && System.currentTimeMillis() - keysAt < 3_600_000) return keys;
        Reply reply = call("GET", String.valueOf(config.get("jwks_uri")), null);
        Map<String, Object> doc = Json.map(reply.body);
        List<Object> list = doc == null ? null : Json.list(doc.get("keys"));
        if (reply.status != 200 || list == null) throw new GnapError("ssf", "the transmitter's JWKS answered " + reply.status);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object item : list) {
            Map<String, Object> key = Json.map(item);
            if (key != null) out.add(key);
        }
        keys = out;
        keysAt = System.currentTimeMillis();
        return keys;
    }

    private Map<String, Object> ensureStream() {
        String endpoint = String.valueOf(config.get("configuration_endpoint"));
        Reply listed = call("GET", endpoint, null);
        if (listed.status == 200) {
            List<Object> all = Json.list(listed.body);
            if (all == null && listed.body != null) all = List.of(listed.body);
            if (all != null) {
                for (Object item : all) {
                    Map<String, Object> one = Json.map(item);
                    if (one != null && POLL.equals(delivery(one).get("method")) && one.get("stream_id") != null) return one;
                }
            }
        } else if (listed.status != 404) {
            throw new GnapError("ssf", "listing the streams at " + endpoint + " answered " + listed.status);
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("delivery", Json.obj("method", POLL));
        payload.put("events_requested", eventsRequested);
        if (description != null) payload.put("description", description);
        Reply created = call("POST", endpoint, payload);
        Map<String, Object> doc = Json.map(created.body);
        if ((created.status != 200 && created.status != 201) || doc == null || doc.get("stream_id") == null) {
            throw new GnapError("ssf", "creating a stream at " + endpoint + " answered " + created.status);
        }
        return doc;
    }

    private Reply call(String method, String url, Object body) {
        String text = body == null ? null : Json.dumps(body);
        Map<String, String> extra = new LinkedHashMap<>();
        if (headers != null) {
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("method", method);
            request.put("url", url);
            if (text != null) request.put("body", text);
            Map<String, String> signed = headers.apply(request);
            if (signed != null) extra.putAll(signed);
        }
        extra.putIfAbsent("accept", "application/json");
        if (text != null) extra.putIfAbsent("content-type", "application/json");
        Http.Answer answer = Http.send(url, method, extra, text, tls, "ssf");
        Object parsed = null;
        if (answer.body != null && !answer.body.isEmpty()) {
            try { parsed = Json.parse(answer.body); } catch (Exception err) { parsed = answer.body; }
        }
        return new Reply(answer.status, parsed);
    }

    private static Map<String, Object> delivery(Map<String, Object> stream) {
        Map<String, Object> delivery = stream == null ? null : Json.map(stream.get("delivery"));
        return delivery == null ? Map.of() : delivery;
    }

    private static List<String> strings(Object value) {
        if (value instanceof List<?> list) {
            List<String> out = new ArrayList<>();
            for (Object item : list) out.add(String.valueOf(item));
            return out;
        }
        if (value == null) return List.of();
        return List.of(String.valueOf(value));
    }

    public static final class Event {
        public final String type;
        public final Object payload;
        public final Map<String, String> subject;
        public final String jti;
        public final List<String> sessions;
        public boolean ended;

        public Event(String type, Object payload, Map<String, String> subject, String jti, List<String> sessions, boolean ended) {
            this.type = type;
            this.payload = payload;
            this.subject = subject;
            this.jti = jti;
            this.sessions = sessions;
            this.ended = ended;
        }
    }

    private record Reply(int status, Object body) {}
}
