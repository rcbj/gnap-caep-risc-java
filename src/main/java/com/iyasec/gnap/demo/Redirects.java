// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap.demo;

import java.net.URI;
import java.util.Set;

/** Loopback finish and display URLs follow the port the demo listens on. Any other host is left as written. */
public final class Redirects {
    private static final Set<String> LOOPBACK = Set.of("localhost", "127.0.0.1", "::1", "[::1]");

    private Redirects() {}

    public static Integer portNumber(String value) {
        if (value == null || value.isBlank()) return null;
        try {
            int port = Integer.parseInt(value.trim());
            return port >= 1 && port <= 65535 ? port : null;
        } catch (NumberFormatException err) {
            return null;
        }
    }

    public static String onPort(String url, int port) {
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            String shown = host != null && host.contains(":") && !host.startsWith("[") ? "[" + host + "]" : host;
            if (host == null || (!LOOPBACK.contains(host) && !LOOPBACK.contains(shown))) return url;
            String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
            String query = uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery();
            return uri.getScheme() + "://" + shown + ":" + port + path + query;
        } catch (Exception err) {
            return url;
        }
    }

    public static Moved redirectsFor(String finishUri, String displayUri, String publicUrl, boolean publicUrlGiven, Integer port) {
        if (publicUrlGiven && publicUrl != null && !publicUrl.isBlank()) {
            URI base = URI.create(publicUrl.endsWith("/") ? publicUrl : publicUrl + "/");
            return new Moved(move(finishUri, base), move(displayUri, base));
        }
        if (port != null) return new Moved(onPort(finishUri, port), displayUri == null || displayUri.isBlank() ? displayUri : onPort(displayUri, port));
        return new Moved(finishUri, displayUri);
    }

    public static Integer demoPort(String envPort, String containerPort) {
        Integer container = portNumber(containerPort);
        return container != null ? container : portNumber(envPort);
    }

    private static String move(String value, URI base) {
        if (value == null || value.isBlank()) return value;
        URI next = URI.create(value);
        String path = next.getRawPath() == null || next.getRawPath().isEmpty() ? "/" : next.getRawPath();
        String query = next.getRawQuery() == null ? "" : "?" + next.getRawQuery();
        return base.getScheme() + "://" + base.getRawAuthority() + path + query;
    }

    public record Moved(String finishUri, String displayUri) {}
}
