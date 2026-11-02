// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import java.net.URI;
import java.util.Set;

/** Absolute URLs in the form Node's URL.href produces, including bracketed IPv6 hosts. */
public final class Urls {
    public static final Set<String> LOOPBACK = Set.of("localhost", "127.0.0.1", "::1", "[::1]");

    private Urls() {}

    public static String href(String url) {
        URI uri = URI.create(url);
        if (uri.getScheme() == null || uri.getHost() == null) return url;
        if (!"http".equals(uri.getScheme()) && !"https".equals(uri.getScheme())) return url;
        String host = shown(uri.getHost());
        int port = uri.getPort();
        boolean standard = port < 0 || ("http".equals(uri.getScheme()) && port == 80) || ("https".equals(uri.getScheme()) && port == 443);
        String netloc = standard ? host : host + ":" + port;
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        String query = uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery();
        String fragment = uri.getRawFragment() == null ? "" : "#" + uri.getRawFragment();
        return uri.getScheme() + "://" + netloc + path + query + fragment;
    }

    public static String origin(String url) {
        URI uri = URI.create(url);
        String host = shown(uri.getHost());
        int port = uri.getPort();
        boolean standard = port < 0 || ("http".equals(uri.getScheme()) && port == 80) || ("https".equals(uri.getScheme()) && port == 443);
        return uri.getScheme() + "://" + (standard ? host : host + ":" + port);
    }

    public static boolean isLoopback(String url) {
        try {
            String host = URI.create(url).getHost();
            if (host == null) return false;
            String lower = host.toLowerCase();
            return LOOPBACK.contains(lower) || LOOPBACK.contains(shown(lower));
        } catch (Exception err) {
            return false;
        }
    }

    public static String shown(String host) {
        if (host == null) return "";
        if (host.contains(":") && !(host.startsWith("[") && host.endsWith("]"))) return "[" + host + "]";
        return host;
    }
}
