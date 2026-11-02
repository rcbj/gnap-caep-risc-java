// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap.demo;

import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/** Exits 0 when GET http://127.0.0.1:$PORT/healthz returns ok. */
public final class HealthCheck {
    private HealthCheck() {}

    public static void main(String[] args) throws Exception {
        String port = System.getenv().getOrDefault("PORT", "3000");
        HttpURLConnection conn = (HttpURLConnection) new URL("http://127.0.0.1:" + port + "/healthz").openConnection();
        conn.setConnectTimeout(2000);
        conn.setReadTimeout(2000);
        int status = conn.getResponseCode();
        byte[] body = conn.getInputStream().readAllBytes();
        if (status != 200 || !"ok".equals(new String(body, StandardCharsets.UTF_8))) System.exit(1);
    }
}
