// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package com.iyasec.gnap;

import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import net.minidev.json.writer.JsonReader;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Compact JSON and base64. Signed bodies are these exact bytes. */
public final class Json {
    private Json() {}

    public static Object parse(String text) {
        try {
            // LinkedHashMap so object key order matches the bytes, the same as JSON.parse.
            JsonReader reader = new JsonReader();
            return new JSONParser(JSONParser.MODE_PERMISSIVE).parse(text, reader.DEFAULT_ORDERED);
        } catch (ParseException err) {
            Caught.error(err);
            throw new IllegalArgumentException(err.getMessage(), err);
        }
    }

    public static String dumps(Object value) {
        StringBuilder out = new StringBuilder();
        write(out, value);
        return out.toString();
    }

    public static String b64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static byte[] b64urlDecode(String value) {
        int pad = (4 - value.length() % 4) % 4;
        return Base64.getUrlDecoder().decode(value + "=".repeat(pad));
    }

    public static String b64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception err) {
            Caught.error(err);
            throw new IllegalStateException(err);
        }
    }

    public static boolean timingEqual(String left, String right) {
        byte[] a = left.getBytes(StandardCharsets.UTF_8);
        byte[] b = right.getBytes(StandardCharsets.UTF_8);
        return a.length == b.length && MessageDigest.isEqual(a, b);
    }

    public static boolean isNumber(Object value) {
        return value instanceof Number;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> map(Object value) {
        return value instanceof Map<?, ?> ? (Map<String, Object>) value : null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> list(Object value) {
        return value instanceof List<?> ? (List<Object>) value : null;
    }

    public static String text(Object value) {
        return value instanceof String ? (String) value : null;
    }

    public static Map<String, Object> obj(Object... pairs) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) out.put((String) pairs[i], pairs[i + 1]);
        return out;
    }

    private static void write(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String text) {
            out.append('"');
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                switch (c) {
                    case '"' -> out.append("\\\"");
                    case '\\' -> out.append("\\\\");
                    case '\n' -> out.append("\\n");
                    case '\r' -> out.append("\\r");
                    case '\t' -> out.append("\\t");
                    default -> {
                        if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                        else out.append(c);
                    }
                }
            }
            out.append('"');
        } else if (value instanceof Boolean || value instanceof Number) {
            if (value instanceof Double || value instanceof Float) {
                double number = ((Number) value).doubleValue();
                if (number == Math.rint(number) && !Double.isInfinite(number)) out.append(Long.toString((long) number));
                else out.append(value.toString());
            } else {
                out.append(value.toString());
            }
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) out.append(',');
                first = false;
                write(out, String.valueOf(entry.getKey()));
                out.append(':');
                write(out, entry.getValue());
            }
            out.append('}');
        } else if (value instanceof Collection<?> list) {
            out.append('[');
            boolean first = true;
            for (Object item : list) {
                if (!first) out.append(',');
                first = false;
                write(out, item);
            }
            out.append(']');
        } else {
            write(out, String.valueOf(value));
        }
    }
}
