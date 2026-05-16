package com.portswigger.jwt.intruder;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.nimbusds.jose.jwk.RSAKey;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class JWTUtils {

    // Relaxed pattern: only requires the HEADER to start with "eyJ"
    // Stricter pattern: "eyJ…eyJ…" failed on attack-result requests where payload segment's base64url didn't happen to start with "eyJ"
    private static final Pattern JWT_PATTERN =
            Pattern.compile("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*");

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // ── Extraction  //

    public static String extractJWT(byte[] data) {
        if (data == null || data.length == 0) return null;
        String text = new String(data, StandardCharsets.UTF_8);
        Matcher m = JWT_PATTERN.matcher(text);
        return m.find() ? m.group(0) : null;
    }

    /**
     * Extract JWT from HTTP request
     * Header names are compared case-insensitively (because HTTP/2 uses lowercase, James Kettle eat your heart out)
     */
    public static String extractJWTFromRequest(HttpRequest req) {
        if (req == null) return null;

        // Strategy 1+2: iterate headers with case-insensitive name matching
        try {
            for (var header : req.headers()) {
                String name  = header.name().toLowerCase();
                String value = header.value();
                if (value == null || value.isEmpty()) continue;

                if (name.equals("authorization")) {
                    String t = value.trim();
                    String candidate = t.toLowerCase().startsWith("bearer ")
                            ? t.substring(7).trim() : t;
                    if (looksLikeJWT(candidate)) return candidate;
                    String found = extractJWT(value.getBytes(StandardCharsets.UTF_8));
                    if (found != null) return found;
                }

                if (name.equals("cookie")) {
                    // Split "name=val; name2=val2" and check each cookie value
                    for (String seg : value.split(";")) {
                        seg = seg.trim();
                        int eq = seg.indexOf('=');
                        if (eq >= 0) {
                            String cookieVal = seg.substring(eq + 1).trim();
                            if (looksLikeJWT(cookieVal)) return cookieVal;
                            String found = extractJWT(cookieVal.getBytes(StandardCharsets.UTF_8));
                            if (found != null) return found;
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        // Strategy the Third: full toString() scan (query params, body, etc.)
        try {
            String raw = req.toString();
            if (raw != null && !raw.isEmpty()) {
                String found = extractJWT(raw.getBytes(StandardCharsets.UTF_8));
                if (found != null) return found;
            }
        } catch (Exception ignored) {}

        // Strategy the Fourth: scan EVERY header value
        try {
            for (var header : req.headers()) {
                if (header.value() == null) continue;
                String found = extractJWT(header.value().getBytes(StandardCharsets.UTF_8));
                if (found != null) return found;
            }
        } catch (Exception ignored) {}

        return null;
    }

    public static boolean looksLikeJWT(String s) {
        if (s == null || s.isEmpty()) return false;
        int first = s.indexOf('.');
        if (first < 0) return false;
        return s.indexOf('.', first + 1) >= 0 && s.startsWith("eyJ");
    }

    // ── Decoding  //

    public static JSONObject decodeHeader(String jwt) throws Exception {
        String[] parts = jwt.split("\\.", 3);
        if (parts.length < 2) throw new IllegalArgumentException("Not a JWT");
        return new JSONObject(new String(base64UrlDecode(parts[0]), StandardCharsets.UTF_8));
    }

    public static JSONObject decodePayload(String jwt) throws Exception {
        String[] parts = jwt.split("\\.", 3);
        if (parts.length < 2) throw new IllegalArgumentException("Not a JWT");
        return new JSONObject(new String(base64UrlDecode(parts[1]), StandardCharsets.UTF_8));
    }

    public static String prettyPrint(JSONObject obj) {
        StringBuilder sb = new StringBuilder("{\n");
        var keys = obj.keys();
        boolean first = true;
        while (keys.hasNext()) {
            if (!first) sb.append(",\n");
            String k = keys.next();
            Object v = obj.get(k);
            sb.append("  \"").append(k).append("\": ");
            if (v instanceof String) sb.append("\"").append(v).append("\"");
            else sb.append(v);
            first = false;
        }
        sb.append("\n}");
        return sb.toString();
    }

    // ── § sub  //

    public static String applySubstitution(String template, String value) {
        int start = template.indexOf('§');
        if (start == -1) return template;
        int end = template.indexOf('§', start + 1);
        if (end == -1) return template;
        return template.substring(0, start) + value + template.substring(end + 1);
    }

    public static boolean hasMarker(String template) {
        if (template == null) return false;
        int first = template.indexOf('§');
        return first != -1 && template.indexOf('§', first + 1) != -1;
    }

    // ── Building & signing  //

    public static String buildModifiedSignedJWT(
            String originalJwt,
            String payloadTemplate,
            String headerTemplate,
            String payloadValue,
            String algorithm,
            String keyMaterial) throws Exception {

        String headerJson;
        if (hasMarker(headerTemplate)) {
            headerJson = applySubstitution(headerTemplate, payloadValue);
        } else if (headerTemplate != null && !headerTemplate.isBlank()) {
            headerJson = headerTemplate;
        } else {
            headerJson = prettyPrint(decodeHeader(originalJwt));
        }

        String payloadJson;
        if (hasMarker(payloadTemplate)) {
            payloadJson = applySubstitution(payloadTemplate, payloadValue);
        } else if (payloadTemplate != null && !payloadTemplate.isBlank()) {
            payloadJson = payloadTemplate;
        } else {
            payloadJson = prettyPrint(decodePayload(originalJwt));
        }

        JSONObject hObj = new JSONObject(headerJson);
        hObj.put("alg", algorithm);
        headerJson = hObj.toString();

        return signJWT(headerJson, payloadJson, algorithm, keyMaterial);
    }

    private static String signJWT(String headerJson, String payloadJson,
                                   String algorithm, String keyMaterial) throws Exception {
        // Compact JSON before encoding so both segments start with "eyJ"
        String compactHeader  = new JSONObject(headerJson).toString();
        String compactPayload = new JSONObject(payloadJson).toString();
        String headerB64  = base64UrlEncode(compactHeader.getBytes(StandardCharsets.UTF_8));
        String payloadB64 = base64UrlEncode(compactPayload.getBytes(StandardCharsets.UTF_8));
        String signingInput = headerB64 + "." + payloadB64;
        byte[] sig = computeSignature(
                signingInput.getBytes(StandardCharsets.UTF_8), algorithm, keyMaterial);
        return signingInput + "." + base64UrlEncode(sig);
    }

    private static byte[] computeSignature(byte[] input, String algorithm,
                                            String keyMaterial) throws Exception {
        switch (algorithm) {
            case "HS256": return hmac(input, keyMaterial, "HmacSHA256");
            case "HS384": return hmac(input, keyMaterial, "HmacSHA384");
            case "HS512": return hmac(input, keyMaterial, "HmacSHA512");
            case "RS256": return rsaSign(input, keyMaterial, "SHA256withRSA");
            case "RS384": return rsaSign(input, keyMaterial, "SHA384withRSA");
            case "RS512": return rsaSign(input, keyMaterial, "SHA512withRSA");
            case "PS256": return rsaSign(input, keyMaterial, "SHA256withRSAandMGF1");
            case "PS384": return rsaSign(input, keyMaterial, "SHA384withRSAandMGF1");
            case "PS512": return rsaSign(input, keyMaterial, "SHA512withRSAandMGF1");
            default: throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }

    private static byte[] hmac(byte[] input, String secret, String jcaAlgorithm) throws Exception {
        byte[] keyBytes = resolveHmacSecret(secret);
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance(jcaAlgorithm);
        mac.init(new javax.crypto.spec.SecretKeySpec(keyBytes, jcaAlgorithm));
        return mac.doFinal(input);
    }

    private static byte[] resolveHmacSecret(String secret) {
        try { return Base64.getUrlDecoder().decode(secret); } catch (Exception ignored) {}
        try { return Base64.getDecoder().decode(secret);    } catch (Exception ignored) {}
        return secret.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] rsaSign(byte[] input, String keyMaterial,
                                   String jcaAlgorithm) throws Exception {
        PrivateKey privateKey = parsePrivateKey(keyMaterial.trim());
        Signature sig = jcaAlgorithm.contains("MGF1")
                ? Signature.getInstance(jcaAlgorithm, "BC")
                : Signature.getInstance(jcaAlgorithm);
        sig.initSign(privateKey);
        sig.update(input);
        return sig.sign();
    }

    private static PrivateKey parsePrivateKey(String keyMaterial) throws Exception {
        if (keyMaterial.startsWith("{")) {
            return RSAKey.parse(keyMaterial).toPrivateKey();
        }
        String stripped = keyMaterial
                .replaceAll("-----BEGIN [^-]+-----", "")
                .replaceAll("-----END [^-]+-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(stripped);
        try {
            return KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception ignored) {}
        RSAPrivateKey asn1 = RSAPrivateKey.getInstance(der);
        return KeyFactory.getInstance("RSA")
                .generatePrivate(new RSAPrivateKeySpec(
                        asn1.getModulus(), asn1.getPrivateExponent()));
    }

    public static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static byte[] base64UrlDecode(String s) {
        int pad = (4 - s.length() % 4) % 4;
        return Base64.getUrlDecoder().decode(s + "=".repeat(pad));
    }

    private JWTUtils() {}
}
