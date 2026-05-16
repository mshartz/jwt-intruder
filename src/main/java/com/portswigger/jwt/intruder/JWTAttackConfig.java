package com.portswigger.jwt.intruder;

import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * Session-scoped config shared between the editor UI and payload processor 
 * All fields are held in memory only to prevent accidental key leakage between Burp sessions
 */
public class JWTAttackConfig {

    // ── Signing  //
    /**
     * One of: HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512
     */
    private final AtomicReference<String> algorithm =
            new AtomicReference<>("HS256");

    /**
     * HMAC algorithms : raw UTF-8 secret string (or Base64url-encoded bytes for binary secrets)
     * RSA algorithms  : PKCS#8 PEM private key  OR  a JWK JSON object
     */
    private final AtomicReference<String> keyMaterial =
            new AtomicReference<>("");

    // § Templates //
    /**
     * JSON payload with exactly one pair of § markers indicating where
     * the Intruder payload value will be inserted
     *
     * e.g.  {"sub":"user","role":"§user§"}
     *
     * If blank, original payload is re-encoded verbatim 
     */
    private final AtomicReference<String> payloadTemplate =
            new AtomicReference<>("");

    /**
     * The header JSON with § markers.  Usually left blank; included for the edge cases, i.e. when header claim "kid" needs fuzzing
     * If blank, original header is used with only the "alg" field updated to match algorithm.
     */
    private final AtomicReference<String> headerTemplate =
            new AtomicReference<>("");

    // Accessors //

    public String getAlgorithm()               { return algorithm.get(); }
    public void   setAlgorithm(String v)       { algorithm.set(v == null ? "HS256" : v.trim()); }

    public String getKeyMaterial()             { return keyMaterial.get(); }
    public void   setKeyMaterial(String v)     { keyMaterial.set(v == null ? "" : v); }

    public String getPayloadTemplate()         { return payloadTemplate.get(); }
    public void   setPayloadTemplate(String v) { payloadTemplate.set(v == null ? "" : v); }

    public String getHeaderTemplate()          { return headerTemplate.get(); }
    public void   setHeaderTemplate(String v)  { headerTemplate.set(v == null ? "" : v); }

    // Returns true if § insertion point has been configured //
    public boolean hasTemplate() {
        return payloadTemplate.get().contains("§") ||
               headerTemplate.get().contains("§");
    }

    // Returns true if signing key/secret has been entered //
    public boolean hasKey() {
        return !keyMaterial.get().isBlank();
    }

    // ── Result JWT queue ───────────────────────────────────────────────────
    // processor pushes each signed result JWT here so the editor tab can display decoded token even when it cannot read it from the request
    private final ConcurrentLinkedDeque<String> resultQueue =
            new ConcurrentLinkedDeque<>();
    private static final int MAX_QUEUE = 500;

    public void pushResultJwt(String jwt) {
        if (jwt == null) return;
        resultQueue.addLast(jwt);
        while (resultQueue.size() > MAX_QUEUE) resultQueue.pollFirst();
    }

    /** Removes and returns the oldest unread result JWT, or null if empty */
    public String pollResultJwt() {
        return resultQueue.pollFirst();
    }
}
