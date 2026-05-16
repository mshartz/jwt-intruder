package com.portswigger.jwt.intruder;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;
import burp.api.montoya.intruder.PayloadProcessor;

import java.nio.charset.StandardCharsets;

/**
 * JWT Signing Payload Processor
 *
 * For each Intruder payload value, this processor:
 *   1. Extracts the original JWT from the insertion point base value
 *   2. Applies the § template substitution stored in JWTAttackConfig
 *   3. Re-signs with the configured algorithm + key
 *   4. Returns the complete signed JWT to Intruder
 *
 * All steps are logged to the Burp Output tab so you can diagnose
 * issues without needing to run in a debugger.
 */
public class JWTSigningProcessor implements PayloadProcessor {

    private final MontoyaApi api;
    private final JWTAttackConfig config;

    public JWTSigningProcessor(MontoyaApi api, JWTAttackConfig config) {
        this.api    = api;
        this.config = config;
    }

    @Override
    public String displayName() {
        return "JWT – Signing Processor";
    }

    @Override
    public PayloadProcessingResult processPayload(PayloadData payloadData) {

        // ── 1. Get the raw Intruder payload value ─────────────────────────
        String payloadValue = new String(
                payloadData.currentPayload().getBytes(), StandardCharsets.UTF_8);

        api.logging().logToOutput("[JWT Processor] ── New payload ──────────────────");
        api.logging().logToOutput("[JWT Processor] Payload value  : " + payloadValue);

        // ── 2. Extract the JWT from the insertion point ───────────────────
        // baseValue() returns the content of the §marked§ region.
        // We also scan it with extractJWT() as a fallback in case the
        // base value contains surrounding whitespace or HTTP context.
        byte[] baseBytes = payloadData.insertionPoint().baseValue().getBytes();
        String baseStr   = new String(baseBytes, StandardCharsets.UTF_8).trim();

        api.logging().logToOutput("[JWT Processor] Base value     : " +
                baseStr.substring(0, Math.min(120, baseStr.length())));

        String originalJwt = null;

        // Try direct parse first (base value IS the JWT)
        if (JWTUtils.looksLikeJWT(baseStr)) {
            originalJwt = baseStr;
            api.logging().logToOutput("[JWT Processor] JWT source     : direct base value");
        }

        // Fallback: scan base value bytes with regex (handles extra whitespace / headers)
        if (originalJwt == null) {
            originalJwt = JWTUtils.extractJWT(baseBytes);
            if (originalJwt != null) {
                api.logging().logToOutput("[JWT Processor] JWT source     : regex scan of base value");
            }
        }

        if (originalJwt == null) {
            api.logging().logToError(
                "[JWT Processor] ERROR: no JWT found in insertion point base value.\n" +
                "  → In Intruder Positions, make sure you have highlighted the\n" +
                "    entire JWT token and clicked 'Add §'.\n" +
                "  → Base value was: " + baseStr.substring(0, Math.min(200, baseStr.length())));
            return PayloadProcessingResult.usePayload(payloadData.currentPayload());
        }

        api.logging().logToOutput("[JWT Processor] JWT found      : " +
                originalJwt.substring(0, Math.min(60, originalJwt.length())) + "…");

        // ── 3. Validate configuration ─────────────────────────────────────
        String payloadTemplate = config.getPayloadTemplate();
        String headerTemplate  = config.getHeaderTemplate();
        String algorithm       = config.getAlgorithm();
        String keyMaterial     = config.getKeyMaterial();

        api.logging().logToOutput("[JWT Processor] Algorithm      : " + algorithm);
        api.logging().logToOutput("[JWT Processor] Key set        : " + !keyMaterial.isBlank());
        api.logging().logToOutput("[JWT Processor] Payload tpl    : " +
                (payloadTemplate.isEmpty() ? "(none — will use original)" : payloadTemplate));
        api.logging().logToOutput("[JWT Processor] Has § marker   : " +
                JWTUtils.hasMarker(payloadTemplate));

        if (keyMaterial.isBlank()) {
            api.logging().logToError(
                "[JWT Processor] ERROR: no signing key configured.\n" +
                "  → Open the JWT tab in the Positions view, enter your\n" +
                "    secret or private key, and click 'Apply Configuration'.");
            return PayloadProcessingResult.usePayload(payloadData.currentPayload());
        }

        // If no template has been set, or there are no § markers, we still
        // re-sign the original JWT unchanged — useful for testing signing alone.
        if (!JWTUtils.hasMarker(payloadTemplate) && !JWTUtils.hasMarker(headerTemplate)) {
            api.logging().logToOutput(
                "[JWT Processor] No § markers in template — re-signing original JWT unchanged");
        }

        // ── 4. Build and sign the modified JWT ────────────────────────────
        try {
            String modifiedJwt = JWTUtils.buildModifiedSignedJWT(
                    originalJwt,
                    payloadTemplate,
                    headerTemplate,
                    payloadValue,
                    algorithm,
                    keyMaterial);

            api.logging().logToOutput("[JWT Processor] Result         : " +
                    modifiedJwt.substring(0, Math.min(60, modifiedJwt.length())) + "…");
            api.logging().logToOutput("[JWT Processor] ─────────────────────────────────────");

            return PayloadProcessingResult.usePayload(
                    ByteArray.byteArray(modifiedJwt.getBytes(StandardCharsets.UTF_8)));

        } catch (Exception e) {
            api.logging().logToError(
                "[JWT Processor] ERROR: signing failed — " + e.getMessage() + "\n" +
                "  Algorithm : " + algorithm + "\n" +
                "  Check that the key format matches the algorithm:\n" +
                "    HS* → UTF-8 or Base64url secret string\n" +
                "    RS*/PS* → PKCS#8 PEM (-----BEGIN PRIVATE KEY-----)\n" +
                "              or JWK JSON { \"kty\":\"RSA\", ... }");
            return PayloadProcessingResult.usePayload(payloadData.currentPayload());
        }
    }
}