package com.portswigger.jwt.intruder;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.portswigger.jwt.intruder.ui.JWTEditorProvider;

/**
 * Welcome to the JWT Intruder Extension!
 *
 * Adds "JWT" tab to Burp's request editor in all tools (Proxy, Repeater,
 * Intruder) and creates a "JWT – Signing Processor" payload processor to
 * lets testers fuzz specific claim values while automatically re-signing each
 * modified token before it is sent. 
 *
 * Compatible with Burp Suite Professional 2026.x (Montoya API 2026.2)
 * Works independent of the existing (and incredible!) JWT Editor extension
 */
public class JWTIntruderExtension implements BurpExtension {

    public static final String NAME = "JWT Intruder";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);

        // Shared session-scoped config
        JWTAttackConfig config = new JWTAttackConfig();

        // Register the JWT tab in Proxy, Repeater, Intruder and Scanner editors
        // Note: Scanning support has not been fully tested. If anyone has ideas or wants to test this, please feel free to do so
        api.userInterface().registerHttpRequestEditorProvider(
                new JWTEditorProvider(api, config));

        // Register the signing payload processor
        api.intruder().registerPayloadProcessor(
                new JWTSigningProcessor(api, config));

        api.logging().logToOutput("===========================================");
        api.logging().logToOutput(NAME + " loaded");
        api.logging().logToOutput("─── Quick start ─────────────────────────");
        api.logging().logToOutput("1. Open any JWT request → click the JWT tab");
        api.logging().logToOutput("2. Place § markers in the payload JSON");
        api.logging().logToOutput("   e.g.  {\"sub\":\"§user§\",\"role\":\"USER\"}");
        api.logging().logToOutput("3. Select algorithm + enter key → Apply Configuration");
        api.logging().logToOutput("4. In Intruder Positions: mark the whole JWT as §token§");
        api.logging().logToOutput("5. In Payloads: add your list + add Payload Processing");
        api.logging().logToOutput("   → Extension → JWT – Signing Processor");
        api.logging().logToOutput("6. Start attack");
        api.logging().logToOutput("===========================================");
    }
}
