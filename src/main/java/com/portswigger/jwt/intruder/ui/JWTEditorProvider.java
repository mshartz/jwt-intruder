package com.portswigger.jwt.intruder.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import com.portswigger.jwt.intruder.JWTAttackConfig;
import com.portswigger.jwt.intruder.JWTUtils;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.nio.charset.StandardCharsets;

public class JWTEditorProvider implements HttpRequestEditorProvider {

    private final MontoyaApi api;
    private final JWTAttackConfig config;

    public JWTEditorProvider(MontoyaApi api, JWTAttackConfig config) {
        this.api    = api;
        this.config = config;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext ctx) {
        boolean editable = ctx.editorMode() != EditorMode.READ_ONLY;
        return new JWTEditorTab(api, config, editable);
    }

    private static class JWTEditorTab implements ExtensionProvidedHttpRequestEditor {

        private final MontoyaApi api;
        private final JWTAttackConfig config;
        private final boolean editable;
        private HttpRequestResponse currentRR;

        private final JPanel    root;
        private final JTextArea headerArea;
        private final JTextArea payloadArea;
        private final JComboBox<String> algorithmCombo;
        private final JTextArea keyArea;
        private final JLabel    statusLabel = new JLabel(" ");
        private final JButton   applyButton = new JButton("Apply Configuration");

        JWTEditorTab(MontoyaApi api, JWTAttackConfig config, boolean editable) {
            this.api      = api;
            this.config   = config;
            this.editable = editable;
            headerArea     = monoArea(6,  false);
            payloadArea    = monoArea(14, editable);
            algorithmCombo = buildAlgorithmCombo();
            keyArea        = monoArea(6,  editable);
            root = buildUI();
        }

        // ── ExtensionProvidedHttpRequestEditor  //

        @Override public HttpRequest getRequest() {
            return currentRR == null ? null : currentRR.request();
        }

        @Override
        public void setRequestResponse(HttpRequestResponse rr) {
            this.currentRR = rr;
            SwingUtilities.invokeLater(() -> refresh(rr));
        }

        @Override public boolean isEnabledFor(HttpRequestResponse rr) { return true; }
        @Override public String    caption()       { return "JWT"; }
        @Override public Component uiComponent()   { return root; }
        @Override public Selection selectedData()  { return null; }
        @Override public boolean   isModified()    { return false; }

        // ── Populate  //

        private void refresh(HttpRequestResponse rr) {
            if (rr == null) { clearAreas(); return; }

            // Strategy the First: in results mode, use processor queue so we always see the decoded modified+signed JWT regardless of how Burp exposes request object
            if (!editable) {
                String queued = config.pollResultJwt();
                if (queued != null) {
                    decode(queued);
                    return;
                }
            }

            // Strategy the Second: extract JWT from the request object
            String jwt = extractFromRequest(rr.request());
            if (jwt != null) {
                decode(jwt);
                return;
            }

            clearAreas();
        }

         // Trying to find JWT in the request using multiple strategies, all case-insensitive //
        private String extractFromRequest(HttpRequest req) {
            if (req == null) return null;

            // Scan every header value for a substring starting with "eyJ"
            try {
                for (var h : req.headers()) {
                    String val = h.value();
                    if (val == null) continue;
                    int idx = val.indexOf("eyJ");
                    if (idx < 0) continue;
                    String candidate = extractAnchoredAt(val, idx);
                    if (candidate != null) return candidate;
                }
            } catch (Exception ignored) {}

            // Fallback: scan the full toString()
            try {
                String raw = req.toString();
                if (raw != null) {
                    int idx = raw.indexOf("eyJ");
                    while (idx >= 0) {
                        String candidate = extractAnchoredAt(raw, idx);
                        if (candidate != null) return candidate;
                        idx = raw.indexOf("eyJ", idx + 3);
                    }
                }
            } catch (Exception ignored) {}

            return null;
        }

        // Extract JWT-shaped token anchored at position {@code idx} in {@code s}. //
        private static String extractAnchoredAt(String s, int idx) {
            StringBuilder sb = new StringBuilder();
            for (int i = idx; i < s.length(); i++) {
                char c = s.charAt(i);
                if (Character.isLetterOrDigit(c) || c == '-' || c == '_' || c == '.') {
                    sb.append(c);
                } else {
                    break;
                }
            }
            String tok = sb.toString();
            // Need exactly two dots (header.payload.signature) //
            int d1 = tok.indexOf('.');
            if (d1 < 0) return null;
            int d2 = tok.indexOf('.', d1 + 1);
            if (d2 < 0) return null;
            // Each segment must be non-empty //
            if (d1 == 0 || d2 == d1 + 1) return null;
            return tok;
        }

        private void decode(String jwt) {
            try {
                JSONObject header  = JWTUtils.decodeHeader(jwt);
                JSONObject payload = JWTUtils.decodePayload(jwt);
                headerArea.setText(JWTUtils.prettyPrint(header));

                if (editable) {
                    String tpl = config.getPayloadTemplate();
                    payloadArea.setText(tpl != null && !tpl.isBlank()
                            ? tpl : JWTUtils.prettyPrint(payload));
                    algorithmCombo.setSelectedItem(config.getAlgorithm());
                    keyArea.setText(config.getKeyMaterial());
                } else {
                    payloadArea.setText(JWTUtils.prettyPrint(payload));
                }

                String alg = header.optString("alg", "?");
                String marker = (!editable || JWTUtils.hasMarker(payloadArea.getText()))
                        ? "" : " · add § markers to the payload to target a claim";
                status("alg=" + alg + " · " + payload.length() + " claims" + marker,
                        new Color(0, 130, 0));
            } catch (Exception e) {
                status("Could not decode JWT: " + e.getMessage(), Color.RED);
            }
        }

        private void clearAreas() {
            headerArea.setText("");
            payloadArea.setText("");
            status("No JWT found in this request", Color.GRAY);
        }

        // ── UI  //

        private JPanel buildUI() {
            JPanel p = new JPanel(new BorderLayout(6, 6));
            p.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
            statusLabel.setFont(statusLabel.getFont().deriveFont(Font.ITALIC, 11f));
            statusLabel.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
            p.add(statusLabel, BorderLayout.NORTH);
            JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                    buildLeftPanel(), buildRightPanel());
            split.setResizeWeight(0.60);
            p.add(split, BorderLayout.CENTER);
            return p;
        }

        private JPanel buildLeftPanel() {
            JPanel p = new JPanel();
            p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
            p.add(titledScroll("Header (decoded — read-only)", headerArea, 150));
            p.add(Box.createVerticalStrut(4));
            p.add(titledScroll(
                editable ? "Payload (editable — place § markers around the fuzz target)"
                         : "Payload (decoded — what was actually sent)",
                payloadArea, 280));
            return p;
        }

        private JPanel buildRightPanel() {
            JPanel p = new JPanel(new BorderLayout(4, 4));
            p.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Signing configuration",
                TitledBorder.LEFT, TitledBorder.TOP));
            p.setPreferredSize(new Dimension(300, 0));

            if (!editable) {
                JTextArea note = new JTextArea(
                    "Results view\n\n" +
                    "This panel shows the decoded JWT that was actually sent " +
                    "for each Intruder request.\n\n" +
                    "To configure signing, open the request in the " +
                    "Positions tab and use the JWT tab there.");
                note.setEditable(false);
                note.setOpaque(false);
                note.setLineWrap(true);
                note.setWrapStyleWord(true);
                note.setForeground(Color.DARK_GRAY);
                note.setFont(note.getFont().deriveFont(11.5f));
                note.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
                p.add(new JScrollPane(note,
                        JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                        JScrollPane.HORIZONTAL_SCROLLBAR_NEVER),
                      BorderLayout.CENTER);
                return p;
            }

            JPanel form = new JPanel(new GridBagLayout());
            GridBagConstraints c = gbc();

            c.gridx = 0; c.gridy = 0; c.weightx = 0;
            form.add(new JLabel("Algorithm:"), c);
            c.gridx = 1; c.weightx = 1;
            form.add(algorithmCombo, c);

            c.gridx = 0; c.gridy = 1; c.gridwidth = 2; c.weightx = 1;
            form.add(new JLabel("<html>Secret (HMAC) or Private Key (RSA):<br>" +
                "<small>UTF-8 secret, Base64url secret, PKCS#8 PEM, or JWK JSON</small></html>"), c);

            c.gridy = 2; c.fill = GridBagConstraints.BOTH; c.weighty = 1;
            form.add(new JScrollPane(keyArea), c);

            c.gridy = 3; c.fill = GridBagConstraints.HORIZONTAL; c.weighty = 0;
            applyButton.setFont(applyButton.getFont().deriveFont(Font.BOLD));
            applyButton.addActionListener(this::onApply);
            form.add(applyButton, c);

            p.add(form, BorderLayout.CENTER);
            p.add(buildInstructions(), BorderLayout.SOUTH);
            return p;
        }

        private void onApply(ActionEvent e) {
            String payload = payloadArea.getText().trim();
            String header  = headerArea.getText().trim();
            if (!JWTUtils.hasMarker(payload) && !JWTUtils.hasMarker(header)) {
                status("⚠ No § markers found — add § around the fuzz target in the payload", Color.RED);
                return;
            }
            if (keyArea.getText().isBlank()) {
                status("⚠ No key/secret entered", Color.RED);
                return;
            }
            config.setPayloadTemplate(payload);
            config.setHeaderTemplate(header);
            config.setAlgorithm((String) algorithmCombo.getSelectedItem());
            config.setKeyMaterial(keyArea.getText());
            status("✓ Configuration applied — alg=" + config.getAlgorithm(), new Color(0, 130, 0));
        }

        private JPanel buildInstructions() {
            JPanel p = new JPanel(new BorderLayout());
            p.setBorder(BorderFactory.createTitledBorder("How to use"));
            JTextArea l = new JTextArea(
                "1. Place § around the fuzz target in the payload\n" +
                "   e.g. {\"sub\":\"§wiener§\",\"role\":\"user\"}\n\n" +
                "2. Select algorithm + enter key\n\n" +
                "3. Click Apply Configuration\n\n" +
                "4. In Positions: mark the whole JWT as §token§\n\n" +
                "5. In Payloads: add your list, then under\n" +
                "   Payload Processing → Add → Extension\n" +
                "   → JWT – Signing Processor\n\n" +
                "6. Start attack");
            l.setEditable(false);
            l.setOpaque(false);
            l.setLineWrap(true);
            l.setWrapStyleWord(true);
            l.setFont(l.getFont().deriveFont(10.5f));
            l.setForeground(Color.DARK_GRAY);
            l.setBorder(BorderFactory.createEmptyBorder(4, 6, 6, 6));
            p.add(l, BorderLayout.CENTER);
            return p;
        }

        // ── Helpers, because boy howdy do we need them  //

        private JComboBox<String> buildAlgorithmCombo() {
            JComboBox<String> cb = new JComboBox<>(new String[]{
                "HS256","HS384","HS512","RS256","RS384","RS512","PS256","PS384","PS512"});
            cb.setSelectedItem(config.getAlgorithm());
            return cb;
        }

        private static JScrollPane titledScroll(String title, JTextArea area, int h) {
            JScrollPane sp = new JScrollPane(area);
            sp.setBorder(BorderFactory.createTitledBorder(title));
            sp.setPreferredSize(new Dimension(400, h));
            sp.setAlignmentX(Component.LEFT_ALIGNMENT);
            return sp;
        }

        private static JTextArea monoArea(int rows, boolean editable) {
            JTextArea a = new JTextArea(rows, 60);
            a.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            a.setLineWrap(true);
            a.setWrapStyleWord(false);
            a.setEditable(editable);
            if (!editable) a.setBackground(new Color(245, 245, 245));
            return a;
        }

        private static GridBagConstraints gbc() {
            GridBagConstraints c = new GridBagConstraints();
            c.insets = new Insets(4, 4, 4, 4);
            c.anchor = GridBagConstraints.WEST;
            c.fill   = GridBagConstraints.HORIZONTAL;
            c.gridx = 0; c.gridy = 0; c.weightx = 1;
            return c;
        }

        private void status(String msg, Color color) {
            statusLabel.setText(msg);
            statusLabel.setForeground(color);
        }
    }
}
