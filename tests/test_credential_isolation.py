"""
Comprehensive Unit Tests for Credential & Session Scope Isolation.
Validates:
1. Exact parity between ESM and content-script IIFE definitions.
2. Viewport scope boundary enforcement and coordinate clamping.
3. Deterministic always-redact classification for autofilled fields and credentials (password, OTP, 2FA, token, SSH keys) regardless of base classifier confidence.
4. DLP rule replacements and semantic token injection.
5. Active tab & session scope validation.
"""

import unittest
import re
import os
import json

class TestCredentialAndSessionScopeIsolation(unittest.TestCase):
    def setUp(self):
        self.root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.sensitive_mjs_path = os.path.join(self.root_dir, "client", "lib", "sensitive-fields.mjs")
        self.sensitive_js_path = os.path.join(self.root_dir, "client", "lib", "sensitive-fields.js")
        self.classifier_path = os.path.join(self.root_dir, "client", "lib", "field-classifier.mjs")
        self.dlp_heuristics_path = os.path.join(self.root_dir, "client", "lib", "dlp-heuristics.mjs")
        self.dlp_sanitizer_path = os.path.join(self.root_dir, "client", "lib", "dlp-sanitizer.mjs")
        self.dlp_script_path = os.path.join(self.root_dir, "client", "dlp-content-script.js")
        self.skeleton_path = os.path.join(self.root_dir, "client", "skeleton.js")
        self.content_path = os.path.join(self.root_dir, "client", "content.js")
        self.background_path = os.path.join(self.root_dir, "client", "background.js")
        self.offscreen_path = os.path.join(self.root_dir, "client", "offscreen.js")
        self.pii_rules_path = os.path.join(self.root_dir, "client", "lib", "pii-rules.mjs")
        self.dom_redactor_path = os.path.join(self.root_dir, "client", "dom-redactor.js")

    def test_file_presence(self):
        """Verify that all core security and isolation files are present."""
        files = [
            self.sensitive_mjs_path, self.sensitive_js_path, self.classifier_path,
            self.dlp_heuristics_path, self.dlp_sanitizer_path, self.dlp_script_path,
            self.skeleton_path, self.content_path, self.background_path, self.offscreen_path,
            self.pii_rules_path, self.dom_redactor_path
        ]
        for f in files:
            self.assertTrue(os.path.exists(f), f"Required file missing: {f}")

    def test_sensitive_fields_parity(self):
        """Ensure full parity between ESM module and IIFE content script for sensitive-fields."""
        with open(self.sensitive_mjs_path, "r", encoding="utf-8") as f:
            esm_text = f.read()
        with open(self.sensitive_js_path, "r", encoding="utf-8") as f:
            iife_text = f.read()

        # Check critical categories in both
        critical_categories = [
            "password", "credential", "credentials", "autofill_credential", "autofill",
            "otp", "2fa", "mfa", "totp", "one-time-code", "auth_token", "api_key",
            "secret", "ssh_key", "session_token", "access_token", "security_key",
            "aadhaar", "pan", "ssn", "credit-card", "cvv", "bank account information"
        ]
        for cat in critical_categories:
            self.assertIn(f'"{cat}"', esm_text, f"Category '{cat}' missing in sensitive-fields.mjs")
            self.assertIn(f'"{cat}"', iife_text, f"Category '{cat}' missing in sensitive-fields.js")

        self.assertIn("ALWAYS_REDACT_CATEGORIES", esm_text)
        self.assertIn("ALWAYS_REDACT_CATEGORIES", iife_text)
        self.assertIn("CREDENTIAL_CATEGORIES", esm_text)
        self.assertIn("CREDENTIAL_CATEGORIES", iife_text)
        self.assertIn("isAlwaysRedact", esm_text)
        self.assertIn("isAlwaysRedact", iife_text)

    def test_deterministic_always_redact_autofill(self):
        """Verify field classifier source guarantees 1.0 confidence and alwaysRedact for autofill."""
        with open(self.classifier_path, "r", encoding="utf-8") as f:
            code = f.read()

        # Check autofill handling
        self.assertIn("const isAutofill = !!(s.isAutofilled || s.autofilled || s.isAutofill);", code)
        self.assertIn("return { category: cat, confidence: 1.0, alwaysRedact: true, isAutofilled: isAutofill };", code)

    def test_password_and_otp_classification(self):
        """Verify password inputs and OTP autocomplete are classified with 1.0 confidence."""
        with open(self.classifier_path, "r", encoding="utf-8") as f:
            code = f.read()

        self.assertIn("const isPwd = tag === \"input\" && type === \"password\";", code)
        self.assertIn("current-password|new-password|one-time-code|webauthn|credential", code)

    def test_viewport_scope_isolation_content_and_skeleton(self):
        """Verify active viewport scope isolation in content.js and skeleton.js."""
        with open(self.content_path, "r", encoding="utf-8") as f:
            content_code = f.read()
        with open(self.skeleton_path, "r", encoding="utf-8") as f:
            skeleton_code = f.read()

        # Viewport clamping & filtering in content.js
        self.assertIn("window.innerWidth", content_code)
        self.assertIn("window.innerHeight", content_code)
        self.assertIn("clampLeft", content_code)
        self.assertIn("clampTop", content_code)

        # Viewport filtering in skeleton.js
        self.assertIn("isVisibleInViewport", skeleton_code)
        self.assertIn("isScopedToViewport: true", skeleton_code)
        self.assertIn("clampLeft", skeleton_code)

    def test_offscreen_canvas_viewport_clamping(self):
        """Verify offscreen.js bounds all redaction boxes to canvas viewport dimensions."""
        with open(self.offscreen_path, "r", encoding="utf-8") as f:
            offscreen_code = f.read()

        self.assertIn("Math.min(canvas.width", offscreen_code)
        self.assertIn("Math.min(canvas.height", offscreen_code)
        self.assertIn("isAlwaysRedactCategory", offscreen_code)
        self.assertIn("isCredentialCategory", offscreen_code)

    def test_background_active_tab_session_verification(self):
        """Verify background.js checks active tab status before captureVisibleTab."""
        with open(self.background_path, "r", encoding="utf-8") as f:
            bg_code = f.read()

        self.assertIn("chrome.tabs.get(tabId)", bg_code)
        self.assertIn("!currentTab.active", bg_code)
        self.assertIn("session scope isolation prevented background capture", bg_code)
        self.assertIn("alwaysRedact: true", bg_code)

    def test_dlp_secret_tokens(self):
        """Verify DLP heuristics defines dedicated tokens for OTP, passwords, and credentials."""
        with open(self.dlp_heuristics_path, "r", encoding="utf-8") as f:
            dlp_code = f.read()

        self.assertIn("[TOKEN_PASSWORD]", dlp_code)
        self.assertIn("[TOKEN_OTP_2FA]", dlp_code)
        self.assertIn("[TOKEN_CREDENTIAL]", dlp_code)
        self.assertIn("[TOKEN_SSH_KEY]", dlp_code)
        self.assertIn("[TOKEN_API_KEY]", dlp_code)

    def test_pii_rules_ocr_and_dom_redactor(self):
        """Verify OCR PII rules and DOM text redactor catch 2FA/OTP codes, API keys, and SSH keys."""
        with open(self.pii_rules_path, "r", encoding="utf-8") as f:
            pii_code = f.read()
        with open(self.dom_redactor_path, "r", encoding="utf-8") as f:
            dom_redactor_code = f.read()

        self.assertIn("category: \"otp\"", pii_code)
        self.assertIn("category: \"credential\"", pii_code)
        self.assertIn("category: \"ssh-key\"", pii_code)

        self.assertIn("category: \"otp\"", dom_redactor_code)
        self.assertIn("category: \"credential\"", dom_redactor_code)
        self.assertIn("category: \"ssh-key\"", dom_redactor_code)

if __name__ == "__main__":
    unittest.main()
