# Phase 1 — High-Level Orientation: CONNOR (Privacy-Preserving Vision Agent)

## 1. Executive Summary & Purpose

**CONNOR** (**C**onfidential **O**n-device **N**avigation & **N**etwork-**O**ptimized **R**edaction agent, reference SIH26171) is an on-device, privacy-preserving visual AI agent designed for autonomous, safe browser form-filling and web navigation.

Modern Vision-Language Models (VLMs) like Google Gemini and OpenAI GPT-4o possess powerful visual reasoning capabilities to navigate complex web forms, but sending raw web screenshots, DOM contents, and user identity credentials to third-party cloud APIs poses severe data privacy, compliance (e.g., India DPDP Act, GDPR, HIPAA), and security risks (credential theft, prompt injection, data exfiltration).

CONNOR solves this through an asymmetric, zero-PII client-server architecture:
1. **Local Redaction & Structural Extraction (Client)**: A Manifest V3 browser extension captures the browser viewport, performs on-device OCR (Tesseract.js WASM) and face detection (MediaPipe BlazeFace), strips actual user values from the DOM, and creates a solid blackout-redacted screenshot alongside an anonymized accessibility skeleton.
2. **Abstract Visual Reasoning (Cloud / VLM)**: The cloud backend receives *only* the blacked-out visual image and structural skeleton nodes with tokenized field descriptors (`fillToken`, `piiCategory`, `isCensored: true`, `hasFill: true`). The VLM reasons about layout, required steps, and navigation without ever seeing real PII.
3. **Local Resolution & Action Firewall (Client Execution)**: The VLM returns high-level tokenized actions (e.g., `type` target `node_12` with token `local:aadhaar`). The on-device Action Firewall validates the action against security policies, resolves the token from the user's encrypted local profile vault on the client device, and simulates safe user interaction directly in the DOM.

---

## 2. Technology Stack & Ecosystem

| Layer / Subsystem | Technologies & Tools | Purpose |
|---|---|---|
| **Client Extension** | JavaScript (ES Modules, Vanilla JS), Manifest V3, Web Audio / DOM APIs | Chrome and Firefox browser extension for UI, content interception, DOM skeleton generation, and local execution |
| **On-Device Vision / OCR** | Tesseract.js (WASM), MediaPipe BlazeFace (WASM), Offscreen Canvas | In-browser offscreen document worker for zero-cloud OCR text detection and facial bounding box identification |
| **Backend API** | Python 3.10+, FastAPI, Uvicorn, Pydantic v2 | High-performance asynchronous REST API serving `/agent/step`, `/health`, and `/privacy` |
| **VLM Integrations** | Google Gemini (`gemini-3.6-flash` via HTTP API), OpenAI-compatible API (`httpx`, `openai`), Mock Engine | Multi-backend visual reasoning adapter supporting Gemini, OpenAI/vLLM/OpenRouter, and offline deterministic mock planning |
| **Testing & Eval Harness** | Node.js Test Runner (`node --test`), Python `pytest`, Synthetic Benchmark Generators | Comprehensive test suite covering heuristic DLP, checksum validation (Luhn, Verhoeff), prompt injection, canary token tracking, and security labs |
| **Styling & Assets** | Vanilla CSS, HTML5, Custom SVG / WebP icons | High-performance, dependency-free UI design for popup dashboard and test fixtures |

---

## 3. Root-Level Configuration & Environment

- **`package.json`**:
  - Name: `privacy-lens-vision-agent` (Version `0.2.0`)
  - Type: `"module"` (native ES Modules)
  - Defines scripts for:
    - Vendor asset management (`scripts/fetch-vendor.mjs`)
    - Chrome/Firefox manifest generation (`scripts/build-manifest.mjs`)
    - Test execution (`tests/**/*.test.mjs`)
    - Benchmarks: Redaction accuracy (`eval/bench/redaction.mjs`), latency benchmarking (`eval/bench/latency.mjs`), synthetic screen scoring (`eval/screens/score.mjs`), egress verification (`eval/experiments/privacy-egress.mjs`), and competitor baselines
    - Security Lab generation & evaluation (`security-lab/gen-lab.mjs`, `eval/security/attack-suite.mjs`)
    - Local fixture serving (`scripts/serve.mjs`)
- **`server/requirements.txt`**:
  - `fastapi>=0.110`, `uvicorn[standard]>=0.27`, `pydantic>=2.6`, `python-dotenv>=1.0`, `httpx>=0.27`, `certifi>=2024.0`, `openai>=1.30`.
- **`server/.env` / `server/.env.example`**:
  - Configuration for `VLM_MODE` (`gemini`, `openai`, `mock`), `GEMINI_API_KEY`, `VLM_MODEL`, `VLM_BASE_URL`, and `VLM_API_KEY`.
- **`.gitignore`**:
  - Ignores Python `.venv/`, `__pycache__/`, Node `node_modules/`, downloaded vendor models/WASM binaries (`client/vendor/`), temporary test artifacts, and `.env` files.
- **`benchmark-results.json`**:
  - Pre-computed performance metrics documenting OCR F1-scores, redaction latency, face detection precision, and action firewall bypass rates.

---

## 4. Key Application Entry Points

1. **Browser Extension Service Worker (`client/background.js`)**:
   - Central coordinator for Manifest V3. Manages active tabs, initiates viewport screenshot capture, delegates OCR/face detection to the offscreen worker, drives step loops by calling the backend API, and routes actions to content scripts.
2. **Extension Popup Dashboard (`client/popup.html` & `client/popup.js`)**:
   - User control center. Manages user profile fields (identity, address, financial info), sets agent goals, toggles autonomous vs. step-by-step approval modes, and displays live visual logs with bounding-box overlays and DPDP compliance audits.
3. **Content Script Layer (`client/content.js`, `client/skeleton.js`, `client/executor.js`, `client/dlp-content-script.js`)**:
   - Injected into web pages. Extracts the accessibility DOM skeleton, tags PII field candidates, executes sandboxed click/type/select actions, and applies client-side DLP sanitization.
4. **Offscreen Processing Worker (`client/offscreen.html` & `client/offscreen.js`)**:
   - Dedicated offscreen execution environment hosting Tesseract.js and MediaPipe WASM runtime to perform client-side visual inspection without blocking the DOM or extension UI.
5. **Backend Server Application (`server/main.py`)**:
   - FastAPI server exposing `/agent/step` to process blacked-out screenshots and skeleton trees, delegating visual reasoning to `server/vlm.py` (Gemini/OpenAI/Mock) and enforcing defense-in-depth safety filters.
6. **Evaluation & Security Suite (`eval/run_eval.mjs`, `eval/agent-eval.mjs`, `security-lab/gen-lab.mjs`)**:
   - Benchmark runners to test DLP detectors, adversarial prompt injections, canary leaks, and end-to-end form completion fidelity.
