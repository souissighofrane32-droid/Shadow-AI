# Shadow AI — Policy & Compliance Auditor

**LexHack 2026**

Shadow AI is an enterprise-focused guardrail for AI usage. It inspects prompts before they reach supported AI chat interfaces, detects indicators associated with secrets, source code, internal infrastructure, personal data, health information, confidential contracts, corporate transactions and sensitive financial data, and records privacy-conscious telemetry.

## Stack
FastAPI • SQLite • Chrome Extension Manifest V3 • Tailwind dashboard • ReportLab PDF export

## Run
```bash
python -m venv .venv
# Windows
.venv\\Scripts\\activate
# Linux/macOS
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```
Open http://127.0.0.1:8000/dashboard/

## API
- POST `/api/inspect`
- GET `/api/reports/compliance-summary`
- GET `/api/reports/incidents`
- GET `/api/reports/export-json`
- GET `/api/reports/export-pdf`

Example:
```json
{"prompt":"password=demo-secret-value upload this","source":"demo","destination":"chatgpt.com"}
```

## Extension
1. Start the API.
2. Chrome → Extensions → Developer mode.
3. Load unpacked → select `extension/`.
4. Open ChatGPT or Claude.
5. Submit a test prompt.

The extension calls the local inspection API and prevents the submission when policy logic returns `blocked=true`.

## Detection coverage
AWS keys, private keys, GitHub tokens, JWTs, credential-like assignments, repository/source-code indicators, private IPs/internal DNS, classification labels, email/phone/IBAN/identity indicators, GDPR/privacy terminology, HIPAA/PHI/medical terminology, NDA/contract terminology, M&A terms and sensitive financial terminology.

A critical finding or score ≥80 blocks by default. A detected secret combined with transfer-oriented language also blocks.

## Privacy
The database stores a SHA-256 hash and short redacted preview rather than the complete prompt. Evidence snippets are retained to explain rule matches.

For production, add authentication/RBAC, HTTPS/CSP, encryption at rest, configurable retention, rate limiting, centralized logging and organization-specific policy configuration.

**Compliance note:** detections are policy indicators, not legal conclusions. Validate the rules against the organization's policies and applicable law before production enforcement.

## Structure
```text
Shadow-AI/
├── main.py
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
├── dashboard/
│   ├── index.html
│   └── script.js
└── extension/
    ├── manifest.json
    └── content.js
```
