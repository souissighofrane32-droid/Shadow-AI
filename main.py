from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("SHADOW_AI_DB", BASE_DIR / "shadow_ai.db"))

app = FastAPI(
    title="Shadow AI Policy & Compliance Auditor",
    version="1.0.0",
    description="Enterprise AI prompt inspection and compliance telemetry API.",
)

RULES: list[dict[str, Any]] = [
    {"id": "AWS_ACCESS_KEY", "category": "secrets", "risk": "critical", "weight": 100,
     "pattern": r"\bAKIA[0-9A-Z]{16}\b", "message": "AWS access key detected."},
    {"id": "PRIVATE_KEY", "category": "secrets", "risk": "critical", "weight": 100,
     "pattern": r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----", "message": "Private key material detected."},
    {"id": "GITHUB_TOKEN", "category": "secrets", "risk": "critical", "weight": 95,
     "pattern": r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b", "message": "GitHub token pattern detected."},
    {"id": "GENERIC_SECRET", "category": "secrets", "risk": "high", "weight": 80,
     "pattern": r"(?i)\b(?:api[_ -]?key|secret[_ -]?key|client[_ -]?secret|password|passwd|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}",
     "message": "Credential-like assignment detected."},
    {"id": "JWT", "category": "secrets", "risk": "high", "weight": 75,
     "pattern": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
     "message": "JWT-like token detected."},
    {"id": "PRIVATE_REPO_URL", "category": "source_code", "risk": "high", "weight": 55,
     "pattern": r"https?://(?:github|gitlab|bitbucket)\.(?:com|local)/[^\s]+/[^\s]+",
     "message": "Repository URL detected; verify whether it is private."},
    {"id": "SOURCE_CODE", "category": "source_code", "risk": "medium", "weight": 35,
     "pattern": r"(?i)\b(?:def|class|import|from)\s+[A-Za-z_][\w.]*|\b(?:SELECT|INSERT|UPDATE|DELETE)\s+.+\bFROM\b",
     "message": "Source-code or SQL-like content detected."},
    {"id": "INTERNAL_IP", "category": "internal_infrastructure", "risk": "high", "weight": 65,
     "pattern": r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.(?:\d{1,3}\.)\d{1,3})\b",
     "message": "Private/internal IP address detected."},
    {"id": "INTERNAL_DNS", "category": "internal_infrastructure", "risk": "high", "weight": 60,
     "pattern": r"(?i)\b(?:[a-z0-9-]+\.)*(?:internal|intranet|corp|lan|local)\b",
     "message": "Internal DNS/domain marker detected."},
    {"id": "CLASSIFICATION", "category": "internal_data", "risk": "high", "weight": 60,
     "pattern": r"(?i)\b(?:confidential|restricted|internal[- ]only|proprietary|trade secret)\b",
     "message": "Information-classification marker detected."},
    {"id": "EMAIL", "category": "personal_data", "risk": "medium", "weight": 25,
     "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "message": "Email address detected."},
    {"id": "PHONE", "category": "personal_data", "risk": "medium", "weight": 25,
     "pattern": r"(?<!\d)(?:\+\d{1,3}[ .-]?)?(?:\d[ .-]?){8,14}\d(?!\d)", "message": "Phone-number-like data detected."},
    {"id": "IBAN", "category": "financial_data", "risk": "high", "weight": 65,
     "pattern": r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", "message": "IBAN-like financial identifier detected."},
    {"id": "NATIONAL_ID", "category": "personal_data", "risk": "high", "weight": 55,
     "pattern": r"(?i)\b(?:national id|identity number|passport number|cin)\s*[:#-]?\s*[A-Z0-9-]{5,}\b",
     "message": "Government/identity identifier marker detected."},
    {"id": "GDPR_PERSONAL_DATA", "category": "privacy", "risk": "high", "weight": 55,
     "pattern": r"(?i)\b(?:GDPR|personal data|data subject|right to erasure|right of access|special category data|consent)\b",
     "message": "GDPR/privacy-sensitive terminology detected."},
    {"id": "HIPAA_PHI", "category": "health_data", "risk": "high", "weight": 65,
     "pattern": r"(?i)\b(?:HIPAA|PHI|protected health information|medical record|patient id|diagnosis|treatment plan)\b",
     "message": "HIPAA/health-information terminology detected."},
    {"id": "CONFIDENTIAL_CONTRACT", "category": "legal", "risk": "high", "weight": 65,
     "pattern": r"(?i)\b(?:NDA|non[- ]disclosure|confidentiality clause|confidential agreement|contract clause|termination clause|indemnification)\b",
     "message": "Confidential contract/legal terminology detected."},
    {"id": "M_AND_A", "category": "corporate", "risk": "critical", "weight": 90,
     "pattern": r"(?i)\b(?:merger|acquisition|M&A|due diligence|term sheet|material nonpublic information)\b",
     "message": "Potentially restricted corporate transaction terminology detected."},
    {"id": "FINANCIAL_RESTRICTED", "category": "financial_data", "risk": "high", "weight": 60,
     "pattern": r"(?i)\b(?:bank account|credit card|routing number|financial statement|earnings forecast|insider information)\b",
     "message": "Sensitive financial terminology detected."},
]

class InspectRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=100_000)
    source: str = Field(default="api", max_length=100)
    user_id: str | None = Field(default=None, max_length=200)
    destination: str | None = Field(default=None, max_length=200)

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS compliance_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                source TEXT NOT NULL,
                destination TEXT,
                user_id TEXT,
                risk TEXT NOT NULL,
                score INTEGER NOT NULL,
                blocked INTEGER NOT NULL,
                findings_json TEXT NOT NULL,
                prompt_sha256 TEXT NOT NULL,
                prompt_preview TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_created ON compliance_events(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_risk ON compliance_events(risk)")
        conn.commit()

@app.on_event("startup")
def startup() -> None:
    init_db()

def redact_preview(prompt: str) -> str:
    preview = re.sub(r"(?i)(password|secret|token|api[_ -]?key)\s*[:=]\s*\S+", r"\1=[REDACTED]", prompt)
    return preview[:280]

def inspect_prompt(prompt: str) -> tuple[list[dict[str, Any]], int, str, bool]:
    findings = []
    for rule in RULES:
        match = re.search(rule["pattern"], prompt)
        if match:
            start = max(0, match.start() - 45)
            end = min(len(prompt), match.end() + 45)
            evidence = prompt[start:end].replace("\n", " ")
            if len(evidence) > 140:
                evidence = evidence[:140] + "…"
            findings.append({
                "rule_id": rule["id"], "category": rule["category"], "risk": rule["risk"],
                "weight": rule["weight"], "message": rule["message"], "evidence": evidence
            })

    score = min(100, sum(item["weight"] for item in findings))
    if any(item["risk"] == "critical" for item in findings) or score >= 80:
        risk = "critical"
    elif score >= 55 or any(item["risk"] == "high" for item in findings):
        risk = "high"
    elif score >= 25 or findings:
        risk = "medium"
    else:
        risk = "low"

    has_secret = any(item["category"] == "secrets" for item in findings)
    has_transfer = bool(re.search(r"(?i)\b(?:upload|send|share|paste|submit|post|external|public)\b", prompt))
    blocked = risk == "critical" or (has_secret and has_transfer)
    return findings, score, risk, blocked

def record_event(req: InspectRequest, findings: list[dict[str, Any]], score: int, risk: str, blocked: bool) -> int:
    digest = hashlib.sha256(req.prompt.encode("utf-8")).hexdigest()
    with db() as conn:
        cur = conn.execute("""
            INSERT INTO compliance_events
            (created_at, source, destination, user_id, risk, score, blocked, findings_json, prompt_sha256, prompt_preview)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            utc_now(), req.source, req.destination, req.user_id, risk, score, int(blocked),
            json.dumps(findings, ensure_ascii=False), digest, redact_preview(req.prompt)
        ))
        conn.commit()
        return int(cur.lastrowid)

@app.get("/")
def root() -> dict[str, str]:
    return {"name": app.title, "status": "ok", "dashboard": "/dashboard/"}

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy", "time": utc_now()}

@app.post("/api/inspect")
def inspect(req: InspectRequest) -> dict[str, Any]:
    findings, score, risk, blocked = inspect_prompt(req.prompt)
    event_id = record_event(req, findings, score, risk, blocked)
    return {
        "allowed": not blocked, "blocked": blocked, "event_id": event_id,
        "risk": risk, "score": score, "findings": findings,
        "message": "Prompt blocked by policy." if blocked else "Prompt inspected successfully."
    }

@app.get("/api/reports/compliance-summary")
def compliance_summary() -> dict[str, Any]:
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM compliance_events").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM compliance_events WHERE blocked=1").fetchone()[0]
        rows = conn.execute("SELECT risk, COUNT(*) AS count FROM compliance_events GROUP BY risk").fetchall()
        categories = conn.execute("""
            SELECT json_extract(value, '$.category') AS category, COUNT(*) AS count
            FROM compliance_events, json_each(findings_json)
            GROUP BY category ORDER BY count DESC
        """).fetchall()
    breakdown = {r["risk"]: r["count"] for r in rows}
    for level in ("critical", "high", "medium", "low"):
        breakdown.setdefault(level, 0)
    return {
        "total_incidents": total, "blocked_incidents": blocked,
        "risk_breakdown": breakdown,
        "top_categories": [{"category": r["category"], "count": r["count"]} for r in categories],
        "generated_at": utc_now()
    }

@app.get("/api/reports/incidents")
def incidents(limit: int = 50, risk: str | None = None, source: str | None = None) -> dict[str, Any]:
    limit = max(1, min(limit, 200))
    sql = "SELECT * FROM compliance_events WHERE 1=1"
    params: list[Any] = []
    if risk in {"critical", "high", "medium", "low"}:
        sql += " AND risk=?"; params.append(risk)
    if source:
        sql += " AND source=?"; params.append(source)
    sql += " ORDER BY created_at DESC LIMIT ?"; params.append(limit)
    with db() as conn:
        rows = conn.execute(sql, params).fetchall()
    return {"incidents": [
        {
            "id": r["id"], "created_at": r["created_at"], "source": r["source"],
            "destination": r["destination"], "risk": r["risk"], "score": r["score"],
            "blocked": bool(r["blocked"]), "findings": json.loads(r["findings_json"]),
            "prompt_sha256": r["prompt_sha256"], "prompt_preview": r["prompt_preview"]
        } for r in rows
    ]}

@app.get("/api/reports/export-json")
def export_json() -> JSONResponse:
    with db() as conn:
        rows = conn.execute("SELECT * FROM compliance_events ORDER BY created_at DESC").fetchall()
    payload = {"report": "Shadow AI Compliance Audit", "generated_at": utc_now(), "events": [dict(r) for r in rows]}
    return JSONResponse(content=payload, headers={"Content-Disposition": 'attachment; filename="shadow-ai-audit.json"'})

@app.get("/api/reports/export-pdf")
def export_pdf() -> FileResponse:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    output = BASE_DIR / "shadow-ai-audit.pdf"
    summary = compliance_summary()
    data = incidents(100)["incidents"]
    doc = SimpleDocTemplate(str(output), pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Shadow AI — Compliance Audit Report", styles["Title"]),
        Paragraph("Generated: " + summary["generated_at"], styles["Normal"]),
        Spacer(1, 12),
        Paragraph(f"Total incidents: {summary['total_incidents']}    Blocked: {summary['blocked_incidents']}", styles["Heading2"]),
        Spacer(1, 8)
    ]
    risk_data = [["Risk", "Count"]] + [[k.title(), str(summary["risk_breakdown"][k])] for k in ("critical", "high", "medium", "low")]
    t1 = Table(risk_data, colWidths=[180, 100])
    t1.setStyle(TableStyle([("GRID", (0,0), (-1,-1), 0.5, colors.grey), ("BACKGROUND", (0,0), (-1,0), colors.lightgrey)]))
    story += [t1, Spacer(1, 16), Paragraph("Recent incidents", styles["Heading2"])]
    incident_data = [["Time", "Source", "Risk", "Score", "Blocked"]]
    for item in data[:30]:
        incident_data.append([item["created_at"][:19].replace("T", " "), item["source"][:24], item["risk"].upper(), str(item["score"]), "YES" if item["blocked"] else "NO"])
    t2 = Table(incident_data, repeatRows=1, colWidths=[105, 105, 65, 45, 55])
    t2.setStyle(TableStyle([("GRID", (0,0), (-1,-1), 0.25, colors.grey), ("BACKGROUND", (0,0), (-1,0), colors.lightgrey), ("FONTSIZE", (0,0), (-1,-1), 7)]))
    story += [t2, Spacer(1, 12), Paragraph("Detections are policy indicators and do not by themselves establish a legal violation or compliance determination.", styles["Italic"])]
    doc.build(story)
    return FileResponse(str(output), media_type="application/pdf", filename="shadow-ai-audit.pdf")

@app.get("/dashboard/")
def dashboard() -> FileResponse:
    return FileResponse(BASE_DIR / "dashboard" / "index.html")

@app.get("/dashboard/script.js")
def dashboard_script() -> FileResponse:
    return FileResponse(BASE_DIR / "dashboard" / "script.js", media_type="application/javascript")
