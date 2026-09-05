"""OPERATOR-only formatted report export.

The underlying data (DPDP audit categories/counts, security-classification
log) is already visible in the popup UI for every tier — this endpoint does
not gate *seeing* it, it gates the polished, one-click, timestamped export
artifact, which is what "Export Reports" means in the product tiers. The
report body is exactly what the client already computed locally (category
names/counts only — dpdp-audit.mjs never includes raw PII values), so this
endpoint receives nothing more sensitive than what was already on screen.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

import models
from entitlements import require_feature

router = APIRouter(prefix="/reports", tags=["reports"])


class ExportRequest(BaseModel):
    title: str = "DPDP Compliance Audit Report"
    dpdp_report: dict[str, Any] | None = None
    security_summary: dict[str, Any] | None = None


@router.post("/export")
def export_report(body: ExportRequest, user: models.User = Depends(require_feature("EXPORT_REPORTS"))):
    generated_at = datetime.now(timezone.utc).isoformat()
    report_id = f"rpt_{uuid.uuid4().hex[:12]}"
    lines = [
        f"# {body.title}",
        "",
        f"Report ID: {report_id}",
        f"Generated: {generated_at}",
        f"Generated for: {user.email}",
        "Tier: Operator",
        "",
        "---",
        "",
    ]
    if body.dpdp_report:
        lines.append("## DPDP Act 2023 Compliance Summary")
        lines.append("")
        lines.append("```json")
        import json

        lines.append(json.dumps(body.dpdp_report, indent=2, default=str))
        lines.append("```")
        lines.append("")
    if body.security_summary:
        lines.append("## Security / Egress Classification Summary")
        lines.append("")
        lines.append("```json")
        import json

        lines.append(json.dumps(body.security_summary, indent=2, default=str))
        lines.append("```")

    return {
        "report_id": report_id,
        "generated_at": generated_at,
        "content_markdown": "\n".join(lines),
    }
