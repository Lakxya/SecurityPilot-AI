from typing import List
from pydantic import BaseModel, Field
from app.engine.finding import Finding
from app.engine.severity import Severity

class RiskSummary(BaseModel):
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

class SecurityScoreReport(BaseModel):
    security_score: int = Field(..., ge=0, le=100, description="Overall Security Score 0-100")
    risk_level: str = Field(..., description="EXCELLENT, GOOD, WARNING, CRITICAL")
    risk_summary: RiskSummary
    recommendations: List[str] = Field(default_factory=list, description="Prioritized recommendations")

class RiskEngine:
    """
    Enterprise Security Risk & CVSS Scoring Engine.
    Calculates overall security score (0-100), risk counts, and prioritized recommendations.
    """

    @classmethod
    def calculate_score(cls, findings: List[Finding]) -> SecurityScoreReport:
        critical_cnt = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_cnt = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium_cnt = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_cnt = sum(1 for f in findings if f.severity == Severity.LOW)
        info_cnt = sum(1 for f in findings if f.severity == Severity.INFO)

        # Deduct points from 100
        penalty = (critical_cnt * 20) + (high_cnt * 10) + (medium_cnt * 5) + (low_cnt * 2)
        score = max(0, 100 - penalty)

        if score >= 85:
            risk_level = "EXCELLENT"
        elif score >= 70:
            risk_level = "GOOD"
        elif score >= 50:
            risk_level = "WARNING"
        else:
            risk_level = "CRITICAL"

        # Generate prioritized recommendations
        recs = []
        for f in sorted(findings, key=lambda x: (x.severity != Severity.CRITICAL, x.severity != Severity.HIGH, -x.cvss)):
            if f.recommendation and f.recommendation not in recs:
                recs.append(f.recommendation)
                if len(recs) >= 5:
                    break

        if not recs:
            recs = ["Maintain current security standards.", "Ensure automated continuous compliance scanning."]

        summary = RiskSummary(
            total_findings=len(findings),
            critical_count=critical_cnt,
            high_count=high_cnt,
            medium_count=medium_cnt,
            low_count=low_cnt,
            info_count=info_cnt,
        )

        return SecurityScoreReport(
            security_score=score,
            risk_level=risk_level,
            risk_summary=summary,
            recommendations=recs,
        )
