from datetime import datetime, timezone
from typing import List
from pydantic import BaseModel, Field
from app.engine.severity import Severity

class Finding(BaseModel):
    id: str = Field(..., description="Unique finding ID")
    provider: str = Field(..., description="Cloud or platform provider (e.g. AWS, Azure, GCP, Docker, K8s, Terraform, GitHub)")
    service: str = Field(..., description="Service name (e.g. IAM, S3, EC2, CloudTrail, KMS)")
    resource: str = Field(..., description="Target resource ARN or identifier")
    title: str = Field(..., description="Finding title")
    description: str = Field(..., description="Detailed vulnerability description")
    severity: Severity = Field(..., description="Vulnerability severity rating")
    cvss: float = Field(default=0.0, ge=0.0, le=10.0, description="CVSS v3.1 score rating")
    recommendation: str = Field(..., description="Recommended fix strategy")
    remediation: str = Field(..., description="Copy-paste remediation code or command")
    references: List[str] = Field(default_factory=list, description="Reference links & documentation")
    frameworks: List[str] = Field(default_factory=list, description="Mapped compliance frameworks (e.g. OWASP, CIS, NIST, SOC2, ISO27001, MITRE ATT&CK)")
    status: str = Field(default="OPEN", description="Finding status (OPEN, IN_PROGRESS, RESOLVED, IGNORED)")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="UTC timestamp when finding was created")
