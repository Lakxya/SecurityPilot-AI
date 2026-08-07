from typing import List, Optional
from fastapi import APIRouter, Query, HTTPException, status
from pydantic import BaseModel
from app.engine.scanner_registry import scanner_registry
from app.engine.compliance_engine import ComplianceEngine
from app.engine.risk_engine import RiskEngine, SecurityScoreReport
from app.engine.finding import Finding
import app.scanners  # ensures init_scanners() runs

router = APIRouter(tags=["Security Scanners"])

class ScanRequest(BaseModel):
    provider: Optional[str] = None
    service: Optional[str] = None
    providers: Optional[List[str]] = None
    scanner_keys: Optional[List[str]] = None

class ScanResponse(BaseModel):
    status: str
    total_findings: int
    findings: List[Finding]
    score_report: SecurityScoreReport

@router.get("/scanners", response_model=List[dict])
async def list_scanners():
    """List metadata for all registered security scanners."""
    return scanner_registry.list_scanners()

@router.get("/scanners/providers", response_model=List[str])
async def list_providers():
    """List unique registered cloud and platform providers."""
    return scanner_registry.list_providers()

@router.post("/scanners/run", response_model=ScanResponse)
async def run_scanners(request: ScanRequest = ScanRequest()):
    """Execute selected security scanners or all scanners across cloud providers."""
    scanners_to_run = []

    # Direct key lookup
    if request.scanner_keys:
        for key in request.scanner_keys:
            scanner = scanner_registry.get(key)
            if scanner:
                scanners_to_run.append(scanner)
    # Direct single provider & service lookup (e.g. provider="aws", service="iam")
    elif request.provider and request.service:
        key = f"{request.provider.lower()}_{request.service.lower()}"
        scanner = scanner_registry.get(key)
        if scanner:
            scanners_to_run.append(scanner)
        else:
            # Fallback to provider lookup
            scanners_to_run.extend(scanner_registry.get_by_provider(request.provider))
    elif request.provider:
        scanners_to_run.extend(scanner_registry.get_by_provider(request.provider))
    elif request.providers:
        for p in request.providers:
            scanners_to_run.extend(scanner_registry.get_by_provider(p))
    else:
        # Run all master scanners
        scanners_to_run = [
            scanner for scanner in scanner_registry._scanners.values()
            if "master" in scanner.metadata().get("id", "")
        ]

    if not scanners_to_run:
        # Fallback to all scanners if no master matches
        scanners_to_run = list(scanner_registry._scanners.values())

    all_findings: List[Finding] = []
    for scanner in scanners_to_run:
        findings = await scanner.scan()
        all_findings.extend(findings)

    # Enrich findings with compliance frameworks
    enriched_findings = ComplianceEngine.map_findings(all_findings)
    score_report = RiskEngine.calculate_score(enriched_findings)

    return ScanResponse(
        status="success",
        total_findings=len(enriched_findings),
        findings=enriched_findings,
        score_report=score_report,
    )

@router.get("/findings", response_model=List[Finding])
async def get_findings(provider: Optional[str] = None):
    """Retrieve active security findings filtered optionally by provider."""
    all_scanners = list(scanner_registry._scanners.values())
    raw_findings: List[Finding] = []
    for scanner in all_scanners:
        findings = await scanner.scan()
        raw_findings.extend(findings)

    enriched = ComplianceEngine.map_findings(raw_findings)

    if provider:
        p_lower = provider.lower()
        enriched = [f for f in enriched if f.provider.lower() == p_lower]

    return enriched

@router.get("/security-score", response_model=SecurityScoreReport)
async def get_security_score(provider: Optional[str] = None):
    """Calculate and return the overall security score report."""
    findings = await get_findings(provider=provider)
    return RiskEngine.calculate_score(findings)
