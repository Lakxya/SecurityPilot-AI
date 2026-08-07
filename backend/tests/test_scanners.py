import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.engine.finding import Finding
from app.engine.severity import Severity
from app.engine.scanner_base import BaseScanner
from app.engine.scanner_registry import ScannerRegistry, scanner_registry
from app.engine.risk_engine import RiskEngine
from app.engine.compliance_engine import ComplianceEngine
from app.scanners.aws.iam import AWSIAMScanner
from app.scanners.aws.s3 import AWSS3Scanner

class MockTestScanner(BaseScanner):
    async def scan(self):
        return [
            Finding(
                id="TEST-001",
                provider="TestProvider",
                service="TestService",
                resource="test-resource",
                title="Test Vulnerability",
                description="Test description for unit testing",
                severity=Severity.HIGH,
                cvss=8.0,
                recommendation="Fix test vulnerability",
                remediation="echo fix",
            )
        ]

    async def health_check(self):
        return True

    def metadata(self):
        return {
            "id": "mock_test_scanner",
            "name": "Mock Test Auditor",
            "provider": "TestProvider",
            "service": "TestService",
            "version": "1.0.0",
        }

@pytest.mark.asyncio
async def test_scanner_registry():
    registry = ScannerRegistry()
    mock_scanner = MockTestScanner()
    
    registry.register("test_key", mock_scanner)
    assert registry.get("test_key") == mock_scanner
    assert "TestProvider" in registry.list_providers()
    assert len(registry.get_by_provider("TestProvider")) == 1
    assert registry.list_scanners()[0]["name"] == "Mock Test Auditor"
    
    registry.unregister("test_key")
    assert registry.get("test_key") is None

@pytest.mark.asyncio
async def test_risk_engine():
    f1 = Finding(
        id="F-1",
        provider="AWS",
        service="IAM",
        resource="res1",
        title="Critical Finding",
        description="Critical description",
        severity=Severity.CRITICAL,
        cvss=9.8,
        recommendation="Fix critical issue",
        remediation="fix cmd",
    )
    f2 = Finding(
        id="F-2",
        provider="AWS",
        service="S3",
        resource="res2",
        title="High Finding",
        description="High description",
        severity=Severity.HIGH,
        cvss=7.5,
        recommendation="Fix high issue",
        remediation="fix cmd",
    )

    report = RiskEngine.calculate_score([f1, f2])
    assert report.security_score == 70  # 100 - (20 + 10) = 70
    assert report.risk_level == "GOOD"
    assert report.risk_summary.critical_count == 1
    assert report.risk_summary.high_count == 1
    assert report.risk_summary.total_findings == 2
    assert "Fix critical issue" in report.recommendations

@pytest.mark.asyncio
async def test_compliance_engine():
    f = Finding(
        id="F-MFA",
        provider="AWS",
        service="IAM",
        resource="root",
        title="Root User MFA Disabled",
        description="Root account missing MFA credential",
        severity=Severity.CRITICAL,
        cvss=9.8,
        recommendation="Enable MFA",
        remediation="enable mfa",
    )

    enriched = ComplianceEngine.enrich_finding(f)
    assert any("OWASP" in tag for tag in enriched.frameworks)
    assert any("CIS" in tag for tag in enriched.frameworks)

@pytest.mark.asyncio
async def test_api_endpoints():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # GET /api/v1/scanners
        res = await client.get("/api/v1/scanners")
        assert res.status_code == 200
        scanners_data = res.json()
        assert isinstance(scanners_data, list)
        assert len(scanners_data) > 0

        # GET /api/v1/scanners/providers
        res_providers = await client.get("/api/v1/scanners/providers")
        assert res_providers.status_code == 200
        providers_data = res_providers.json()
        assert "AWS" in providers_data

        # POST /api/v1/scanners/run
        res_run = await client.post("/api/v1/scanners/run", json={"providers": ["AWS"]})
        assert res_run.status_code == 200
        run_data = res_run.json()
        assert run_data["status"] == "success"
        assert run_data["total_findings"] > 0
        assert "score_report" in run_data

        # GET /api/v1/findings
        res_findings = await client.get("/api/v1/findings?provider=AWS")
        assert res_findings.status_code == 200
        findings_data = res_findings.json()
        assert isinstance(findings_data, list)

        # GET /api/v1/security-score
        res_score = await client.get("/api/v1/security-score?provider=AWS")
        assert res_score.status_code == 200
        score_data = res_score.json()
        assert "security_score" in score_data
        assert 0 <= score_data["security_score"] <= 100
