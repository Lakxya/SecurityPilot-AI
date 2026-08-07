import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.guardduty import AWSGuardDutyScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_guardduty_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # List detectors paginator mock
    detectors_paginator = MagicMock()
    detectors_paginator.paginate.return_value = [
        {"DetectorIds": ["det-0123456789abcdef0"]}
    ]

    def mock_get_paginator(operation_name):
        if operation_name == "list_detectors":
            return detectors_paginator
        return MagicMock()

    client.get_paginator.side_effect = mock_get_paginator

    # Get detector mock
    client.get_detector.return_value = {
        "Status": "ENABLED",
        "DataSources": {
            "S3Logs": {"Status": "DISABLED"},
            "Kubernetes": {"AuditLogs": {"Status": "DISABLED"}},
            "MalwareProtection": {
                "ScanEc2InstanceWithFindings": {
                    "EbsVolumes": {"Status": "DISABLED"}
                }
            },
            "LambdaLogs": {"Status": "DISABLED"},
        }
    }

    # List threat intel sets mock
    client.list_threat_intel_sets.return_value = {"ThreatIntelSetIds": []}

    # List ip sets mock
    client.list_ip_sets.return_value = {"IpSetIds": []}

    # List publishing destinations mock
    client.list_publishing_destinations.return_value = {"Destinations": []}

    # List findings & get findings mock
    client.list_findings.return_value = {"FindingIds": ["f-001"]}
    client.get_findings.return_value = {
        "Findings": [
            {
                "Id": "f-001",
                "Severity": 8.5,
                "Type": "CryptoCurrency:EC2/BitcoinTool.B!DNS"
            }
        ]
    }

    return session, client

@pytest.mark.asyncio
async def test_aws_guardduty_scanner_mocked_checks(mock_guardduty_session):
    session, client = mock_guardduty_session
    scanner = AWSGuardDutyScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # Verify S3 Protection check
    s3_findings = [f for f in findings if "S3 Protection Disabled" in f.title]
    assert len(s3_findings) > 0
    assert s3_findings[0].severity == Severity.HIGH

    # Verify Malware Protection check
    malware_findings = [f for f in findings if "Malware Protection Disabled" in f.title]
    assert len(malware_findings) > 0

    # Verify Critical Threat Findings check
    crit_findings = [f for f in findings if "CRITICAL Severity Threat Findings" in f.title]
    assert len(crit_findings) > 0
    assert crit_findings[0].severity == Severity.CRITICAL

@pytest.mark.asyncio
async def test_risk_engine_integration_guardduty(mock_guardduty_session):
    session, client = mock_guardduty_session
    scanner = AWSGuardDutyScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.critical_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_guardduty():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "guardduty"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
