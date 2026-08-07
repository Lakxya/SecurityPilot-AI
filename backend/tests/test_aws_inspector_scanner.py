import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.inspector import AWSInspectorScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_inspector_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # Account status mock
    client.batch_get_account_status.return_value = {
        "accounts": [
            {
                "accountId": "123456789012",
                "resourceState": {
                    "ec2": {"status": "ENABLED"},
                    "ecr": {"status": "DISABLED"},
                    "lambda": {"status": "DISABLED"}
                }
            }
        ]
    }

    # Coverage paginator mock
    coverage_paginator = MagicMock()
    coverage_paginator.paginate.return_value = [
        {
            "coveredResources": [
                {
                    "resourceId": "i-0123456789",
                    "coverageStatus": {"statusCode": "COVERED"}
                },
                {
                    "resourceId": "i-9876543210",
                    "coverageStatus": {"statusCode": "UNCOVERED"}
                }
            ]
        }
    ]

    # Findings paginator mock
    findings_paginator = MagicMock()
    findings_paginator.paginate.return_value = [
        {
            "findings": [
                {
                    "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/001",
                    "severity": "CRITICAL",
                    "type": "PACKAGE_VULNERABILITY",
                    "exploitAvailable": "YES"
                },
                {
                    "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/002",
                    "severity": "HIGH",
                    "type": "NETWORK_REACHABILITY",
                    "exploitAvailable": "NO",
                    "networkReachabilityDetails": {"openPortRange": {"begin": 22, "end": 22}}
                }
            ]
        }
    ]

    def mock_get_paginator(operation_name):
        if operation_name == "list_coverage":
            return coverage_paginator
        elif operation_name == "list_findings":
            return findings_paginator
        return MagicMock()

    client.get_paginator.side_effect = mock_get_paginator

    return session, client

@pytest.mark.asyncio
async def test_aws_inspector_scanner_mocked_checks(mock_inspector_session):
    session, client = mock_inspector_session
    scanner = AWSInspectorScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # Verify ECR Scanning Disabled check
    ecr_findings = [f for f in findings if "ECR Container Scanning Disabled" in f.title]
    assert len(ecr_findings) > 0
    assert ecr_findings[0].severity == Severity.HIGH

    # Verify Critical CVEs check
    crit_findings = [f for f in findings if "CRITICAL Vulnerabilities" in f.title]
    assert len(crit_findings) > 0
    assert crit_findings[0].severity == Severity.CRITICAL

    # Verify Exploitable CVEs check
    exploit_findings = [f for f in findings if "Publicly Exploitable Vulnerabilities" in f.title]
    assert len(exploit_findings) > 0

@pytest.mark.asyncio
async def test_risk_engine_integration_inspector(mock_inspector_session):
    session, client = mock_inspector_session
    scanner = AWSInspectorScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.critical_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_inspector():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "inspector"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
