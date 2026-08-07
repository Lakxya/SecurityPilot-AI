import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.securityhub import AWSSecurityHubScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_securityhub_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # Describe hub mock
    client.describe_hub.return_value = {
        "HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default",
        "SubscribedAt": "2026-01-01T00:00:00Z"
    }

    # Enabled standards paginator mock
    standards_paginator = MagicMock()
    standards_paginator.paginate.return_value = [
        {
            "StandardsSubscriptions": [
                {
                    "StandardsArn": "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v1.0.0"
                }
            ]
        }
    ]

    # Get findings paginator mock
    findings_paginator = MagicMock()
    findings_paginator.paginate.return_value = [
        {
            "Findings": [
                {
                    "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/001",
                    "Severity": {"Label": "CRITICAL"},
                    "Compliance": {"Status": "FAILED"}
                },
                {
                    "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/002",
                    "Severity": {"Label": "HIGH"},
                    "Compliance": {"Status": "FAILED"}
                }
            ]
        }
    ]

    # Members paginator mock
    members_paginator = MagicMock()
    members_paginator.paginate.return_value = [{"Members": []}]

    # Products paginator mock
    products_paginator = MagicMock()
    products_paginator.paginate.return_value = [{"ProductSubscriptions": []}]

    # Insights paginator mock
    insights_paginator = MagicMock()
    insights_paginator.paginate.return_value = [{"Insights": []}]

    def mock_get_paginator(operation_name):
        if operation_name == "get_enabled_standards":
            return standards_paginator
        elif operation_name == "get_findings":
            return findings_paginator
        elif operation_name == "list_members":
            return members_paginator
        elif operation_name == "list_enabled_products_for_import":
            return products_paginator
        elif operation_name == "get_insights":
            return insights_paginator
        return MagicMock()

    client.get_paginator.side_effect = mock_get_paginator

    # Organization config mock
    client.describe_organization_configuration.return_value = {"AutoEnable": False}

    # Direct call fallbacks
    client.list_members.return_value = {"Members": []}
    client.list_enabled_products_for_import.return_value = {"ProductSubscriptions": []}
    client.get_insights.return_value = {"Insights": []}
    client.get_findings.return_value = {
        "Findings": [
            {
                "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/001",
                "Severity": {"Label": "CRITICAL"},
                "Compliance": {"Status": "FAILED"}
            },
            {
                "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/002",
                "Severity": {"Label": "HIGH"},
                "Compliance": {"Status": "FAILED"}
            }
        ]
    }

    return session, client

@pytest.mark.asyncio
async def test_aws_securityhub_scanner_mocked_checks(mock_securityhub_session):
    session, client = mock_securityhub_session
    scanner = AWSSecurityHubScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # Verify CIS Standard check
    cis_findings = [f for f in findings if "CIS AWS Foundations Benchmark Standard Disabled" in f.title]
    assert len(cis_findings) > 0
    assert cis_findings[0].severity == Severity.HIGH

    # Verify Critical Findings check
    crit_findings = [f for f in findings if "CRITICAL Findings Detected" in f.title]
    assert len(crit_findings) > 0
    assert crit_findings[0].severity == Severity.CRITICAL

    # Verify Failed Controls check
    failed_findings = [f for f in findings if "Failed Security Controls Summary" in f.title]
    assert len(failed_findings) > 0

@pytest.mark.asyncio
async def test_risk_engine_integration_securityhub(mock_securityhub_session):
    session, client = mock_securityhub_session
    scanner = AWSSecurityHubScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.critical_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_securityhub():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "securityhub"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
