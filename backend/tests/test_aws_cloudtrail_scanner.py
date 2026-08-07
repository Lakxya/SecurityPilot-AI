import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.cloudtrail import AWSCloudTrailScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_cloudtrail_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # Describe trails mock
    client.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "main-audit-trail",
                "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/main-audit-trail",
                "HomeRegion": "us-east-1",
                "IsMultiRegionTrail": False,
                "LogFileValidationEnabled": False,
                "KmsKeyId": None,
                "CloudWatchLogsLogGroupArn": None,
                "SnsTopicARN": None,
                "IsOrganizationTrail": False,
            }
        ]
    }

    # Get trail status mock
    client.get_trail_status.return_value = {"IsLogging": True}

    # Get event selectors mock
    client.get_event_selectors.return_value = {
        "EventSelectors": [
            {
                "ReadWriteType": "All",
                "IncludeManagementEvents": True,
                "DataResources": []
            }
        ]
    }

    # Get insight selectors mock
    client.get_insight_selectors.return_value = {"InsightSelectors": []}

    return session, client

@pytest.mark.asyncio
async def test_aws_cloudtrail_scanner_mocked_checks(mock_cloudtrail_session):
    session, client = mock_cloudtrail_session
    scanner = AWSCloudTrailScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # Verify Log File Validation check
    val_findings = [f for f in findings if "Integrity Validation Disabled" in f.title]
    assert len(val_findings) > 0
    assert val_findings[0].severity == Severity.HIGH

    # Verify Multi-Region check
    multi_findings = [f for f in findings if "Not Configured for Multi-Region" in f.title]
    assert len(multi_findings) > 0

    # Verify KMS check
    kms_findings = [f for f in findings if "Encrypted Without KMS" in f.title]
    assert len(kms_findings) > 0

    # Verify CloudWatch Logs check
    cw_findings = [f for f in findings if "CloudWatch Logs Integration Missing" in f.title]
    assert len(cw_findings) > 0
    assert cw_findings[0].severity == Severity.MEDIUM

@pytest.mark.asyncio
async def test_risk_engine_integration_cloudtrail(mock_cloudtrail_session):
    session, client = mock_cloudtrail_session
    scanner = AWSCloudTrailScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.high_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_cloudtrail():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "cloudtrail"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
