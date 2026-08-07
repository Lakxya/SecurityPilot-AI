import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.config import AWSConfigScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_config_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # Describe configuration recorders mock
    client.describe_configuration_recorders.return_value = {
        "ConfigurationRecorders": [
            {
                "name": "default",
                "roleARN": "arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
                "recordingGroup": {
                    "allSupported": False,
                    "includeGlobalResourceTypes": False,
                    "resourceTypes": ["AWS::EC2::Instance"]
                }
            }
        ]
    }

    # Describe configuration recorder status mock
    client.describe_configuration_recorder_status.return_value = {
        "ConfigurationRecordersStatus": [
            {
                "name": "default",
                "recording": False,
                "lastStatus": "SUCCESS"
            }
        ]
    }

    # Describe delivery channels mock
    client.describe_delivery_channels.return_value = {
        "DeliveryChannels": [
            {
                "name": "default",
                "s3BucketName": "my-config-logs-bucket",
                "snsTopicARN": None,
                "configSnapshotDeliveryProperties": {
                    "deliveryFrequency": "TwentyFour_Hours"
                }
            }
        ]
    }

    # Describe config rules mock
    client.describe_config_rules.return_value = {
        "ConfigRules": [
            {
                "ConfigRuleName": "s3-bucket-public-read-prohibited",
                "ConfigRuleArn": "arn:aws:config:us-east-1:123456789012:config-rule/s3-bucket-public-read-prohibited",
                "ConfigRuleState": "ACTIVE"
            }
        ]
    }

    # Describe conformance packs mock
    client.describe_conformance_packs.return_value = {"ConformancePackDetails": []}

    # Describe aggregators mock
    client.describe_configuration_aggregators.return_value = {"ConfigurationAggregators": []}

    return session, client

@pytest.mark.asyncio
async def test_aws_config_scanner_mocked_checks(mock_config_session):
    session, client = mock_config_session
    scanner = AWSConfigScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # Verify Stopped Recorder check
    stopped_findings = [f for f in findings if "Recording Stopped" in f.title]
    assert len(stopped_findings) > 0
    assert stopped_findings[0].severity == Severity.CRITICAL

    # Verify Global Resource check
    global_findings = [f for f in findings if "Global Resource Recording Disabled" in f.title]
    assert len(global_findings) > 0
    assert global_findings[0].severity == Severity.HIGH

    # Verify SNS Missing check
    sns_findings = [f for f in findings if "Missing SNS Notification Topic" in f.title]
    assert len(sns_findings) > 0
    assert sns_findings[0].severity == Severity.MEDIUM

    # Verify Aggregator Missing check
    agg_findings = [f for f in findings if "Aggregator Missing" in f.title]
    assert len(agg_findings) > 0

@pytest.mark.asyncio
async def test_risk_engine_integration_config(mock_config_session):
    session, client = mock_config_session
    scanner = AWSConfigScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.critical_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_config():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "config"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
