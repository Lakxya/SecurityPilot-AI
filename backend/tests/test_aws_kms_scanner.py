import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.kms import AWSKMSScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_kms_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # List keys paginator mock
    keys_paginator = MagicMock()
    keys_paginator.paginate.return_value = [
        {
            "Keys": [
                {"KeyId": "key-0123456789abcdef0", "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-0123456789abcdef0"}
            ]
        }
    ]

    # List aliases paginator mock
    aliases_paginator = MagicMock()
    aliases_paginator.paginate.return_value = [
        {
            "Aliases": [
                {"AliasName": "alias/app-key", "TargetKeyId": "key-0123456789abcdef0"}
            ]
        }
    ]

    def mock_get_paginator(operation_name):
        if operation_name == "list_keys":
            return keys_paginator
        if operation_name == "list_aliases":
            return aliases_paginator
        return MagicMock()

    client.get_paginator.side_effect = mock_get_paginator

    # Describe key mock
    client.describe_key.return_value = {
        "KeyMetadata": {
            "KeyId": "key-0123456789abcdef0",
            "Arn": "arn:aws:kms:us-east-1:123456789012:key/key-0123456789abcdef0",
            "KeyManager": "CUSTOMER",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeySpec": "SYMMETRIC_DEFAULT",
            "MultiRegion": False,
        }
    }

    # Key rotation status mock
    client.get_key_rotation_status.return_value = {"KeyRotationEnabled": False}

    # Key policy mock
    client.get_key_policy.return_value = {
        "Policy": '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "kms:*"}]}'
    }

    return session, client

@pytest.mark.asyncio
async def test_aws_kms_scanner_mocked_checks(mock_kms_session):
    session, client = mock_kms_session
    scanner = AWSKMSScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # Verify Rotation check
    rot_findings = [f for f in findings if "Annual Auto-Rotation Disabled" in f.title]
    assert len(rot_findings) > 0
    assert rot_findings[0].severity == Severity.MEDIUM

    # Verify Wildcard Policy check
    policy_findings = [f for f in findings if "Wildcard Principal Access" in f.title]
    assert len(policy_findings) > 0
    assert policy_findings[0].severity == Severity.CRITICAL

    # Verify Inventory check
    inv_findings = [f for f in findings if "Inventory" in f.title]
    assert len(inv_findings) > 0
    assert inv_findings[0].severity == Severity.INFO

@pytest.mark.asyncio
async def test_risk_engine_integration_kms(mock_kms_session):
    session, client = mock_kms_session
    scanner = AWSKMSScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.critical_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_kms():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "kms"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
