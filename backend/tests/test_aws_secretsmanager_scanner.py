import pytest
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.secretsmanager import AWSSecretsManagerScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_secretsmanager_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # 100-day old timestamp
    old_date = datetime.now(timezone.utc) - timedelta(days=100)

    # List secrets paginator mock
    secrets_paginator = MagicMock()
    secrets_paginator.paginate.return_value = [
        {
            "SecretList": [
                {
                    "Name": "prod-db-password",
                    "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-db-password",
                    "RotationEnabled": False,
                    "LastRotatedDate": old_date,
                    "KmsKeyId": "aws/secretsmanager",
                    "Tags": [{"Key": "Environment", "Value": "Production"}]
                },
                {
                    "Name": "api-key-staging",
                    "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:api-key-staging",
                    "RotationEnabled": True,
                    "DeletedDate": old_date,
                    "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/custom-cmk"
                }
            ]
        }
    ]

    # Secret version ids paginator mock
    version_paginator = MagicMock()
    version_paginator.paginate.return_value = [
        {"Versions": [{"VersionId": f"v-{i}"} for i in range(25)]}
    ]

    def mock_get_paginator(operation_name):
        if operation_name == "list_secrets":
            return secrets_paginator
        elif operation_name == "list_secret_version_ids":
            return version_paginator
        return MagicMock()

    client.get_paginator.side_effect = mock_get_paginator

    # Resource policy mock (public principal wildcard)
    def mock_get_resource_policy(SecretId):
        if SecretId == "prod-db-password":
            return {
                "ResourcePolicy": json.dumps({
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "secretsmanager:GetSecretValue"
                        }
                    ]
                })
            }
        return {"ResourcePolicy": "{}"}

    client.get_resource_policy.side_effect = mock_get_resource_policy

    return session, client

@pytest.mark.asyncio
async def test_aws_secretsmanager_scanner_mocked_checks(mock_secretsmanager_session):
    session, client = mock_secretsmanager_session
    scanner = AWSSecretsManagerScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # CRITICAL SECURITY CHECK: Assert payload access APIs were NEVER invoked
    client.get_secret_value.assert_not_called()
    if hasattr(client, "batch_get_secret_value"):
        client.batch_get_secret_value.assert_not_called()

    # Verify Rotation Disabled check
    rot_findings = [f for f in findings if "Automatic Rotation Disabled" in f.title]
    assert len(rot_findings) > 0
    assert rot_findings[0].severity == Severity.HIGH

    # Verify Public Access Resource Policy check
    pub_findings = [f for f in findings if "Allows Public Access" in f.title]
    assert len(pub_findings) > 0
    assert pub_findings[0].severity == Severity.CRITICAL

    # Verify Scheduled Deletion check
    del_findings = [f for f in findings if "Scheduled For Permanent Deletion" in f.title]
    assert len(del_findings) > 0

    # Verify Default KMS Key check
    key_findings = [f for f in findings if "Default AWS Key" in f.title]
    assert len(key_findings) > 0
    assert key_findings[0].severity == Severity.MEDIUM

@pytest.mark.asyncio
async def test_secret_payload_protection_guarantee(mock_secretsmanager_session):
    session, client = mock_secretsmanager_session
    scanner = AWSSecretsManagerScanner(session=session)
    findings = await scanner.scan()

    # Ensure no secret payload references exist in finding descriptions or remediations
    for f in findings:
        assert "SecretString" not in f.description
        assert "SecretBinary" not in f.description
        assert "SecretString" not in f.remediation

    # Ensure get_secret_value was never called
    client.get_secret_value.assert_not_called()

@pytest.mark.asyncio
async def test_secretsmanager_exception_isolation(mock_secretsmanager_session):
    session, client = mock_secretsmanager_session

    # Simulate get_resource_policy throwing AccessDenied on first call
    client.get_resource_policy.side_effect = Exception("AccessDeniedException: User is not authorized")
    scanner = AWSSecretsManagerScanner(session=session)

    findings = await scanner.scan()
    # Scan must succeed gracefully without raising exception
    assert isinstance(findings, list)
    client.get_secret_value.assert_not_called()

@pytest.mark.asyncio
async def test_risk_engine_integration_secretsmanager(mock_secretsmanager_session):
    session, client = mock_secretsmanager_session
    scanner = AWSSecretsManagerScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.critical_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_secretsmanager():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "secretsmanager"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
