import pytest
from unittest.mock import MagicMock
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.iam import AWSIAMScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_boto_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # Setup standard paginator for list_users
    paginator = MagicMock()
    paginator.paginate.return_value = [{
        "Users": [
            {
                "UserName": "test-user-admin",
                "Arn": "arn:aws:iam::123456789012:user/test-user-admin",
                "PasswordLastUsed": datetime.now(timezone.utc) - timedelta(days=100),
            },
            {
                "UserName": "test-user-mfa",
                "Arn": "arn:aws:iam::123456789012:user/test-user-mfa",
            }
        ]
    }]
    client.get_paginator.return_value = paginator

    # MFA devices setup
    client.list_mfa_devices.side_effect = lambda UserName: (
        {"MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/test-user-admin"}]}
        if UserName == "test-user-admin"
        else {"MFADevices": []}
    )

    # Attached user policies setup
    client.list_attached_user_policies.side_effect = lambda UserName: (
        {"AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}
        if UserName == "test-user-admin"
        else {"AttachedPolicies": []}
    )

    # Access keys setup
    old_date = datetime.now(timezone.utc) - timedelta(days=120)
    client.list_access_keys.side_effect = lambda UserName: (
        {"AccessKeyMetadata": [{"AccessKeyId": "AKIA123456789OLD", "CreateDate": old_date, "Status": "Active"}]}
        if UserName == "test-user-admin"
        else {"AccessKeyMetadata": []}
    )

    # Account summary setup
    client.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}

    # Password policy setup (weak)
    client.get_account_password_policy.return_value = {
        "PasswordPolicy": {
            "MinimumPasswordLength": 8,
            "RequireSymbols": False,
            "RequireNumbers": True,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "ExpirePasswords": False,
        }
    }

    # Inline policies setup
    client.list_user_policies.return_value = {"PolicyNames": []}

    # Login profile setup
    client.get_login_profile.return_value = {"LoginProfile": {"UserName": "test-user-admin"}}

    return session, client

@pytest.mark.asyncio
async def test_aws_iam_scanner_mocked_checks(mock_boto_session):
    session, client = mock_boto_session
    scanner = AWSIAMScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # Verify MFA check
    mfa_findings = [f for f in findings if "MFA" in f.title]
    assert len(mfa_findings) > 0
    assert mfa_findings[0].severity == Severity.HIGH
    assert mfa_findings[0].cvss == 8.8

    # Verify Admin check
    admin_findings = [f for f in findings if "AdministratorAccess" in f.title]
    assert len(admin_findings) > 0
    assert admin_findings[0].severity == Severity.CRITICAL
    assert admin_findings[0].cvss == 9.4

    # Verify Key Age check
    key_findings = [f for f in findings if "Older Than 90 Days" in f.title]
    assert len(key_findings) > 0
    assert key_findings[0].severity == Severity.HIGH

    # Verify Password Policy check
    pass_findings = [f for f in findings if "Password Policy" in f.title]
    assert len(pass_findings) > 0
    assert pass_findings[0].severity == Severity.MEDIUM

@pytest.mark.asyncio
async def test_risk_engine_integration_iam(mock_boto_session):
    session, client = mock_boto_session
    scanner = AWSIAMScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.critical_count >= 1
    assert report.risk_summary.high_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_iam():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "iam"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
