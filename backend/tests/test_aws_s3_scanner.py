import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.s3 import AWSS3Scanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_s3_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # Setup list_buckets
    client.list_buckets.return_value = {
        "Buckets": [
            {"Name": "test-sec-bucket-1"},
            {"Name": "test-sec-bucket-2"},
        ]
    }

    # Helper to get bucket argument from call
    def _get_b(args, kwargs):
        if "Bucket" in kwargs:
            return kwargs["Bucket"]
        if args:
            return args[0]
        return None

    # Public access block setup (disabled on bucket 1)
    def mock_public_block(*args, **kwargs):
        b = _get_b(args, kwargs)
        if b == "test-sec-bucket-1":
            return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}}
        return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}
    client.get_public_access_block.side_effect = mock_public_block

    # ACL setup (public on bucket 1)
    def mock_acl(*args, **kwargs):
        b = _get_b(args, kwargs)
        if b == "test-sec-bucket-1":
            return {"Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]}
        return {"Grants": []}
    client.get_bucket_acl.side_effect = mock_acl

    # Policy setup (wildcard on bucket 1)
    def mock_policy(*args, **kwargs):
        b = _get_b(args, kwargs)
        if b == "test-sec-bucket-1":
            return {"Policy": '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}'}
        return {"Policy": "{}"}
    client.get_bucket_policy.side_effect = mock_policy

    # Encryption setup (none on bucket 1, AES256 on bucket 2)
    def mock_enc(*args, **kwargs):
        b = _get_b(args, kwargs)
        if b == "test-sec-bucket-1":
            return {"ServerSideEncryptionConfiguration": {"Rules": []}}
        return {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}
    client.get_bucket_encryption.side_effect = mock_enc

    # Versioning setup
    def mock_ver(*args, **kwargs):
        b = _get_b(args, kwargs)
        if b == "test-sec-bucket-1":
            return {"Status": "Disabled"}
        return {"Status": "Enabled"}
    client.get_bucket_versioning.side_effect = mock_ver

    # Logging setup
    def mock_log(*args, **kwargs):
        b = _get_b(args, kwargs)
        if b == "test-sec-bucket-1":
            return {}
        return {"LoggingEnabled": {"TargetBucket": "logs", "TargetPrefix": "s3/"}}
    client.get_bucket_logging.side_effect = mock_log

    # Ownership controls
    client.get_bucket_ownership_controls.return_value = {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}}

    # Tagging
    client.get_bucket_tagging.return_value = {"TagSet": [{"Key": "Environment", "Value": "Prod"}]}

    # Lifecycle
    client.get_bucket_lifecycle_configuration.return_value = {"Rules": []}

    # Location
    client.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}

    return session, client

@pytest.mark.asyncio
async def test_aws_s3_scanner_mocked_checks(mock_s3_session):
    session, client = mock_s3_session
    scanner = AWSS3Scanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # Verify Public Access Block check
    public_block = [f for f in findings if "Block Public Access" in f.title]
    assert len(public_block) > 0
    assert public_block[0].severity in [Severity.HIGH, Severity.CRITICAL]

    # Verify ACL check
    acl_findings = [f for f in findings if "ACL Grants Public Access" in f.title]
    assert len(acl_findings) > 0
    assert acl_findings[0].severity == Severity.CRITICAL

    # Verify Policy Wildcard check
    policy_findings = [f for f in findings if "Wildcard Principal" in f.title]
    assert len(policy_findings) > 0

    # Verify Encryption check
    enc_findings = [f for f in findings if "Encryption" in f.title]
    assert len(enc_findings) > 0

@pytest.mark.asyncio
async def test_risk_engine_integration_s3(mock_s3_session):
    session, client = mock_s3_session
    scanner = AWSS3Scanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.critical_count >= 1
    assert report.risk_summary.high_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_s3():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "s3"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
