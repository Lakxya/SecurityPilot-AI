import pytest
import json
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.ecr import AWSECRScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_ecr_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # Registry scanning config mock
    client.get_registry_scanning_configuration.return_value = {
        "scanningConfiguration": {
            "scanType": "BASIC",
            "rules": []
        }
    }

    # Repository paginator mock
    repo_paginator = MagicMock()
    repo_paginator.paginate.return_value = [
        {
            "repositories": [
                {
                    "repositoryName": "app-repo",
                    "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/app-repo",
                    "imageScanningConfiguration": {"scanOnPush": False},
                    "imageTagMutability": "MUTABLE",
                    "encryptionConfiguration": {"encryptionType": "AES256"}
                }
            ]
        }
    ]

    # Image paginator mock
    image_paginator = MagicMock()
    image_paginator.paginate.return_value = [
        {
            "imageDetails": [
                {
                    "imageDigest": "sha256:1234567890abcdef",
                    "imageTags": [],
                    "imageScanFindingsSummary": {
                        "findingSeverityCounts": {
                            "CRITICAL": 2,
                            "HIGH": 5
                        }
                    }
                }
            ]
        }
    ]

    def mock_get_paginator(operation_name):
        if operation_name == "describe_repositories":
            return repo_paginator
        elif operation_name == "describe_images":
            return image_paginator
        return MagicMock()

    client.get_paginator.side_effect = mock_get_paginator

    # Repository policy mock (allows public)
    client.get_repository_policy.return_value = {
        "policyText": json.dumps({
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "ecr:GetDownloadUrlForLayer"
                }
            ]
        })
    }

    # Lifecycle policy mock (missing)
    client.get_lifecycle_policy.side_effect = Exception("LifecyclePolicyNotFoundException")

    return session, client

@pytest.mark.asyncio
async def test_aws_ecr_scanner_mocked_checks(mock_ecr_session):
    session, client = mock_ecr_session
    scanner = AWSECRScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # Verify Scan On Push Disabled check
    scan_findings = [f for f in findings if "Scan On Push Disabled" in f.title]
    assert len(scan_findings) > 0
    assert scan_findings[0].severity == Severity.HIGH

    # Verify Public Access Policy check
    public_findings = [f for f in findings if "Allows Public Access" in f.title]
    assert len(public_findings) > 0
    assert public_findings[0].severity == Severity.CRITICAL

    # Verify Critical Vulnerabilities check
    crit_findings = [f for f in findings if "CRITICAL Image Vulnerabilities" in f.title]
    assert len(crit_findings) > 0
    assert crit_findings[0].severity == Severity.CRITICAL

@pytest.mark.asyncio
async def test_risk_engine_integration_ecr(mock_ecr_session):
    session, client = mock_ecr_session
    scanner = AWSECRScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.critical_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_ecr():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "ecr"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
