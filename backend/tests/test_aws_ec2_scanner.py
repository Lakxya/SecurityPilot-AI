import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.ec2 import AWSEC2Scanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_ec2_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # Security Groups mock
    client.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-0123456789abcdef0",
                "GroupName": "open-sg",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 3389,
                        "ToPort": 3389,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    },
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    }
                ]
            }
        ]
    }

    # Describe instances paginator mock
    inst_paginator = MagicMock()
    inst_paginator.paginate.return_value = [
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-0123456789abcdef0",
                            "State": {"Name": "running"},
                            "PublicIpAddress": "54.210.12.34",
                            "MetadataOptions": {"HttpTokens": "optional"},
                            "IamInstanceProfile": None,
                            "Monitoring": {"State": "disabled"},
                            "Tags": [{"Key": "Name", "Value": "web-server"}]
                        }
                    ]
                }
            ]
        }
    ]

    # Describe volumes paginator mock
    vol_paginator = MagicMock()
    vol_paginator.paginate.return_value = [
        {
            "Volumes": [
                {
                    "VolumeId": "vol-0123456789abcdef0",
                    "Encrypted": False,
                    "State": "available",
                    "Attachments": []
                }
            ]
        }
    ]

    def mock_get_paginator(operation_name):
        if operation_name == "describe_instances":
            return inst_paginator
        if operation_name == "describe_volumes":
            return vol_paginator
        return MagicMock()

    client.get_paginator.side_effect = mock_get_paginator

    return session, client

@pytest.mark.asyncio
async def test_aws_ec2_scanner_mocked_checks(mock_ec2_session):
    session, client = mock_ec2_session
    scanner = AWSEC2Scanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # Verify SSH 22 check
    ssh_findings = [f for f in findings if "SSH Port 22" in f.title]
    assert len(ssh_findings) > 0
    assert ssh_findings[0].severity == Severity.HIGH

    # Verify RDP 3389 check
    rdp_findings = [f for f in findings if "RDP Port 3389" in f.title]
    assert len(rdp_findings) > 0

    # Verify Unrestricted ALL traffic check
    all_findings = [f for f in findings if "Unrestricted ALL Traffic" in f.title]
    assert len(all_findings) > 0
    assert all_findings[0].severity == Severity.CRITICAL

    # Verify IMDSv2 check
    imds_findings = [f for f in findings if "IMDSv2 Not Enforced" in f.title]
    assert len(imds_findings) > 0

    # Verify EBS encryption check
    ebs_findings = [f for f in findings if "EBS Volume" in f.title and "Unencrypted" in f.title]
    assert len(ebs_findings) > 0

@pytest.mark.asyncio
async def test_risk_engine_integration_ec2(mock_ec2_session):
    session, client = mock_ec2_session
    scanner = AWSEC2Scanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.critical_count >= 1
    assert report.risk_summary.high_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_ec2():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "ec2"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
