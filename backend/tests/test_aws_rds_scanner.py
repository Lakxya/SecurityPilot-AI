import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.rds import AWSRDSScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_rds_session():
    session = MagicMock()
    client = MagicMock()
    ec2_client = MagicMock()

    def get_client(service_name):
        if service_name == "rds":
            return client
        elif service_name == "ec2":
            return ec2_client
        return MagicMock()

    session.client.side_effect = get_client

    # DB Instances paginator mock
    instance_paginator = MagicMock()
    instance_paginator.paginate.return_value = [
        {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "prod-db-1",
                    "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:prod-db-1",
                    "PubliclyAccessible": True,
                    "StorageEncrypted": False,
                    "KmsKeyId": "aws/rds",
                    "BackupRetentionPeriod": 3,
                    "DeletionProtection": False,
                    "MultiAZ": False,
                    "MonitoringInterval": 0,
                    "PerformanceInsightsEnabled": False,
                    "EnabledCloudwatchLogsExports": [],
                    "IAMDatabaseAuthenticationEnabled": False,
                    "AutoMinorVersionUpgrade": False,
                    "Engine": "postgres",
                    "EngineVersion": "9.6.1",
                    "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-12345"}],
                    "Endpoint": {"Port": 5432}
                },
                {
                    "DBInstanceIdentifier": "oracle-db-2",
                    "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:oracle-db-2",
                    "PubliclyAccessible": False,
                    "StorageEncrypted": True,
                    "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/custom-cmk",
                    "BackupRetentionPeriod": 14,
                    "DeletionProtection": True,
                    "MultiAZ": True,
                    "MonitoringInterval": 60,
                    "PerformanceInsightsEnabled": True,
                    "EnabledCloudwatchLogsExports": ["alert", "audit"],
                    "IAMDatabaseAuthenticationEnabled": False,
                    "AutoMinorVersionUpgrade": True,
                    "Engine": "oracle-ee",
                    "EngineVersion": "19.0",
                    "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-secure"}],
                    "Endpoint": {"Port": 1521}
                }
            ]
        }
    ]

    # DB Clusters paginator mock
    cluster_paginator = MagicMock()
    cluster_paginator.paginate.return_value = [
        {
            "DBClusters": [
                {
                    "DBClusterIdentifier": "aurora-prod-cluster",
                    "DBClusterArn": "arn:aws:rds:us-east-1:123456789012:cluster:aurora-prod-cluster",
                    "PubliclyAccessible": True,
                    "StorageEncrypted": True,
                    "KmsKeyId": "aws/rds",
                    "BackupRetentionPeriod": 1,
                    "DeletionProtection": False,
                    "EnabledCloudwatchLogsExports": [],
                    "IAMDatabaseAuthenticationEnabled": False
                }
            ]
        }
    ]

    def mock_get_paginator(operation_name):
        if operation_name == "describe_db_instances":
            return instance_paginator
        elif operation_name == "describe_db_clusters":
            return cluster_paginator
        return MagicMock()

    client.get_paginator.side_effect = mock_get_paginator

    # Security Group describe mock for EC2
    ec2_client.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-12345",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 5432,
                        "ToPort": 5432,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    }
                ]
            },
            {
                "GroupId": "sg-secure",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 1521,
                        "ToPort": 1521,
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}]
                    }
                ]
            }
        ]
    }

    # Tag list mock
    client.list_tags_for_resource.return_value = {"TagList": []}

    return session, client, ec2_client

@pytest.mark.asyncio
async def test_aws_rds_scanner_mocked_checks(mock_rds_session):
    session, client, ec2_client = mock_rds_session
    scanner = AWSRDSScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # CRITICAL SECURITY CHECK: Assert mutation APIs were NEVER invoked
    if hasattr(client, "modify_db_instance"):
        client.modify_db_instance.assert_not_called()
    if hasattr(client, "delete_db_instance"):
        client.delete_db_instance.assert_not_called()

    # Verify Unrestricted Port Ingress check
    open_port_findings = [f for f in findings if "Permits Unrestricted Public Ingress" in f.title]
    assert len(open_port_findings) > 0
    assert open_port_findings[0].severity == Severity.CRITICAL

    # Verify Public Instance context check
    pub_findings = [f for f in findings if "Publicly Accessible (Public IP Assigned)" in f.title]
    assert len(pub_findings) >= 1
    assert pub_findings[0].severity == Severity.HIGH

    # Verify Storage Encryption check
    enc_findings = [f for f in findings if "Storage Encryption Disabled" in f.title]
    assert len(enc_findings) >= 1
    assert enc_findings[0].severity == Severity.HIGH

    # Verify IAM Auth supported engine check (postgres flags IAM auth)
    iam_findings = [f for f in findings if "IAM Database Authentication Optional Control Disabled" in f.title]
    assert len(iam_findings) == 1
    assert "prod-db-1" in iam_findings[0].resource
    # Verify Oracle (unsupported engine) does NOT generate IAM Auth finding
    assert not any("oracle-db-2" in f.resource for f in iam_findings)

    # Verify Customer KMS CMK recommendation check
    km_findings = [f for f in findings if "Customer-Managed KMS Key" in f.title]
    assert len(km_findings) > 0
    assert km_findings[0].severity == Severity.LOW

@pytest.mark.asyncio
async def test_rds_payload_and_mutation_safety(mock_rds_session):
    session, client, ec2_client = mock_rds_session
    scanner = AWSRDSScanner(session=session)
    findings = await scanner.scan()

    for f in findings:
        # Guarantee no passwords or master credentials exist in finding payload
        assert "MasterUserPassword" not in f.description
        assert "MasterUserPassword" not in f.remediation

@pytest.mark.asyncio
async def test_rds_exception_isolation(mock_rds_session):
    session, client, ec2_client = mock_rds_session
    client.list_tags_for_resource.side_effect = Exception("AccessDenied: Not authorized to list tags")

    scanner = AWSRDSScanner(session=session)
    findings = await scanner.scan()

    # Scan must complete cleanly despite tag list exception
    assert isinstance(findings, list)

@pytest.mark.asyncio
async def test_risk_engine_integration_rds(mock_rds_session):
    session, client, ec2_client = mock_rds_session
    scanner = AWSRDSScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.critical_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_rds():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "rds"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
