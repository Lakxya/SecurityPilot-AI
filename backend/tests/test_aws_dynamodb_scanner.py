import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.dynamodb import AWSDynamoDBScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_dynamodb_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # List tables paginator mock
    table_paginator = MagicMock()
    table_paginator.paginate.return_value = [
        {"TableNames": ["users-table", "secure-orders-table"]}
    ]

    def mock_get_paginator(operation_name):
        if operation_name == "list_tables":
            return table_paginator
        return MagicMock()

    client.get_paginator.side_effect = mock_get_paginator

    # Describe table mock
    def mock_describe_table(TableName):
        if TableName == "users-table":
            return {
                "Table": {
                    "TableName": "users-table",
                    "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/users-table",
                    "DeletionProtectionEnabled": False,
                    "BillingModeSummary": {"BillingMode": "PROVISIONED"},
                    "SSEDescription": {"Status": "ENABLED", "KMSMasterKeyArn": "aws/dynamodb"}
                }
            }
        elif TableName == "secure-orders-table":
            return {
                "Table": {
                    "TableName": "secure-orders-table",
                    "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/secure-orders-table",
                    "DeletionProtectionEnabled": True,
                    "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
                    "SSEDescription": {"Status": "ENABLED", "KMSMasterKeyArn": "arn:aws:kms:us-east-1:123456789012:key/custom-cmk"},
                    "Replicas": [{"RegionName": "eu-west-1"}, {"RegionName": "ap-northeast-1"}]
                }
            }
        return {}

    client.describe_table.side_effect = mock_describe_table

    # Describe continuous backups mock
    def mock_describe_continuous_backups(TableName):
        if TableName == "users-table":
            return {"ContinuousBackupsDescription": {"PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "DISABLED"}}}
        elif TableName == "secure-orders-table":
            return {"ContinuousBackupsDescription": {"PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "ENABLED"}}}
        return {}

    client.describe_continuous_backups.side_effect = mock_describe_continuous_backups

    # List tags mock
    def mock_list_tags_of_resource(ResourceArn):
        if "secure-orders-table" in ResourceArn:
            return {"Tags": [{"Key": "Environment", "Value": "Production"}, {"Key": "Owner", "Value": "DBA"}, {"Key": "Classification", "Value": "Restricted"}]}
        return {"Tags": []}

    client.list_tags_of_resource.side_effect = mock_list_tags_of_resource

    return session, client

@pytest.mark.asyncio
async def test_aws_dynamodb_scanner_mocked_checks(mock_dynamodb_session):
    session, client = mock_dynamodb_session
    scanner = AWSDynamoDBScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # CRITICAL MUTATION & DATA ACCESS API SAFETY ASSERTIONS
    forbidden_methods = [
        "create_table", "update_table", "delete_table",
        "tag_resource", "untag_resource", "put_item", "get_item", "scan", "query"
    ]
    for method_name in forbidden_methods:
        if hasattr(client, method_name):
            getattr(client, method_name).assert_not_called()

    # 1. Point-In-Time Recovery Disabled (users-table) -> MEDIUM severity (5.5)
    pitr_findings = [f for f in findings if "Point-In-Time Recovery (PITR) Disabled" in f.title]
    assert len(pitr_findings) == 1
    assert "users-table" in pitr_findings[0].resource
    assert pitr_findings[0].severity == Severity.MEDIUM
    assert pitr_findings[0].cvss == 5.5

    # 2. Deletion Protection Disabled (users-table) -> MEDIUM severity (4.5)
    del_findings = [f for f in findings if "Deletion Protection Disabled" in f.title]
    assert len(del_findings) == 1
    assert "users-table" in del_findings[0].resource
    assert del_findings[0].severity == Severity.MEDIUM
    assert del_findings[0].cvss == 4.5

    # 3. Default KMS Key Recommendation (users-table) -> LOW severity (3.5)
    kms_findings = [f for f in findings if "Customer-Managed KMS Key Governance Recommendation" in f.title]
    assert len(kms_findings) == 1
    assert "users-table" in kms_findings[0].resource
    assert kms_findings[0].severity == Severity.LOW

    # 4. Provisioned Mode Auto-Scaling Recommendation (users-table) vs PAY_PER_REQUEST (secure-orders-table - NOT flagged!)
    scale_findings = [f for f in findings if "Provisioned Capacity Auto-Scaling Recommendation" in f.title]
    assert len(scale_findings) == 1
    assert "users-table" in scale_findings[0].resource
    assert not any("secure-orders-table" in f.resource for f in scale_findings)

    # 5. Global Table Replica Summary (secure-orders-table) -> INFO severity (0.0)
    replica_findings = [f for f in findings if "Multi-Region Replicas Summary" in f.title]
    assert len(replica_findings) == 1
    assert "secure-orders-table" in replica_findings[0].resource
    assert replica_findings[0].severity == Severity.INFO
    assert replica_findings[0].cvss == 0.0

    # 6. Missing Governance Tags (users-table) vs Fully Tagged (secure-orders-table)
    tag_findings = [f for f in findings if "Missing Governance Tags" in f.title]
    assert len(tag_findings) == 1
    assert "users-table" in tag_findings[0].resource
    assert not any("secure-orders-table" in f.resource for f in tag_findings)

@pytest.mark.asyncio
async def test_dynamodb_empty_account():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    paginator = MagicMock()
    paginator.paginate.return_value = [{"TableNames": []}]
    client.get_paginator.return_value = paginator

    scanner = AWSDynamoDBScanner(session=session)
    findings = await scanner.scan()

    assert len(findings) == 1
    assert "0 Tables Deployed" in findings[0].title
    assert findings[0].severity == Severity.INFO

@pytest.mark.asyncio
async def test_dynamodb_exception_isolation(mock_dynamodb_session):
    session, client = mock_dynamodb_session
    client.describe_continuous_backups.side_effect = Exception("AccessDenied: Not authorized")

    scanner = AWSDynamoDBScanner(session=session)
    findings = await scanner.scan()

    # Scan must complete cleanly despite AccessDenied exception on backups
    assert isinstance(findings, list)
    assert len(findings) > 0

@pytest.mark.asyncio
async def test_risk_engine_integration_dynamodb(mock_dynamodb_session):
    session, client = mock_dynamodb_session
    scanner = AWSDynamoDBScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.medium_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_dynamodb():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "dynamodb"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
