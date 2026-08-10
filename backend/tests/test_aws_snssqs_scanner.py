import json
import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.snssqs import AWSSNSQSScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_snssqs_session():
    session = MagicMock()
    sns_client = MagicMock()
    sqs_client = MagicMock()

    def side_effect_client(service_name):
        if service_name == "sns":
            return sns_client
        elif service_name == "sqs":
            return sqs_client
        return MagicMock()

    session.client.side_effect = side_effect_client

    # SNS List Topics mock
    sns_paginator = MagicMock()
    sns_paginator.paginate.return_value = [
        {
            "Topics": [
                {"TopicArn": "arn:aws:sns:us-east-1:123456789012:unprotected-topic"},
                {"TopicArn": "arn:aws:sns:us-east-1:123456789012:secure-topic"}
            ]
        }
    ]
    sns_client.get_paginator.return_value = sns_paginator

    # SQS List Queues mock
    sqs_paginator = MagicMock()
    sqs_paginator.paginate.return_value = [
        {
            "QueueUrls": [
                "https://sqs.us-east-1.amazonaws.com/123456789012/unprotected-queue",
                "https://sqs.us-east-1.amazonaws.com/123456789012/secure-queue"
            ]
        }
    ]
    sqs_client.get_paginator.return_value = sqs_paginator

    # SNS Topic Attributes mock
    def mock_get_topic_attributes(TopicArn):
        if "unprotected-topic" in TopicArn:
            return {
                "Attributes": {
                    "Policy": json.dumps({
                        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "SNS:Publish"}]
                    }),
                    "KmsMasterKeyId": ""
                }
            }
        elif "secure-topic" in TopicArn:
            return {
                "Attributes": {
                    "Policy": json.dumps({
                        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "SNS:Publish"}]
                    }),
                    "KmsMasterKeyId": "arn:aws:kms:us-east-1:123456789012:key/custom-sns-cmk"
                }
            }
        return {"Attributes": {}}

    sns_client.get_topic_attributes.side_effect = mock_get_topic_attributes

    # SNS Subscriptions mock
    def mock_list_subscriptions(TopicArn):
        if "unprotected-topic" in TopicArn:
            return {"Subscriptions": [{"Protocol": "http", "SubscriptionArn": "arn:aws:sns:...:sub1"}]}
        return {"Subscriptions": [{"Protocol": "https", "SubscriptionArn": "arn:aws:sns:...:sub2"}]}

    sns_client.list_subscriptions_by_topic.side_effect = mock_list_subscriptions

    # SQS Queue Attributes mock
    def mock_get_queue_attributes(QueueUrl, AttributeNames):
        if "unprotected-queue" in QueueUrl:
            return {
                "Attributes": {
                    "Policy": json.dumps({
                        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "SQS:SendMessage"}]
                    }),
                    "KmsMasterKeyId": "",
                    "SqsManagedSseEnabled": "false",
                    "RedrivePolicy": ""
                }
            }
        elif "secure-queue" in QueueUrl:
            return {
                "Attributes": {
                    "Policy": json.dumps({
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "SQS:*"},
                            {"Effect": "Deny", "Principal": "*", "Action": "SQS:*", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
                        ]
                    }),
                    "KmsMasterKeyId": "arn:aws:kms:us-east-1:123456789012:key/custom-sqs-cmk",
                    "SqsManagedSseEnabled": "true",
                    "RedrivePolicy": json.dumps({"deadLetterTargetArn": "arn:aws:sqs:...:dlq", "maxReceiveCount": "5"})
                }
            }
        return {"Attributes": {}}

    sqs_client.get_queue_attributes.side_effect = mock_get_queue_attributes

    # SNS Tags mock
    def mock_sns_tags(ResourceArn):
        if "secure-topic" in ResourceArn:
            return {"Tags": [{"Key": "Environment", "Value": "Production"}, {"Key": "Owner", "Value": "SecOps"}, {"Key": "Classification", "Value": "Restricted"}]}
        return {"Tags": []}

    sns_client.list_tags_for_resource.side_effect = mock_sns_tags

    # SQS Tags mock
    def mock_sqs_tags(QueueUrl):
        if "secure-queue" in QueueUrl:
            return {"Tags": {"Environment": "Production", "Owner": "SecOps", "Classification": "Restricted"}}
        return {"Tags": {}}

    sqs_client.list_queue_tags.side_effect = mock_sqs_tags

    return session, sns_client, sqs_client

@pytest.mark.asyncio
async def test_aws_snssqs_scanner_mocked_checks(mock_snssqs_session):
    session, sns_client, sqs_client = mock_snssqs_session
    scanner = AWSSNSQSScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # CRITICAL MUTATION & MESSAGE DATA ACCESS SAFETY ASSERTIONS
    forbidden_sns_methods = [
        "create_topic", "delete_topic", "publish", "subscribe", "unsubscribe",
        "set_topic_attributes", "tag_resource", "untag_resource"
    ]
    for method_name in forbidden_sns_methods:
        if hasattr(sns_client, method_name):
            getattr(sns_client, method_name).assert_not_called()

    forbidden_sqs_methods = [
        "create_queue", "delete_queue", "send_message", "send_message_batch",
        "receive_message", "delete_message", "purge_queue", "set_queue_attributes",
        "tag_queue", "untag_queue"
    ]
    for method_name in forbidden_sqs_methods:
        if hasattr(sqs_client, method_name):
            getattr(sqs_client, method_name).assert_not_called()

    # 1. Public SNS Topic Policy (unprotected-topic) vs Restricted (secure-topic)
    sns_policy_findings = [f for f in findings if "SNS Topic 'unprotected-topic' Access Policy Permits Public Access" in f.title]
    assert len(sns_policy_findings) == 1
    assert sns_policy_findings[0].severity == Severity.HIGH

    # 2. Public SQS Queue Policy (unprotected-queue) vs Restricted (secure-queue)
    sqs_policy_findings = [f for f in findings if "SQS Queue 'unprotected-queue' Access Policy Permits Public Access" in f.title]
    assert len(sqs_policy_findings) == 1
    assert sqs_policy_findings[0].severity == Severity.HIGH

    # 3. SQS Queue SSE Disabled (unprotected-queue) vs Enabled (secure-queue)
    sqs_sse_findings = [f for f in findings if "SQS Queue 'unprotected-queue' Server-Side Encryption (SSE) Disabled" in f.title]
    assert len(sqs_sse_findings) == 1
    assert sqs_sse_findings[0].severity == Severity.HIGH

    # 4. SNS Topic SSE Disabled (unprotected-topic) vs Enabled (secure-topic)
    sns_sse_findings = [f for f in findings if "SNS Topic 'unprotected-topic' Server-Side Encryption (KMS) Disabled" in f.title]
    assert len(sns_sse_findings) == 1
    assert sns_sse_findings[0].severity == Severity.HIGH

    # 5. SQS Queue Policy HTTPS Not Enforced (unprotected-queue) vs Enforced (secure-queue)
    sqs_http_findings = [f for f in findings if "SQS Queue 'unprotected-queue' Policy Does Not Enforce HTTPS" in f.title]
    assert len(sqs_http_findings) == 1
    assert sqs_http_findings[0].severity == Severity.HIGH

    # 6. Dead Letter Queue Recommendation Missing (unprotected-queue) vs Configured (secure-queue)
    dlq_findings = [f for f in findings if "SQS Queue 'unprotected-queue' Dead Letter Queue (DLQ) Recommendation" in f.title]
    assert len(dlq_findings) == 1
    assert dlq_findings[0].severity == Severity.MEDIUM

    # 7. Unencrypted HTTP SNS Subscription (unprotected-topic) vs HTTPS (secure-topic)
    http_sub_findings = [f for f in findings if "Has Unencrypted HTTP Endpoint Subscription" in f.title]
    assert len(http_sub_findings) == 1
    assert "unprotected-topic" in http_sub_findings[0].resource
    assert http_sub_findings[0].severity == Severity.LOW

    # 8. Missing Governance Tags (unprotected-topic & unprotected-queue) vs Tagged (secure-topic & secure-queue)
    tag_findings = [f for f in findings if "Missing Governance Tags" in f.title]
    assert len(tag_findings) == 2
    assert not any("secure-topic" in f.resource for f in tag_findings)
    assert not any("secure-queue" in f.resource for f in tag_findings)

@pytest.mark.asyncio
async def test_snssqs_empty_account():
    session = MagicMock()
    sns_client = MagicMock()
    sqs_client = MagicMock()

    def side_effect_client(service_name):
        if service_name == "sns":
            return sns_client
        elif service_name == "sqs":
            return sqs_client
        return MagicMock()

    session.client.side_effect = side_effect_client

    sns_paginator = MagicMock()
    sns_paginator.paginate.return_value = [{"Topics": []}]
    sns_client.get_paginator.return_value = sns_paginator

    sqs_paginator = MagicMock()
    sqs_paginator.paginate.return_value = [{"QueueUrls": []}]
    sqs_client.get_paginator.return_value = sqs_paginator

    scanner = AWSSNSQSScanner(session=session)
    findings = await scanner.scan()

    assert len(findings) == 1
    assert "0 Topics/Queues Deployed" in findings[0].title
    assert findings[0].severity == Severity.INFO

@pytest.mark.asyncio
async def test_snssqs_exception_isolation(mock_snssqs_session):
    session, sns_client, sqs_client = mock_snssqs_session
    sqs_client.get_queue_attributes.side_effect = Exception("AccessDenied: Not authorized")

    scanner = AWSSNSQSScanner(session=session)
    findings = await scanner.scan()

    # Scan must complete cleanly despite AccessDenied exception on SQS attributes
    assert isinstance(findings, list)
    assert len(findings) > 0

@pytest.mark.asyncio
async def test_risk_engine_integration_snssqs(mock_snssqs_session):
    session, sns_client, sqs_client = mock_snssqs_session
    scanner = AWSSNSQSScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.high_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_snssqs():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "snssqs"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
