import pytest
import json
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.lambda_scanner import AWSLambdaScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_lambda_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # List functions paginator mock (Page 1 and Page 2 to verify multi-page pagination)
    functions_paginator = MagicMock()
    functions_paginator.paginate.return_value = [
        {
            "Functions": [
                {
                    "FunctionName": "payment-handler",
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:payment-handler",
                    "Runtime": "python3.7",
                    "KMSKeyArn": "",
                    "VpcConfig": {},
                    "Timeout": 600,
                    "TracingConfig": {"Mode": "PassThrough"},
                    "DeadLetterConfig": {},
                    "Environment": {"Variables": {"API_KEY": "super-secret-token-12345"}}
                }
            ]
        },
        {
            "Functions": [
                {
                    "FunctionName": "secure-processor",
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:secure-processor",
                    "Runtime": "python3.12",
                    "KMSKeyArn": "arn:aws:kms:us-east-1:123456789012:key/custom-cmk",
                    "VpcConfig": {"VpcId": "vpc-12345", "SubnetIds": ["subnet-1"]},
                    "Timeout": 30,
                    "TracingConfig": {"Mode": "Active"},
                    "DeadLetterConfig": {"TargetArn": "arn:aws:sqs:us-east-1:123456789012:dlq"},
                    "SigningProfileVersionArn": "arn:aws:signer:us-east-1:123456789012:/profiles/p1"
                }
            ]
        }
    ]

    def mock_get_paginator(operation_name):
        if operation_name == "list_functions":
            return functions_paginator
        return MagicMock()

    client.get_paginator.side_effect = mock_get_paginator

    # Function URL config mock: payment-handler is unauthenticated (NONE), secure-processor is authenticated (AWS_IAM)
    def mock_list_function_url_configs(FunctionName):
        if FunctionName == "payment-handler":
            return {
                "FunctionUrlConfigs": [
                    {
                        "FunctionUrl": "https://xyz.lambda-url.us-east-1.on.aws/",
                        "AuthType": "NONE"
                    }
                ]
            }
        elif FunctionName == "secure-processor":
            return {
                "FunctionUrlConfigs": [
                    {
                        "FunctionUrl": "https://abc.lambda-url.us-east-1.on.aws/",
                        "AuthType": "AWS_IAM"
                    }
                ]
            }
        return {"FunctionUrlConfigs": []}

    client.list_function_url_configs.side_effect = mock_list_function_url_configs

    # Resource policy mock: payment-handler has wildcard Principal (*), secure-processor has restricted S3 principal
    def mock_get_policy(FunctionName):
        if FunctionName == "payment-handler":
            return {
                "Policy": json.dumps({
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "lambda:InvokeFunction"
                        }
                    ]
                })
            }
        elif FunctionName == "secure-processor":
            return {
                "Policy": json.dumps({
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "s3.amazonaws.com"},
                            "Action": "lambda:InvokeFunction",
                            "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}}
                        }
                    ]
                })
            }
        return {}

    client.get_policy.side_effect = mock_get_policy

    # List tags mock
    def mock_list_tags(Resource):
        if "secure-processor" in Resource:
            return {"Tags": {"Environment": "Production", "Owner": "SecOps", "Classification": "Restricted"}}
        return {"Tags": {}}

    client.list_tags.side_effect = mock_list_tags

    return session, client

@pytest.mark.asyncio
async def test_aws_lambda_scanner_mocked_checks(mock_lambda_session):
    session, client = mock_lambda_session
    scanner = AWSLambdaScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # CRITICAL MUTATION API SAFETY ASSERTIONS
    mutation_methods = [
        "create_function", "update_function_code", "update_function_configuration",
        "delete_function", "add_permission", "remove_permission", "publish_version",
        "update_alias", "tag_resource", "untag_resource"
    ]
    for method_name in mutation_methods:
        if hasattr(client, method_name):
            getattr(client, method_name).assert_not_called()

    # 1. Unauthenticated Public Function URL (payment-handler) vs Authenticated (secure-processor)
    url_findings = [f for f in findings if "Unauthenticated Public Function URL" in f.title]
    assert len(url_findings) == 1
    assert "payment-handler" in url_findings[0].resource
    assert not any("secure-processor" in f.resource for f in url_findings)

    # 2. Public Policy (payment-handler) vs Restricted (secure-processor)
    policy_findings = [f for f in findings if "Allows Public Access" in f.title]
    assert len(policy_findings) == 1
    assert "payment-handler" in policy_findings[0].resource
    assert not any("secure-processor" in f.resource for f in policy_findings)

    # 3. Deprecated Runtime (python3.7) vs Supported (python3.12)
    runtime_findings = [f for f in findings if "Deprecated Runtime" in f.title]
    assert len(runtime_findings) == 1
    assert "payment-handler" in runtime_findings[0].resource
    assert not any("secure-processor" in f.resource for f in runtime_findings)

    # 4. KMS CMK Recommendation (payment-handler) vs Custom CMK (secure-processor)
    kms_findings = [f for f in findings if "Customer-Managed KMS Key Governance Recommendation" in f.title]
    assert len(kms_findings) == 1
    assert "payment-handler" in kms_findings[0].resource
    assert not any("secure-processor" in f.resource for f in kms_findings)

    # 5. Missing Governance Tags (payment-handler has missing tags, secure-processor is fully tagged)
    tag_findings = [f for f in findings if "Missing Governance Tags" in f.title]
    assert len(tag_findings) == 1
    assert "payment-handler" in tag_findings[0].resource
    assert not any("secure-processor" in f.resource for f in tag_findings)

@pytest.mark.asyncio
async def test_lambda_payload_protection(mock_lambda_session):
    session, client = mock_lambda_session
    scanner = AWSLambdaScanner(session=session)
    findings = await scanner.scan()

    for f in findings:
        assert "super-secret-token-12345" not in f.description
        assert "super-secret-token-12345" not in f.remediation

@pytest.mark.asyncio
async def test_lambda_empty_account():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    paginator = MagicMock()
    paginator.paginate.return_value = [{"Functions": []}]
    client.get_paginator.return_value = paginator

    scanner = AWSLambdaScanner(session=session)
    findings = await scanner.scan()

    assert len(findings) == 1
    assert "0 Functions Deployed" in findings[0].title
    assert findings[0].severity == Severity.INFO

@pytest.mark.asyncio
async def test_lambda_exception_isolation(mock_lambda_session):
    session, client = mock_lambda_session
    client.list_function_url_configs.side_effect = Exception("AccessDenied: Not authorized")

    scanner = AWSLambdaScanner(session=session)
    findings = await scanner.scan()

    # Scan must complete cleanly despite AccessDenied exception on URLs
    assert isinstance(findings, list)
    assert len(findings) > 0

@pytest.mark.asyncio
async def test_risk_engine_integration_lambda(mock_lambda_session):
    session, client = mock_lambda_session
    scanner = AWSLambdaScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.critical_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_lambda():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "lambda"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
