import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.apigateway import AWSAPIGatewayScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_apigw_session():
    session = MagicMock()
    client = MagicMock()
    client2 = MagicMock()

    def side_effect_client(service_name):
        if service_name == "apigateway":
            return client
        elif service_name == "apigatewayv2":
            return client2
        return MagicMock()

    session.client.side_effect = side_effect_client

    # Get REST APIs paginator mock
    api_paginator = MagicMock()
    api_paginator.paginate.return_value = [
        {
            "items": [
                {"id": "unprotected-api", "name": "unprotected-api"},
                {"id": "secure-api", "name": "secure-api"}
            ]
        }
    ]
    client.get_paginator.return_value = api_paginator

    # Get v2 APIs mock
    client2.get_apis.return_value = {"Items": []}

    # Get Resources mock
    def mock_get_resources(restApiId, embed=None):
        if restApiId == "unprotected-api":
            return {
                "items": [
                    {
                        "id": "res-1",
                        "resourceMethods": {
                            "GET": {"authorizationType": "NONE"}
                        }
                    }
                ]
            }
        elif restApiId == "secure-api":
            return {
                "items": [
                    {
                        "id": "res-2",
                        "resourceMethods": {
                            "GET": {"authorizationType": "AWS_IAM"}
                        }
                    }
                ]
            }
        return {"items": []}

    client.get_resources.side_effect = mock_get_resources

    # Get Stages mock
    def mock_get_stages(restApiId):
        if restApiId == "unprotected-api":
            return {
                "item": [
                    {
                        "stageName": "prod",
                        "methodSettings": {
                            "*/*": {
                                "loggingLevel": "OFF",
                                "metricsEnabled": False,
                                "throttlingRateLimit": 0.0
                            }
                        },
                        "accessLogSettings": {},
                        "webAclArn": "",
                        "clientCertificateId": ""
                    }
                ]
            }
        elif restApiId == "secure-api":
            return {
                "item": [
                    {
                        "stageName": "prod",
                        "methodSettings": {
                            "*/*": {
                                "loggingLevel": "INFO",
                                "metricsEnabled": True,
                                "throttlingRateLimit": 1000.0
                            }
                        },
                        "accessLogSettings": {"destinationArn": "arn:aws:logs:..."},
                        "webAclArn": "arn:aws:wafv2:...",
                        "clientCertificateId": "cert-123456"
                    }
                ]
            }
        return {"item": []}

    client.get_stages.side_effect = mock_get_stages

    # Get Domain Names mock
    client.get_domain_names.return_value = {
        "items": [
            {"domainName": "api.unprotected.com", "securityPolicy": "TLS_1_0"},
            {"domainName": "api.secure.com", "securityPolicy": "TLS_1_2"}
        ]
    }

    # Get Tags mock
    def mock_get_tags(resourceArn):
        if "secure-api" in resourceArn:
            return {"tags": {"Environment": "Production", "Owner": "SecOps", "Classification": "Restricted"}}
        return {"tags": {}}

    client.get_tags.side_effect = mock_get_tags

    return session, client, client2

@pytest.mark.asyncio
async def test_aws_apigateway_scanner_mocked_checks(mock_apigw_session):
    session, client, client2 = mock_apigw_session
    scanner = AWSAPIGatewayScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # CRITICAL MUTATION & SENSITIVE DATA ACCESS API SAFETY ASSERTIONS
    forbidden_methods = [
        "create_rest_api", "create_api", "update_stage", "delete_stage",
        "create_authorizer", "update_authorizer", "delete_authorizer",
        "create_deployment", "tag_resource", "untag_resource"
    ]
    for method_name in forbidden_methods:
        if hasattr(client, method_name):
            getattr(client, method_name).assert_not_called()

    # 1. Unprotected Method / Auth Missing (unprotected-api) vs Auth Configured (secure-api)
    auth_findings = [f for f in findings if "Configured Without Authorization" in f.title]
    assert len(auth_findings) == 1
    assert "unprotected-api" in auth_findings[0].resource
    assert auth_findings[0].severity == Severity.HIGH

    # 2. Execution Logging Disabled (unprotected-api prod stage) vs Enabled (secure-api prod stage)
    log_findings = [f for f in findings if "Access/Execution Logging Disabled" in f.title]
    assert len(log_findings) == 1
    assert "unprotected-api" in log_findings[0].resource
    assert log_findings[0].severity == Severity.HIGH

    # 3. WAF Web ACL Integration Missing (unprotected-api prod stage) vs Attached (secure-api prod stage)
    waf_findings = [f for f in findings if "Missing AWS WAF Web ACL Integration" in f.title]
    assert len(waf_findings) == 1
    assert "unprotected-api" in waf_findings[0].resource
    assert waf_findings[0].severity == Severity.MEDIUM

    # 4. Deprecated Custom Domain TLS Policy (api.unprotected.com TLS_1_0) vs Modern (api.secure.com TLS_1_2)
    tls_findings = [f for f in findings if "Uses Deprecated TLS Policy" in f.title]
    assert len(tls_findings) == 1
    assert "api.unprotected.com" in tls_findings[0].resource
    assert tls_findings[0].severity == Severity.HIGH

    # 5. Method Throttling Disabled (unprotected-api prod stage) vs Enabled (secure-api prod stage)
    throttle_findings = [f for f in findings if "Default Method Rate Limiting Disabled" in f.title]
    assert len(throttle_findings) == 1
    assert "unprotected-api" in throttle_findings[0].resource
    assert throttle_findings[0].severity == Severity.MEDIUM

    # 6. Detailed CloudWatch Metrics Disabled (unprotected-api prod stage) vs Enabled (secure-api prod stage)
    metrics_findings = [f for f in findings if "Detailed CloudWatch Metrics Disabled" in f.title]
    assert len(metrics_findings) == 1
    assert "unprotected-api" in metrics_findings[0].resource
    assert metrics_findings[0].severity == Severity.LOW

    # 7. Client Certificate Missing (unprotected-api prod stage) vs Attached (secure-api prod stage)
    cert_findings = [f for f in findings if "Client Certificate Verification Recommendation" in f.title]
    assert len(cert_findings) == 1
    assert "unprotected-api" in cert_findings[0].resource
    assert cert_findings[0].severity == Severity.LOW

    # 8. Missing Governance Tags (unprotected-api) vs Fully Tagged (secure-api)
    tag_findings = [f for f in findings if "Missing Governance Tags" in f.title]
    assert len(tag_findings) == 1
    assert "unprotected-api" in tag_findings[0].resource
    assert not any("secure-api" in f.resource for f in tag_findings)

@pytest.mark.asyncio
async def test_apigw_empty_account():
    session = MagicMock()
    client = MagicMock()
    client2 = MagicMock()

    def side_effect_client(service_name):
        if service_name == "apigateway":
            return client
        elif service_name == "apigatewayv2":
            return client2
        return MagicMock()

    session.client.side_effect = side_effect_client

    paginator = MagicMock()
    paginator.paginate.return_value = [{"items": []}]
    client.get_paginator.return_value = paginator
    client2.get_apis.return_value = {"Items": []}

    scanner = AWSAPIGatewayScanner(session=session)
    findings = await scanner.scan()

    assert len(findings) == 1
    assert "0 APIs Deployed" in findings[0].title
    assert findings[0].severity == Severity.INFO

@pytest.mark.asyncio
async def test_apigw_exception_isolation(mock_apigw_session):
    session, client, client2 = mock_apigw_session
    client.get_stages.side_effect = Exception("AccessDenied: Not authorized")

    scanner = AWSAPIGatewayScanner(session=session)
    findings = await scanner.scan()

    # Scan must complete cleanly despite AccessDenied exception on stages
    assert isinstance(findings, list)
    assert len(findings) > 0

@pytest.mark.asyncio
async def test_risk_engine_integration_apigw(mock_apigw_session):
    session, client, client2 = mock_apigw_session
    scanner = AWSAPIGatewayScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.high_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_apigw():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "apigateway"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
