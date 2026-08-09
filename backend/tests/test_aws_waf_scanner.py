import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.waf import AWSWAFScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_waf_session():
    session = MagicMock()
    reg_client = MagicMock()
    cf_client = MagicMock()

    def get_client(service_name, region_name=None):
        if service_name == "wafv2":
            if region_name == "us-east-1":
                return cf_client
            return reg_client
        return MagicMock()

    session.client.side_effect = get_client

    # List Web ACLs mock
    reg_client.list_web_acls.return_value = {
        "WebACLs": [
            {
                "Name": "unprotected-web-acl",
                "Id": "11111111-2222-3333-4444-555555555555",
                "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/unprotected-web-acl/11111111"
            },
            {
                "Name": "secure-web-acl",
                "Id": "99999999-8888-7777-6666-555555555555",
                "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/secure-web-acl/99999999"
            }
        ]
    }
    cf_client.list_web_acls.return_value = {"WebACLs": []}

    # Get Web ACL details mock
    def mock_get_web_acl(Name, Scope, Id):
        if Name == "unprotected-web-acl":
            return {
                "WebACL": {
                    "Name": "unprotected-web-acl",
                    "Id": "11111111-2222-3333-4444-555555555555",
                    "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/unprotected-web-acl/11111111",
                    "DefaultAction": {"Allow": {}},
                    "Rules": [],
                    "Capacity": 100
                }
            }
        elif Name == "secure-web-acl":
            return {
                "WebACL": {
                    "Name": "secure-web-acl",
                    "Id": "99999999-8888-7777-6666-555555555555",
                    "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/secure-web-acl/99999999",
                    "DefaultAction": {"Allow": {}},
                    "Capacity": 600,
                    "Rules": [
                        {
                            "Name": "AWS-AWSManagedRulesCommonRuleSet",
                            "Statement": {
                                "ManagedRuleGroupStatement": {
                                    "VendorName": "AWS",
                                    "Name": "AWSManagedRulesCommonRuleSet"
                                }
                            }
                        },
                        {
                            "Name": "AWS-AWSManagedRulesSQLiRuleSet",
                            "Statement": {
                                "ManagedRuleGroupStatement": {
                                    "VendorName": "AWS",
                                    "Name": "AWSManagedRulesSQLiRuleSet"
                                }
                            }
                        },
                        {
                            "Name": "AWS-AWSManagedRulesAmazonIpReputationList",
                            "Statement": {
                                "ManagedRuleGroupStatement": {
                                    "VendorName": "AWS",
                                    "Name": "AWSManagedRulesAmazonIpReputationList"
                                }
                            }
                        },
                        {
                            "Name": "RateLimitRule",
                            "Statement": {
                                "RateBasedStatement": {
                                    "Limit": 2000,
                                    "AggregateKeyType": "IP"
                                }
                            }
                        }
                    ]
                }
            }
        return {}

    reg_client.get_web_acl.side_effect = mock_get_web_acl

    # List resources for Web ACL mock
    def mock_list_resources_for_web_acl(WebACLArn, ResourceType):
        if "secure-web-acl" in WebACLArn:
            return {"ResourceArns": ["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/123456"]}
        return {"ResourceArns": []}

    reg_client.list_resources_for_web_acl.side_effect = mock_list_resources_for_web_acl

    # Logging config mock
    def mock_get_logging_configuration(ResourceArn):
        if "secure-web-acl" in ResourceArn:
            return {"LoggingConfiguration": {"LogDestinationConfigs": ["arn:aws:logs:us-east-1:123456789012:log-group:waf-logs"]}}
        raise Exception("ResourceNotFoundException: Logging is not enabled")

    reg_client.get_logging_configuration.side_effect = mock_get_logging_configuration

    # List tags mock
    def mock_list_tags_for_resource(ResourceARN):
        if "secure-web-acl" in ResourceARN:
            return {"TagInfoForResource": {"TagList": [{"Key": "Environment", "Value": "Production"}, {"Key": "Owner", "Value": "SecOps"}, {"Key": "Classification", "Value": "Restricted"}]}}
        return {"TagInfoForResource": {"TagList": []}}

    reg_client.list_tags_for_resource.side_effect = mock_list_tags_for_resource

    return session, reg_client, cf_client

@pytest.mark.asyncio
async def test_aws_waf_scanner_mocked_checks(mock_waf_session):
    session, reg_client, cf_client = mock_waf_session
    scanner = AWSWAFScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # CRITICAL MUTATION API SAFETY ASSERTIONS
    mutation_methods = [
        "create_web_acl", "update_web_acl", "delete_web_acl",
        "put_logging_configuration", "delete_logging_configuration",
        "associate_web_acl", "disassociate_web_acl", "tag_resource", "untag_resource"
    ]
    for method_name in mutation_methods:
        if hasattr(reg_client, method_name):
            getattr(reg_client, method_name).assert_not_called()

    # 1. Unprotected Web ACL (0 rules with ALLOW default action)
    unprotected_findings = [f for f in findings if "Unprotected (Default Action ALLOW With 0 Inspection Rules)" in f.title]
    assert len(unprotected_findings) == 1
    assert "unprotected-web-acl" in unprotected_findings[0].resource
    assert unprotected_findings[0].severity == Severity.HIGH

    # 2. Secure Web ACL with active rules should NOT produce Unprotected finding
    assert not any("secure-web-acl" in f.resource and "Unprotected" in f.title for f in findings)

    # 3. Unused Web ACL Info finding (unprotected-web-acl is unassociated)
    unused_findings = [f for f in findings if "Unused (No Associated Resources)" in f.title]
    assert len(unused_findings) == 1
    assert "unprotected-web-acl" in unused_findings[0].resource
    assert unused_findings[0].severity == Severity.INFO
    assert unused_findings[0].cvss == 0.0

    # 4. Traffic Logging Disabled (unprotected-web-acl) vs Enabled (secure-web-acl)
    log_findings = [f for f in findings if "Traffic Logging Disabled" in f.title]
    assert len(log_findings) == 1
    assert "unprotected-web-acl" in log_findings[0].resource
    assert not any("secure-web-acl" in f.resource for f in log_findings)

@pytest.mark.asyncio
async def test_waf_empty_account():
    session = MagicMock()
    reg_client = MagicMock()
    cf_client = MagicMock()

    def get_client(service_name, region_name=None):
        if region_name == "us-east-1":
            return cf_client
        return reg_client

    session.client.side_effect = get_client
    reg_client.list_web_acls.return_value = {"WebACLs": []}
    cf_client.list_web_acls.return_value = {"WebACLs": []}

    scanner = AWSWAFScanner(session=session)
    findings = await scanner.scan()

    assert len(findings) == 1
    assert "0 Web ACLs Configured" in findings[0].title
    assert findings[0].severity == Severity.INFO

@pytest.mark.asyncio
async def test_waf_exception_isolation(mock_waf_session):
    session, reg_client, cf_client = mock_waf_session
    reg_client.list_resources_for_web_acl.side_effect = Exception("AccessDenied: Not authorized")

    scanner = AWSWAFScanner(session=session)
    findings = await scanner.scan()

    # Scan must complete cleanly despite AccessDenied exception on resource associations
    assert isinstance(findings, list)
    assert len(findings) > 0

@pytest.mark.asyncio
async def test_risk_engine_integration_waf(mock_waf_session):
    session, reg_client, cf_client = mock_waf_session
    scanner = AWSWAFScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.high_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_waf():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "waf"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
