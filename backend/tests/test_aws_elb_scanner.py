import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.elb import AWSELBScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_elb_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # Describe load balancers paginator mock (ALB and NLB)
    lb_paginator = MagicMock()
    lb_paginator.paginate.return_value = [
        {
            "LoadBalancers": [
                {
                    "LoadBalancerName": "unprotected-alb",
                    "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/unprotected-alb/111",
                    "Scheme": "internet-facing",
                    "Type": "application"
                },
                {
                    "LoadBalancerName": "secure-alb",
                    "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/secure-alb/999",
                    "Scheme": "internal",
                    "Type": "application"
                },
                {
                    "LoadBalancerName": "unprotected-nlb",
                    "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/unprotected-nlb/222",
                    "Scheme": "internet-facing",
                    "Type": "network"
                }
            ]
        }
    ]

    # Describe listeners paginator mock
    listener_paginator = MagicMock()
    def mock_paginate_listeners(LoadBalancerArn):
        if "unprotected-alb" in LoadBalancerArn:
            return [
                {
                    "Listeners": [
                        {
                            "ListenerArn": "arn:aws:elbv2:us-east-1:123456789012:listener/app/unprotected-alb/111/1",
                            "Port": 80,
                            "Protocol": "HTTP",
                            "DefaultActions": [{"Type": "forward"}]
                        },
                        {
                            "ListenerArn": "arn:aws:elbv2:us-east-1:123456789012:listener/app/unprotected-alb/111/2",
                            "Port": 443,
                            "Protocol": "HTTPS",
                            "SslPolicy": "ELBSecurityPolicy-2016-08",
                            "DefaultActions": [{"Type": "forward"}]
                        }
                    ]
                }
            ]
        elif "secure-alb" in LoadBalancerArn:
            return [
                {
                    "Listeners": [
                        {
                            "ListenerArn": "arn:aws:elbv2:us-east-1:123456789012:listener/app/secure-alb/999/1",
                            "Port": 80,
                            "Protocol": "HTTP",
                            "DefaultActions": [{"Type": "redirect", "RedirectConfig": {"Protocol": "HTTPS", "Port": "443"}}]
                        },
                        {
                            "ListenerArn": "arn:aws:elbv2:us-east-1:123456789012:listener/app/secure-alb/999/2",
                            "Port": 443,
                            "Protocol": "HTTPS",
                            "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
                            "DefaultActions": [{"Type": "forward"}]
                        }
                    ]
                }
            ]
        elif "unprotected-nlb" in LoadBalancerArn:
            return [
                {
                    "Listeners": [
                        {
                            "ListenerArn": "arn:aws:elbv2:us-east-1:123456789012:listener/net/unprotected-nlb/222/1",
                            "Port": 443,
                            "Protocol": "TLS",
                            "SslPolicy": "ELBSecurityPolicy-2016-08",
                            "DefaultActions": [{"Type": "forward"}]
                        }
                    ]
                }
            ]
        return [{"Listeners": []}]

    listener_paginator.paginate.side_effect = mock_paginate_listeners

    def mock_get_paginator(operation_name):
        if operation_name == "describe_load_balancers":
            return lb_paginator
        elif operation_name == "describe_listeners":
            return listener_paginator
        return MagicMock()

    client.get_paginator.side_effect = mock_get_paginator

    # Attributes mock
    def mock_describe_load_balancer_attributes(LoadBalancerArn):
        if "unprotected-alb" in LoadBalancerArn:
            return {
                "Attributes": [
                    {"Key": "routing.http.drop_invalid_header_fields.enabled", "Value": "false"},
                    {"Key": "access_logs.s3.enabled", "Value": "false"},
                    {"Key": "deletion_protection.enabled", "Value": "false"},
                    {"Key": "routing.http.desync_mitigation_mode", "Value": "defensive"}
                ]
            }
        elif "secure-alb" in LoadBalancerArn:
            return {
                "Attributes": [
                    {"Key": "routing.http.drop_invalid_header_fields.enabled", "Value": "true"},
                    {"Key": "access_logs.s3.enabled", "Value": "true"},
                    {"Key": "deletion_protection.enabled", "Value": "true"},
                    {"Key": "routing.http.desync_mitigation_mode", "Value": "defensive"}
                ]
            }
        elif "unprotected-nlb" in LoadBalancerArn:
            return {
                "Attributes": [
                    {"Key": "access_logs.s3.enabled", "Value": "false"},
                    {"Key": "deletion_protection.enabled", "Value": "false"},
                    {"Key": "cross_zone.load_balancing.enabled", "Value": "false"}
                ]
            }
        return {"Attributes": []}

    client.describe_load_balancer_attributes.side_effect = mock_describe_load_balancer_attributes

    # Describe tags mock
    def mock_describe_tags(ResourceArns):
        if any("secure-alb" in arn for arn in ResourceArns):
            return {
                "TagDescriptions": [
                    {"ResourceArn": ResourceArns[0], "Tags": [{"Key": "Environment", "Value": "Production"}, {"Key": "Owner", "Value": "SecOps"}, {"Key": "Classification", "Value": "Restricted"}]}
                ]
            }
        return {"TagDescriptions": [{"ResourceArn": ResourceArns[0], "Tags": []}]}

    client.describe_tags.side_effect = mock_describe_tags

    return session, client

@pytest.mark.asyncio
async def test_aws_elb_scanner_mocked_checks(mock_elb_session):
    session, client = mock_elb_session
    scanner = AWSELBScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # CRITICAL MUTATION API SAFETY ASSERTIONS
    mutation_methods = [
        "create_load_balancer", "modify_load_balancer_attributes", "delete_load_balancer",
        "create_listener", "modify_listener", "delete_listener", "add_tags", "remove_tags",
        "set_ip_address_type", "set_security_groups", "set_subnets", "register_targets", "deregister_targets"
    ]
    for method_name in mutation_methods:
        if hasattr(client, method_name):
            getattr(client, method_name).assert_not_called()

    # 1. HTTP Listener Missing HTTPS Redirect (unprotected-alb only, strictly NOT NLB or redirect-configured ALB)
    http_findings = [f for f in findings if "Missing HTTPS Redirect" in f.title]
    assert len(http_findings) == 1
    assert "unprotected-alb" in http_findings[0].resource
    assert not any("unprotected-nlb" in f.resource for f in http_findings)
    assert not any("secure-alb" in f.resource for f in http_findings)
    assert http_findings[0].severity == Severity.HIGH

    # 2. Deprecated SSL Policy (ELBSecurityPolicy-2016-08 on unprotected-alb & unprotected-nlb)
    ssl_findings = [f for f in findings if "Uses Deprecated SSL Policy" in f.title]
    assert len(ssl_findings) == 2
    assert ssl_findings[0].severity == Severity.HIGH

    # 3. Drop Invalid Header Fields Disabled (unprotected-alb only, not NLB)
    header_findings = [f for f in findings if "Drop Invalid HTTP Headers Disabled" in f.title]
    assert len(header_findings) == 1
    assert "unprotected-alb" in header_findings[0].resource
    assert header_findings[0].severity == Severity.HIGH

    # 4. Access Logging Disabled (unprotected-alb & unprotected-nlb)
    log_findings = [f for f in findings if "S3 Access Logging Recommendation" in f.title]
    assert len(log_findings) == 2
    assert log_findings[0].severity == Severity.MEDIUM

    # 5. Deletion Protection Disabled (unprotected-alb & unprotected-nlb)
    del_findings = [f for f in findings if "Deletion Protection Disabled" in f.title]
    assert len(del_findings) == 2
    assert del_findings[0].severity == Severity.MEDIUM

    # 6. Internet-Facing ALB Without WAF (unprotected-alb only, not internal secure-alb or NLB)
    waf_findings = [f for f in findings if "AWS WAF Web ACL Integration Recommendation" in f.title]
    assert len(waf_findings) == 1
    assert "unprotected-alb" in waf_findings[0].resource
    assert waf_findings[0].severity == Severity.MEDIUM

    # 7. NLB Cross-Zone Load Balancing Disabled (unprotected-nlb only)
    cross_findings = [f for f in findings if "Cross-Zone Load Balancing Disabled" in f.title]
    assert len(cross_findings) == 1
    assert "unprotected-nlb" in cross_findings[0].resource
    assert cross_findings[0].severity == Severity.LOW

    # 8. Missing Governance Tags
    tag_findings = [f for f in findings if "Missing Governance Tags" in f.title]
    assert len(tag_findings) == 2
    assert not any("secure-alb" in f.resource for f in tag_findings)

@pytest.mark.asyncio
async def test_elb_empty_account():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    paginator = MagicMock()
    paginator.paginate.return_value = [{"LoadBalancers": []}]
    client.get_paginator.return_value = paginator

    scanner = AWSELBScanner(session=session)
    findings = await scanner.scan()

    assert len(findings) == 1
    assert "0 Load Balancers Deployed" in findings[0].title
    assert findings[0].severity == Severity.INFO

@pytest.mark.asyncio
async def test_elb_exception_isolation(mock_elb_session):
    session, client = mock_elb_session
    client.describe_load_balancer_attributes.side_effect = Exception("AccessDenied: Not authorized")

    scanner = AWSELBScanner(session=session)
    findings = await scanner.scan()

    # Scan must complete cleanly despite AccessDenied exception on attributes
    assert isinstance(findings, list)
    assert len(findings) > 0

@pytest.mark.asyncio
async def test_risk_engine_integration_elb(mock_elb_session):
    session, client = mock_elb_session
    scanner = AWSELBScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.high_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_elb():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "elb"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
