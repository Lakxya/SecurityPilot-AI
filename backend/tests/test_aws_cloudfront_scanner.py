import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.cloudfront import AWSCloudFrontScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_cloudfront_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # List distributions paginator mock
    dist_paginator = MagicMock()
    dist_paginator.paginate.return_value = [
        {
            "DistributionList": {
                "Items": [
                    {
                        "Id": "EDISTVULN12345",
                        "ARN": "arn:aws:cloudfront::123456789012:distribution/EDISTVULN12345",
                        "DomainName": "vulnerable.cloudfront.net",
                        "WebACLId": "",
                        "Logging": {"Enabled": False},
                        "DefaultCacheBehavior": {"ViewerProtocolPolicy": "allow-all"},
                        "CacheBehaviors": {"Items": [{"ViewerProtocolPolicy": "redirect-to-https"}]},
                        "ViewerCertificate": {"MinimumProtocolVersion": "TLSv1"},
                        "DefaultRootObject": "",
                        "Origins": {
                            "Items": [
                                {
                                    "Id": "S3OriginUnprotected",
                                    "DomainName": "my-bucket.s3.amazonaws.com",
                                    "S3OriginConfig": {}
                                },
                                {
                                    "Id": "CustomOriginHTTP",
                                    "DomainName": "backend.example.com",
                                    "CustomOriginConfig": {"OriginProtocolPolicy": "http-only"}
                                }
                            ]
                        },
                        "Restrictions": {"GeoRestriction": {"RestrictionType": "none"}}
                    },
                    {
                        "Id": "EDISTSECURE987",
                        "ARN": "arn:aws:cloudfront::123456789012:distribution/EDISTSECURE987",
                        "DomainName": "secure.cloudfront.net",
                        "WebACLId": "arn:aws:wafv2:us-east-1:123456789012:global/webacl/prod-waf/123",
                        "Logging": {"Enabled": True, "Bucket": "logs.s3.amazonaws.com"},
                        "DefaultCacheBehavior": {"ViewerProtocolPolicy": "redirect-to-https"},
                        "ViewerCertificate": {"MinimumProtocolVersion": "TLSv1.2_2021"},
                        "DefaultRootObject": "index.html",
                        "Origins": {
                            "Items": [
                                {
                                    "Id": "S3OriginOAC",
                                    "DomainName": "secure-bucket.s3.amazonaws.com",
                                    "OriginAccessControlId": "oac-123456"
                                },
                                {
                                    "Id": "CustomOriginHTTPS",
                                    "DomainName": "secure-backend.example.com",
                                    "CustomOriginConfig": {"OriginProtocolPolicy": "https-only"}
                                }
                            ]
                        },
                        "Restrictions": {"GeoRestriction": {"RestrictionType": "whitelist"}}
                    }
                ]
            }
        }
    ]

    def mock_get_paginator(operation_name):
        if operation_name == "list_distributions":
            return dist_paginator
        return MagicMock()

    client.get_paginator.side_effect = mock_get_paginator

    # List tags mock
    def mock_list_tags_for_resource(Resource):
        if "EDISTSECURE987" in Resource:
            return {"Tags": {"Items": [{"Key": "Environment", "Value": "Production"}, {"Key": "Owner", "Value": "SecOps"}, {"Key": "Classification", "Value": "Restricted"}]}}
        return {"Tags": {"Items": []}}

    client.list_tags_for_resource.side_effect = mock_list_tags_for_resource

    return session, client

@pytest.mark.asyncio
async def test_aws_cloudfront_scanner_mocked_checks(mock_cloudfront_session):
    session, client = mock_cloudfront_session
    scanner = AWSCloudFrontScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # CRITICAL MUTATION API SAFETY ASSERTIONS
    mutation_methods = [
        "create_distribution", "update_distribution", "delete_distribution",
        "tag_resource", "untag_resource"
    ]
    for method_name in mutation_methods:
        if hasattr(client, method_name):
            getattr(client, method_name).assert_not_called()

    # 1. Unencrypted HTTP Protocol (EDISTVULN12345) vs Redirect to HTTPS (EDISTSECURE987)
    http_findings = [f for f in findings if "Allows Unencrypted HTTP Traffic" in f.title]
    assert len(http_findings) == 1
    assert "EDISTVULN12345" in http_findings[0].resource
    assert http_findings[0].severity == Severity.HIGH

    # 2. Deprecated TLS Protocol (TLSv1) vs Modern (TLSv1.2_2021)
    tls_findings = [f for f in findings if "Deprecated Minimum TLS Protocol" in f.title]
    assert len(tls_findings) == 1
    assert "EDISTVULN12345" in tls_findings[0].resource

    # 3. WAF Web ACL Missing (EDISTVULN12345) -> MEDIUM severity
    waf_findings = [f for f in findings if "WAF Web ACL Integration Recommendation" in f.title]
    assert len(waf_findings) == 1
    assert "EDISTVULN12345" in waf_findings[0].resource
    assert waf_findings[0].severity == Severity.MEDIUM

    # 4. Access Logging Disabled (EDISTVULN12345) -> MEDIUM severity
    log_findings = [f for f in findings if "Standard Access Logging Recommendation" in f.title]
    assert len(log_findings) == 1
    assert "EDISTVULN12345" in log_findings[0].resource
    assert log_findings[0].severity == Severity.MEDIUM

    # 5. S3 Origin Missing OAC (EDISTVULN12345) -> LOW severity recommendation
    s3_findings = [f for f in findings if "S3 Origin Access Control (OAC) Governance Recommendation" in f.title]
    assert len(s3_findings) == 1
    assert "EDISTVULN12345" in s3_findings[0].resource
    assert s3_findings[0].severity == Severity.LOW

    # 6. Custom Origin HTTP-Only (EDISTVULN12345) -> HIGH severity
    custom_findings = [f for f in findings if "Custom Origin Protocol Uses HTTP-Only" in f.title]
    assert len(custom_findings) == 1
    assert "EDISTVULN12345" in custom_findings[0].resource
    assert custom_findings[0].severity == Severity.HIGH

    # 7. Missing Default Root Object -> INFO severity with CVSS 0.0
    root_findings = [f for f in findings if "Default Root Object Unconfigured" in f.title]
    assert len(root_findings) == 1
    assert root_findings[0].severity == Severity.INFO
    assert root_findings[0].cvss == 0.0

    # 8. Missing Governance Tags
    tag_findings = [f for f in findings if "Missing Governance Tags" in f.title]
    assert len(tag_findings) == 1
    assert "EDISTVULN12345" in tag_findings[0].resource
    assert not any("EDISTSECURE987" in f.resource for f in tag_findings)

@pytest.mark.asyncio
async def test_cloudfront_empty_account():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    paginator = MagicMock()
    paginator.paginate.return_value = [{"DistributionList": {"Items": []}}]
    client.get_paginator.return_value = paginator

    scanner = AWSCloudFrontScanner(session=session)
    findings = await scanner.scan()

    assert len(findings) == 1
    assert "0 Distributions Active" in findings[0].title
    assert findings[0].severity == Severity.INFO

@pytest.mark.asyncio
async def test_cloudfront_exception_isolation(mock_cloudfront_session):
    session, client = mock_cloudfront_session
    client.list_tags_for_resource.side_effect = Exception("AccessDenied: Not authorized")

    scanner = AWSCloudFrontScanner(session=session)
    findings = await scanner.scan()

    # Scan must complete cleanly despite AccessDenied exception on tags
    assert isinstance(findings, list)
    assert len(findings) > 0

@pytest.mark.asyncio
async def test_risk_engine_integration_cloudfront(mock_cloudfront_session):
    session, client = mock_cloudfront_session
    scanner = AWSCloudFrontScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.high_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_cloudfront():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "cloudfront"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
