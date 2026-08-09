import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.opensearch import AWSOpenSearchScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_opensearch_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # List domain names mock
    client.list_domain_names.return_value = {
        "DomainNames": [
            {"DomainName": "unprotected-domain"},
            {"DomainName": "secure-domain"}
        ]
    }

    # Describe domains mock
    def mock_describe_domains(DomainNames):
        result = []
        if "unprotected-domain" in DomainNames:
            result.append({
                "DomainName": "unprotected-domain",
                "ARN": "arn:aws:es:us-east-1:123456789012:domain/unprotected-domain",
                "VPCOptions": {"SubnetIds": []},
                "EncryptionAtRestOptions": {"Enabled": False},
                "NodeToNodeEncryptionOptions": {"Enabled": False},
                "DomainEndpointOptions": {"EnforceHTTPS": False, "TLSSecurityPolicy": "Policy-Min-TLS-1-0-2019-07"},
                "AdvancedSecurityOptions": {"Enabled": False},
                "LogPublishingOptions": {"AUDIT_LOGS": {"Enabled": False}}
            })
        if "secure-domain" in DomainNames:
            result.append({
                "DomainName": "secure-domain",
                "ARN": "arn:aws:es:us-east-1:123456789012:domain/secure-domain",
                "VPCOptions": {"SubnetIds": ["subnet-12345678"]},
                "EncryptionAtRestOptions": {"Enabled": True, "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/custom-cmk"},
                "NodeToNodeEncryptionOptions": {"Enabled": True},
                "DomainEndpointOptions": {"EnforceHTTPS": True, "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07"},
                "AdvancedSecurityOptions": {"Enabled": True},
                "LogPublishingOptions": {"AUDIT_LOGS": {"Enabled": True}}
            })
        return {"DomainStatusList": result}

    client.describe_domains.side_effect = mock_describe_domains

    # List tags mock
    def mock_list_tags(ARN):
        if "secure-domain" in ARN:
            return {"TagList": [{"Key": "Environment", "Value": "Production"}, {"Key": "Owner", "Value": "SecOps"}, {"Key": "Classification", "Value": "Restricted"}]}
        return {"TagList": []}

    client.list_tags.side_effect = mock_list_tags

    return session, client

@pytest.mark.asyncio
async def test_aws_opensearch_scanner_mocked_checks(mock_opensearch_session):
    session, client = mock_opensearch_session
    scanner = AWSOpenSearchScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # CRITICAL MUTATION & DATA ACCESS API SAFETY ASSERTIONS
    forbidden_methods = [
        "create_domain", "update_domain_config", "delete_domain",
        "add_tags", "remove_tags", "update_package", "upgrade_domain"
    ]
    for method_name in forbidden_methods:
        if hasattr(client, method_name):
            getattr(client, method_name).assert_not_called()

    # 1. Public Endpoint Exposure Governance (unprotected-domain) -> MEDIUM severity (5.0)
    public_findings = [f for f in findings if "Public Network Endpoint Governance Recommendation" in f.title]
    assert len(public_findings) == 1
    assert "unprotected-domain" in public_findings[0].resource
    assert public_findings[0].severity == Severity.MEDIUM
    assert public_findings[0].cvss == 5.0

    # 2. Encryption at Rest Disabled (unprotected-domain) -> HIGH severity (8.0)
    enc_findings = [f for f in findings if "Storage Encryption at Rest Disabled" in f.title]
    assert len(enc_findings) == 1
    assert "unprotected-domain" in enc_findings[0].resource
    assert enc_findings[0].severity == Severity.HIGH

    # 3. Node-to-Node TLS Disabled (unprotected-domain) -> HIGH severity (7.5)
    ntn_findings = [f for f in findings if "Node-to-Node TLS Encryption Disabled" in f.title]
    assert len(ntn_findings) == 1
    assert "unprotected-domain" in ntn_findings[0].resource
    assert ntn_findings[0].severity == Severity.HIGH

    # 4. Enforce HTTPS Disabled (unprotected-domain) -> HIGH severity (7.5)
    https_findings = [f for f in findings if "Enforce HTTPS Disabled" in f.title]
    assert len(https_findings) == 1
    assert "unprotected-domain" in https_findings[0].resource
    assert https_findings[0].severity == Severity.HIGH

    # 5. Deprecated TLS Policy (unprotected-domain) -> HIGH severity (7.5)
    tls_findings = [f for f in findings if "Uses Deprecated TLS Policy" in f.title]
    assert len(tls_findings) == 1
    assert "unprotected-domain" in tls_findings[0].resource
    assert tls_findings[0].severity == Severity.HIGH

    # 6. Fine-Grained Access Control Disabled (unprotected-domain) -> MEDIUM severity (5.0) with refined wording
    fgac_findings = [f for f in findings if "Fine-Grained Access Control (FGAC) Recommendation" in f.title]
    assert len(fgac_findings) == 1
    assert "unprotected-domain" in fgac_findings[0].resource
    assert fgac_findings[0].severity == Severity.MEDIUM
    assert "review whether domain-level access controls" in fgac_findings[0].description
    assert not any("secure-domain" in f.resource for f in fgac_findings)

    # 7. Missing Governance Tags (unprotected-domain) vs Fully Tagged (secure-domain)
    tag_findings = [f for f in findings if "Missing Governance Tags" in f.title]
    assert len(tag_findings) == 1
    assert "unprotected-domain" in tag_findings[0].resource
    assert not any("secure-domain" in f.resource for f in tag_findings)

@pytest.mark.asyncio
async def test_opensearch_empty_account():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client
    client.list_domain_names.return_value = {"DomainNames": []}

    scanner = AWSOpenSearchScanner(session=session)
    findings = await scanner.scan()

    assert len(findings) == 1
    assert "0 Domains Deployed" in findings[0].title
    assert findings[0].severity == Severity.INFO

@pytest.mark.asyncio
async def test_opensearch_exception_isolation(mock_opensearch_session):
    session, client = mock_opensearch_session
    client.list_tags.side_effect = Exception("AccessDenied: Not authorized")

    scanner = AWSOpenSearchScanner(session=session)
    findings = await scanner.scan()

    # Scan must complete cleanly despite AccessDenied exception on tags
    assert isinstance(findings, list)
    assert len(findings) > 0

@pytest.mark.asyncio
async def test_risk_engine_integration_opensearch(mock_opensearch_session):
    session, client = mock_opensearch_session
    scanner = AWSOpenSearchScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.high_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_opensearch():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "opensearch"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
