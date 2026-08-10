import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.vpc import AWSVPCScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_vpc_session():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    # Describe VPCs mock
    vpc_paginator = MagicMock()
    vpc_paginator.paginate.return_value = [
        {
            "Vpcs": [
                {"VpcId": "vpc-unprotected", "IsDefault": True, "Tags": []},
                {"VpcId": "vpc-secure", "IsDefault": False, "Tags": [{"Key": "Environment", "Value": "Production"}, {"Key": "Owner", "Value": "SecOps"}, {"Key": "Classification", "Value": "Restricted"}]}
            ]
        }
    ]

    # Describe Subnets mock
    subnet_paginator = MagicMock()
    subnet_paginator.paginate.return_value = [
        {
            "Subnets": [
                {"SubnetId": "subnet-unprotected", "VpcId": "vpc-unprotected", "MapPublicIpOnLaunch": True, "Tags": []},
                {"SubnetId": "subnet-secure", "VpcId": "vpc-secure", "MapPublicIpOnLaunch": False, "Tags": [{"Key": "Environment", "Value": "Production"}, {"Key": "Owner", "Value": "SecOps"}, {"Key": "Classification", "Value": "Restricted"}]}
            ]
        }
    ]

    def mock_get_paginator(operation_name):
        if operation_name == "describe_vpcs":
            return vpc_paginator
        elif operation_name == "describe_subnets":
            return subnet_paginator
        return MagicMock()

    client.get_paginator.side_effect = mock_get_paginator

    # Describe Flow Logs mock
    client.describe_flow_logs.return_value = {
        "FlowLogs": [
            {"ResourceId": "vpc-secure", "ResourceType": "VPC", "LogDestinationType": "cloud-watch-logs"}
        ]
    }

    # Describe Internet Gateways mock
    client.describe_internet_gateways.return_value = {
        "InternetGateways": [
            {"InternetGatewayId": "igw-orphaned", "Attachments": []}
        ]
    }

    # Describe NAT Gateways mock
    client.describe_nat_gateways.return_value = {
        "NatGateways": [
            {"NatGatewayId": "nat-single", "VpcId": "vpc-unprotected", "State": "available"}
        ]
    }

    # Describe VPC Peering Connections mock
    client.describe_vpc_peering_connections.return_value = {
        "VpcPeeringConnections": [
            {
                "VpcPeeringConnectionId": "pcx-unprotected",
                "RequesterVpcInfo": {"PeeringOptions": {"AllowDnsResolutionFromRemoteVpc": False}},
                "AccepterVpcInfo": {"PeeringOptions": {"AllowDnsResolutionFromRemoteVpc": False}}
            }
        ]
    }

    # Describe Network ACLs mock
    client.describe_network_acls.return_value = {
        "NetworkAcls": [
            {
                "NetworkAclId": "acl-unprotected",
                "VpcId": "vpc-unprotected",
                "Entries": [
                    {
                        "RuleNumber": 100,
                        "Protocol": "6",
                        "RuleAction": "allow",
                        "Egress": False,
                        "CidrBlock": "0.0.0.0/0",
                        "PortRange": {"From": 22, "To": 22}
                    }
                ]
            }
        ]
    }

    # Describe Route Tables mock
    client.describe_route_tables.return_value = {
        "RouteTables": [
            {
                "RouteTableId": "rtb-main-public",
                "VpcId": "vpc-unprotected",
                "Associations": [{"Main": True}],
                "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-123456"}]
            }
        ]
    }

    return session, client

@pytest.mark.asyncio
async def test_aws_vpc_scanner_mocked_checks(mock_vpc_session):
    session, client = mock_vpc_session
    scanner = AWSVPCScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # CRITICAL MUTATION & TRAFFIC DATA SAFETY ASSERTIONS
    forbidden_methods = [
        "create_vpc", "delete_vpc", "modify_vpc_attribute", "create_subnet",
        "delete_subnet", "modify_subnet_attribute", "create_flow_logs",
        "delete_flow_logs", "create_internet_gateway", "attach_internet_gateway",
        "detach_internet_gateway", "create_route", "replace_route", "delete_route",
        "create_network_acl", "replace_network_acl", "delete_network_acl",
        "create_vpc_peering_connection", "accept_vpc_peering_connection",
        "reject_vpc_peering_connection", "delete_vpc_peering_connection",
        "create_nat_gateway", "delete_nat_gateway"
    ]
    for method_name in forbidden_methods:
        if hasattr(client, method_name):
            getattr(client, method_name).assert_not_called()

    # 1. VPC Flow Logs Disabled (vpc-unprotected) -> MEDIUM severity (4.0)
    flow_findings = [f for f in findings if "Flow Logs Disabled Recommendation" in f.title]
    assert len(flow_findings) == 1
    assert "vpc-unprotected" in flow_findings[0].resource
    assert flow_findings[0].severity == Severity.MEDIUM
    assert flow_findings[0].cvss == 4.0

    # 2. Subnet Auto-Assign Public IP Enabled (subnet-unprotected) -> MEDIUM severity (5.0)
    pub_ip_findings = [f for f in findings if "Auto-Assign Public IP Enabled" in f.title]
    assert len(pub_ip_findings) == 1
    assert "subnet-unprotected" in pub_ip_findings[0].resource
    assert pub_ip_findings[0].severity == Severity.MEDIUM
    assert pub_ip_findings[0].cvss == 5.0
    assert "does not automatically expose existing instances" in pub_ip_findings[0].description

    # 3. Default VPC In Use (vpc-unprotected) -> MEDIUM severity (4.5)
    default_vpc_findings = [f for f in findings if "Default VPC 'vpc-unprotected' Utilization Governance" in f.title]
    assert len(default_vpc_findings) == 1
    assert default_vpc_findings[0].severity == Severity.MEDIUM
    assert default_vpc_findings[0].cvss == 4.5

    # 4. Network ACL Unrestricted Sensitive Ports (acl-unprotected) -> HIGH severity (7.5)
    nacl_findings = [f for f in findings if "Unrestricted Inbound Access to Sensitive Ports" in f.title]
    assert len(nacl_findings) == 1
    assert "acl-unprotected" in nacl_findings[0].resource
    assert nacl_findings[0].severity == Severity.HIGH

    # 5. VPC Peering DNS Resolution Disabled (pcx-unprotected) -> LOW severity (3.5)
    peering_findings = [f for f in findings if "DNS Resolution Disabled" in f.title]
    assert len(peering_findings) == 1
    assert "pcx-unprotected" in peering_findings[0].resource
    assert peering_findings[0].severity == Severity.LOW

    # 6. Unattached Internet Gateway (igw-orphaned) -> LOW severity (3.0)
    igw_findings = [f for f in findings if "Unattached / Orphaned Governance Recommendation" in f.title]
    assert len(igw_findings) == 1
    assert "igw-orphaned" in igw_findings[0].resource
    assert igw_findings[0].severity == Severity.LOW

    # 7. Single NAT Gateway AZ Resilience (nat-single) -> LOW severity (3.5)
    nat_findings = [f for f in findings if "Single NAT Gateway Multi-AZ Resilience Recommendation" in f.title]
    assert len(nat_findings) == 1
    assert nat_findings[0].severity == Severity.LOW

    # 8. Main Route Table Direct IGW Route (rtb-main-public) -> LOW severity (3.5)
    rt_findings = [f for f in findings if "Direct Internet Gateway Route Recommendation" in f.title]
    assert len(rt_findings) == 1
    assert rt_findings[0].severity == Severity.LOW

    # 9. Missing Governance Tags (vpc-unprotected & subnet-unprotected) vs Tagged (vpc-secure & subnet-secure)
    tag_findings = [f for f in findings if "Missing Governance Tags" in f.title]
    assert len(tag_findings) == 2
    assert not any("vpc-secure" in f.resource for f in tag_findings)
    assert not any("subnet-secure" in f.resource for f in tag_findings)

@pytest.mark.asyncio
async def test_vpc_empty_account():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client

    vpc_paginator = MagicMock()
    vpc_paginator.paginate.return_value = [{"Vpcs": []}]
    subnet_paginator = MagicMock()
    subnet_paginator.paginate.return_value = [{"Subnets": []}]

    def mock_get_paginator(operation_name):
        if operation_name == "describe_vpcs":
            return vpc_paginator
        elif operation_name == "describe_subnets":
            return subnet_paginator
        return MagicMock()

    client.get_paginator.side_effect = mock_get_paginator

    scanner = AWSVPCScanner(session=session)
    findings = await scanner.scan()

    assert len(findings) == 1
    assert "0 VPCs Deployed" in findings[0].title
    assert findings[0].severity == Severity.INFO

@pytest.mark.asyncio
async def test_vpc_exception_isolation(mock_vpc_session):
    session, client = mock_vpc_session
    client.describe_flow_logs.side_effect = Exception("AccessDenied: Not authorized")

    scanner = AWSVPCScanner(session=session)
    findings = await scanner.scan()

    # Scan must complete cleanly despite AccessDenied exception on flow logs
    assert isinstance(findings, list)
    assert len(findings) > 0

@pytest.mark.asyncio
async def test_risk_engine_integration_vpc(mock_vpc_session):
    session, client = mock_vpc_session
    scanner = AWSVPCScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.high_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_vpc():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "vpc"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
