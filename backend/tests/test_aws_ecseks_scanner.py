import pytest
from unittest.mock import MagicMock
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.scanners.aws.ecseks import AWSECSEKSScanner
from app.engine.severity import Severity
from app.engine.risk_engine import RiskEngine

@pytest.fixture
def mock_ecseks_session():
    session = MagicMock()
    ecs_client = MagicMock()
    eks_client = MagicMock()

    def side_effect_client(service_name):
        if service_name == "ecs":
            return ecs_client
        elif service_name == "eks":
            return eks_client
        return MagicMock()

    session.client.side_effect = side_effect_client

    # EKS List Clusters mock
    eks_paginator = MagicMock()
    eks_paginator.paginate.return_value = [
        {"clusters": ["unprotected-eks-cluster", "secure-eks-cluster"]}
    ]
    eks_client.get_paginator.return_value = eks_paginator

    # EKS Describe Cluster mock
    def mock_describe_eks_cluster(name):
        if name == "unprotected-eks-cluster":
            return {
                "cluster": {
                    "arn": "arn:aws:eks:us-east-1:123456789012:cluster/unprotected-eks-cluster",
                    "resourcesVpcConfig": {
                        "endpointPublicAccess": True,
                        "publicAccessCidrs": ["0.0.0.0/0"]
                    },
                    "encryptionConfig": [],
                    "logging": {"clusterLogging": []},
                    "tags": {}
                }
            }
        elif name == "secure-eks-cluster":
            return {
                "cluster": {
                    "arn": "arn:aws:eks:us-east-1:123456789012:cluster/secure-eks-cluster",
                    "resourcesVpcConfig": {
                        "endpointPublicAccess": False,
                        "publicAccessCidrs": ["10.0.0.0/16"]
                    },
                    "encryptionConfig": [{"resources": ["secrets"], "provider": {"keyArn": "arn:aws:kms:..."}}],
                    "logging": {"clusterLogging": [{"types": ["api", "audit", "authenticator"], "enabled": True}]},
                    "tags": {"Environment": "Production", "Owner": "SecOps", "Classification": "Restricted"}
                }
            }
        return {"cluster": {}}

    eks_client.describe_cluster.side_effect = mock_describe_eks_cluster

    # ECS List Clusters mock
    ecs_cluster_paginator = MagicMock()
    ecs_cluster_paginator.paginate.return_value = [
        {"clusterArns": ["arn:aws:ecs:us-east-1:123456789012:cluster/unprotected-ecs-cluster", "arn:aws:ecs:us-east-1:123456789012:cluster/secure-ecs-cluster"]}
    ]

    # ECS List Task Definitions mock
    td_paginator = MagicMock()
    td_paginator.paginate.return_value = [
        {"taskDefinitionArns": ["arn:aws:ecs:us-east-1:123456789012:task-definition/unprotected-td:1", "arn:aws:ecs:us-east-1:123456789012:task-definition/secure-td:1"]}
    ]

    def mock_get_ecs_paginator(operation_name):
        if operation_name == "list_clusters":
            return ecs_cluster_paginator
        elif operation_name == "list_task_definitions":
            return td_paginator
        return MagicMock()

    ecs_client.get_paginator.side_effect = mock_get_ecs_paginator

    # ECS Describe Clusters mock
    def mock_describe_ecs_clusters(clusters, include=None):
        return {
            "clusters": [
                {
                    "clusterName": "unprotected-ecs-cluster",
                    "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/unprotected-ecs-cluster",
                    "settings": [],
                    "tags": []
                },
                {
                    "clusterName": "secure-ecs-cluster",
                    "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/secure-ecs-cluster",
                    "settings": [{"name": "containerInsights", "value": "enabled"}],
                    "tags": [{"key": "Environment", "value": "Production"}, {"key": "Owner", "value": "SecOps"}, {"key": "Classification", "value": "Restricted"}]
                }
            ]
        }

    ecs_client.describe_clusters.side_effect = mock_describe_ecs_clusters

    # ECS Describe Task Definition mock
    def mock_describe_task_definition(taskDefinition):
        if "unprotected-td" in taskDefinition:
            return {
                "taskDefinition": {
                    "containerDefinitions": [
                        {
                            "name": "unprotected-app",
                            "privileged": True,
                            "user": "root",
                            "readonlyRootFilesystem": False,
                            "logConfiguration": {}
                        }
                    ]
                }
            }
        elif "secure-td" in taskDefinition:
            return {
                "taskDefinition": {
                    "containerDefinitions": [
                        {
                            "name": "secure-app",
                            "privileged": False,
                            "user": "10001:10001",
                            "readonlyRootFilesystem": True,
                            "logConfiguration": {"logDriver": "awslogs"}
                        }
                    ]
                }
            }
        return {"taskDefinition": {}}

    ecs_client.describe_task_definition.side_effect = mock_describe_task_definition

    return session, ecs_client, eks_client

@pytest.mark.asyncio
async def test_aws_ecseks_scanner_mocked_checks(mock_ecseks_session):
    session, ecs_client, eks_client = mock_ecseks_session
    scanner = AWSECSEKSScanner(session=session)

    findings = await scanner.scan()
    assert len(findings) > 0

    # CRITICAL MUTATION & CONTAINER EXECUTION SAFETY ASSERTIONS
    forbidden_ecs_methods = [
        "create_cluster", "delete_cluster", "register_task_definition",
        "deregister_task_definition", "run_task", "stop_task", "execute_command"
    ]
    for method_name in forbidden_ecs_methods:
        if hasattr(ecs_client, method_name):
            getattr(ecs_client, method_name).assert_not_called()

    forbidden_eks_methods = [
        "create_cluster", "delete_cluster", "update_cluster_config", "update_cluster_version"
    ]
    for method_name in forbidden_eks_methods:
        if hasattr(eks_client, method_name):
            getattr(eks_client, method_name).assert_not_called()

    # 1. EKS Public Endpoint (unprotected-eks-cluster) vs Private (secure-eks-cluster)
    eks_pub_findings = [f for f in findings if "API Server Public Endpoint Exposed" in f.title]
    assert len(eks_pub_findings) == 1
    assert "unprotected-eks-cluster" in eks_pub_findings[0].resource
    assert eks_pub_findings[0].severity == Severity.HIGH

    # 2. ECS Privileged Container (unprotected-td) vs Non-Privileged (secure-td)
    priv_findings = [f for f in findings if "Configured in Privileged Mode" in f.title]
    assert len(priv_findings) == 1
    assert "unprotected-td" in priv_findings[0].resource
    assert priv_findings[0].severity == Severity.HIGH

    # 3. ECS Root User (unprotected-td) vs Non-Root (secure-td)
    root_findings = [f for f in findings if "Configured to Run as Root User" in f.title]
    assert len(root_findings) == 1
    assert "unprotected-td" in root_findings[0].resource
    assert root_findings[0].severity == Severity.HIGH

    # 4. EKS Secrets KMS Encryption Disabled (unprotected-eks-cluster) vs Enabled (secure-eks-cluster)
    kms_findings = [f for f in findings if "Kubernetes Secrets KMS Encryption Disabled" in f.title]
    assert len(kms_findings) == 1
    assert "unprotected-eks-cluster" in kms_findings[0].resource
    assert kms_findings[0].severity == Severity.HIGH

    # 5. EKS Control Plane Logging Disabled (unprotected-eks-cluster) vs Enabled (secure-eks-cluster)
    log_findings = [f for f in findings if "Control Plane Logging Disabled" in f.title]
    assert len(log_findings) == 1
    assert "unprotected-eks-cluster" in log_findings[0].resource
    assert log_findings[0].severity == Severity.HIGH

    # 6. ECS Read-Only Root Filesystem Disabled (unprotected-td) vs Enabled (secure-td)
    ro_fs_findings = [f for f in findings if "Read-Only Root Filesystem Disabled Recommendation" in f.title]
    assert len(ro_fs_findings) == 1
    assert "unprotected-td" in ro_fs_findings[0].resource
    assert ro_fs_findings[0].severity == Severity.MEDIUM

    # 7. ECS Container Insights Disabled (unprotected-ecs-cluster) vs Enabled (secure-ecs-cluster)
    insights_findings = [f for f in findings if "Container Insights Disabled" in f.title]
    assert len(insights_findings) == 1
    assert "unprotected-ecs-cluster" in insights_findings[0].resource
    assert insights_findings[0].severity == Severity.LOW

    # 8. ECS Log Config Missing (unprotected-td) vs Configured (secure-td)
    awslog_findings = [f for f in findings if "Missing CloudWatch Log Configuration" in f.title]
    assert len(awslog_findings) == 1
    assert "unprotected-td" in awslog_findings[0].resource
    assert awslog_findings[0].severity == Severity.LOW

    # 9. Missing Governance Tags (unprotected-eks-cluster & unprotected-ecs-cluster) vs Tagged (secure clusters)
    tag_findings = [f for f in findings if "Missing Governance Tags" in f.title]
    assert len(tag_findings) == 2
    assert not any("secure-eks-cluster" in f.resource for f in tag_findings)
    assert not any("secure-ecs-cluster" in f.resource for f in tag_findings)

@pytest.mark.asyncio
async def test_ecseks_empty_account():
    session = MagicMock()
    ecs_client = MagicMock()
    eks_client = MagicMock()

    def side_effect_client(service_name):
        if service_name == "ecs":
            return ecs_client
        elif service_name == "eks":
            return eks_client
        return MagicMock()

    session.client.side_effect = side_effect_client

    eks_paginator = MagicMock()
    eks_paginator.paginate.return_value = [{"clusters": []}]
    eks_client.get_paginator.return_value = eks_paginator

    ecs_cluster_paginator = MagicMock()
    ecs_cluster_paginator.paginate.return_value = [{"clusterArns": []}]
    td_paginator = MagicMock()
    td_paginator.paginate.return_value = [{"taskDefinitionArns": []}]

    def mock_get_ecs_paginator(operation_name):
        if operation_name == "list_clusters":
            return ecs_cluster_paginator
        elif operation_name == "list_task_definitions":
            return td_paginator
        return MagicMock()

    ecs_client.get_paginator.side_effect = mock_get_ecs_paginator

    scanner = AWSECSEKSScanner(session=session)
    findings = await scanner.scan()

    assert len(findings) == 1
    assert "0 Clusters Deployed" in findings[0].title
    assert findings[0].severity == Severity.INFO

@pytest.mark.asyncio
async def test_ecseks_exception_isolation(mock_ecseks_session):
    session, ecs_client, eks_client = mock_ecseks_session
    eks_client.describe_cluster.side_effect = Exception("AccessDenied: Not authorized")

    scanner = AWSECSEKSScanner(session=session)
    findings = await scanner.scan()

    # Scan must complete cleanly despite AccessDenied exception on EKS describe_cluster
    assert isinstance(findings, list)
    assert len(findings) > 0

@pytest.mark.asyncio
async def test_risk_engine_integration_ecseks(mock_ecseks_session):
    session, ecs_client, eks_client = mock_ecseks_session
    scanner = AWSECSEKSScanner(session=session)
    findings = await scanner.scan()

    report = RiskEngine.calculate_score(findings)
    assert 0 <= report.security_score <= 100
    assert report.risk_summary.high_count >= 1

@pytest.mark.asyncio
async def test_api_run_aws_ecseks():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/api/v1/scanners/run", json={"provider": "aws", "service": "ecseks"})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["total_findings"] > 0
        assert "score_report" in data
